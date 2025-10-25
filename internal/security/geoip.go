package security

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// GeoIPService 地理位置IP服务
type GeoIPService struct {
	cityDatabase *geoip2.Reader
	asnDatabase  *geoip2.Reader
	config       config.GeoBlockingConfig
	mutex        sync.RWMutex
	log          *logrus.Entry
	lastUpdate   time.Time

	// 缓存最近查询结果
	cache     map[string]*GeoLocation
	cacheSize int
	cacheTTL  time.Duration

	// 自动更新配置
	autoUpdateEnabled bool
	updateInterval    time.Duration // 更新间隔（默认7天）
	updateURL         string        // 更新URL
	stopUpdateChan    chan struct{} // 停止更新任务
}

// GeoLocation 地理位置信息
type GeoLocation struct {
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	City        string    `json:"city"`
	Region      string    `json:"region"`
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	Timezone    string    `json:"timezone"`
	ISP         string    `json:"isp"`
	CachedAt    time.Time `json:"cached_at"`
}

// GeoFilterResult 地理位置过滤结果
type GeoFilterResult struct {
	Allowed  bool         `json:"allowed"`
	Country  string       `json:"country"`
	Reason   string       `json:"reason"`
	Location *GeoLocation `json:"location,omitempty"`
}

// NewGeoIPService 创建地理位置IP服务
func NewGeoIPService(config config.GeoBlockingConfig) (*GeoIPService, error) {
	service := &GeoIPService{
		config:            config,
		cache:             make(map[string]*GeoLocation),
		cacheSize:         10000,              // 缓存1万个IP查询结果
		cacheTTL:          time.Hour,          // 缓存1小时
		autoUpdateEnabled: true,               // 默认启用自动更新
		updateInterval:    7 * 24 * time.Hour, // 每7天更新一次
		updateURL:         "",                 // 默认不设置更新URL（需要手动配置）
		stopUpdateChan:    make(chan struct{}),
		log: logrus.WithFields(logrus.Fields{
			"component": "geoip_service",
		}),
	}

	if config.Enabled && config.DatabasePath != "" {
		if err := service.loadDatabase(); err != nil {
			service.log.Errorf("Failed to load GeoIP database: %v", err)
			// 不返回错误，而是禁用功能并继续运行
			service.config.Enabled = false
			service.log.Warn("GeoIP功能已自动禁用，因为无法加载数据库文件")
		} else {
			// 启动自动更新任务
			if service.autoUpdateEnabled {
				go service.startAutoUpdateTask()
			}
		}
	} else if config.Enabled && config.DatabasePath == "" {
		service.log.Warn("GeoIP功能已启用但未配置数据库路径，功能将被禁用")
		service.config.Enabled = false
	}

	return service, nil
}

// loadDatabase 加载GeoIP数据库（优化版：减少锁持有时间）
func (g *GeoIPService) loadDatabase() error {
	// 检查城市数据库文件是否存在
	if _, err := os.Stat(g.config.DatabasePath); os.IsNotExist(err) {
		return fmt.Errorf("GeoIP city database file not found: %s", g.config.DatabasePath)
	}

	// 在锁外打开新数据库（耗时操作）
	newCityDB, err := geoip2.Open(g.config.DatabasePath)
	if err != nil {
		return fmt.Errorf("failed to open GeoIP city database: %w", err)
	}

	// 尝试打开ASN数据库（可选）
	var newASNDB *geoip2.Reader
	asnPath := strings.Replace(g.config.DatabasePath, "GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb", 1)
	if _, err := os.Stat(asnPath); err == nil {
		if asnDB, err := geoip2.Open(asnPath); err == nil {
			newASNDB = asnDB
			g.log.Infof("ASN database loaded successfully from: %s", asnPath)
		} else {
			g.log.Warnf("ASN database file exists but failed to open: %v", err)
		}
	} else {
		g.log.Infof("ASN database not found at: %s (this is optional)", asnPath)
	}

	// 快速切换数据库（持有锁的时间最短）
	g.mutex.Lock()
	oldCityDB := g.cityDatabase
	oldASNDB := g.asnDatabase
	g.cityDatabase = newCityDB
	g.asnDatabase = newASNDB
	g.lastUpdate = time.Now()
	g.mutex.Unlock()

	// 在锁外关闭旧数据库
	if oldCityDB != nil {
		oldCityDB.Close()
	}
	if oldASNDB != nil {
		oldASNDB.Close()
	}

	g.log.Infof("GeoIP city database loaded successfully from: %s", g.config.DatabasePath)
	return nil
}

// CheckCountryAccess 检查国家访问权限
func (g *GeoIPService) CheckCountryAccess(ip string) (*GeoFilterResult, error) {
	if !g.config.Enabled {
		return &GeoFilterResult{
			Allowed: true,
			Reason:  "GeoIP filtering disabled",
		}, nil
	}

	// 获取地理位置信息
	location, err := g.GetLocation(ip)
	if err != nil {
		// 如果无法获取地理位置信息，根据配置决定是否允许
		if g.config.AllowUnknown {
			return &GeoFilterResult{
				Allowed: true,
				Reason:  fmt.Sprintf("Unknown location, allowed by config: %v", err),
			}, nil
		}
		return &GeoFilterResult{
			Allowed: false,
			Reason:  fmt.Sprintf("Unknown location, blocked by config: %v", err),
		}, nil
	}

	// 检查是否在阻止列表中
	for _, blocked := range g.config.BlockedCountries {
		if location.CountryCode == blocked {
			return &GeoFilterResult{
				Allowed:  false,
				Country:  location.Country,
				Reason:   fmt.Sprintf("Country %s (%s) is blocked", location.Country, location.CountryCode),
				Location: location,
			}, nil
		}
	}

	// 如果有允许列表，检查是否在其中
	if len(g.config.AllowedCountries) > 0 {
		for _, allowed := range g.config.AllowedCountries {
			if location.CountryCode == allowed {
				return &GeoFilterResult{
					Allowed:  true,
					Country:  location.Country,
					Reason:   fmt.Sprintf("Country %s (%s) is allowed", location.Country, location.CountryCode),
					Location: location,
				}, nil
			}
		}
		// 不在允许列表中
		return &GeoFilterResult{
			Allowed:  false,
			Country:  location.Country,
			Reason:   fmt.Sprintf("Country %s (%s) not in allowed list", location.Country, location.CountryCode),
			Location: location,
		}, nil
	}

	// 没有允许列表且不在阻止列表中，允许访问
	return &GeoFilterResult{
		Allowed:  true,
		Country:  location.Country,
		Reason:   fmt.Sprintf("Country %s (%s) is allowed", location.Country, location.CountryCode),
		Location: location,
	}, nil
}

// GetLocation 获取IP的地理位置信息（增强版：慢查询日志）
func (g *GeoIPService) GetLocation(ipStr string) (*GeoLocation, error) {
	// 记录开始时间（用于慢查询检测）
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		// 慢查询阈值：100ms
		if duration > 100*time.Millisecond {
			g.log.Warnf("GeoIP慢查询: IP=%s, 耗时=%v", ipStr, duration)
		}
	}()

	g.mutex.RLock()

	// 检查缓存
	if cached, exists := g.cache[ipStr]; exists {
		if time.Since(cached.CachedAt) < g.cacheTTL {
			g.mutex.RUnlock()
			return cached, nil
		}
		// 缓存过期，删除
		delete(g.cache, ipStr)
	}
	g.mutex.RUnlock()

	// 解析IP地址
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	g.mutex.RLock()
	if g.cityDatabase == nil {
		g.mutex.RUnlock()
		return nil, fmt.Errorf("GeoIP city database not loaded")
	}

	// 查询城市信息
	record, err := g.cityDatabase.City(ip)

	// 查询ASN信息（如果可用）
	var asnRecord *geoip2.ASN
	if g.asnDatabase != nil {
		if asn, asnErr := g.asnDatabase.ASN(ip); asnErr == nil {
			asnRecord = asn
		}
	}
	g.mutex.RUnlock()

	if err != nil {
		return nil, fmt.Errorf("GeoIP lookup failed: %w", err)
	}

	// 构建地理位置信息
	location := &GeoLocation{
		CountryCode: record.Country.IsoCode,
		Latitude:    float64(record.Location.Latitude),
		Longitude:   float64(record.Location.Longitude),
		Timezone:    record.Location.TimeZone,
		CachedAt:    time.Now(),
	}

	// 安全地获取国家名称
	if countryName, exists := record.Country.Names["zh-CN"]; exists {
		location.Country = countryName
	} else if countryName, exists := record.Country.Names["en"]; exists {
		location.Country = countryName
	}

	// 安全地获取城市名称
	if cityName, exists := record.City.Names["zh-CN"]; exists {
		location.City = cityName
	} else if cityName, exists := record.City.Names["en"]; exists {
		location.City = cityName
	}

	// 安全地获取地区名称
	if len(record.Subdivisions) > 0 {
		if regionName, exists := record.Subdivisions[0].Names["zh-CN"]; exists {
			location.Region = regionName
		} else if regionName, exists := record.Subdivisions[0].Names["en"]; exists {
			location.Region = regionName
		}
	}

	// 使用ASN数据库获取ISP信息
	if asnRecord != nil {
		location.ISP = asnRecord.AutonomousSystemOrganization
	}

	// 缓存结果
	g.mutex.Lock()
	// 限制缓存大小
	if len(g.cache) >= g.cacheSize {
		// 删除最旧的缓存项
		var oldestKey string
		var oldestTime time.Time
		for key, loc := range g.cache {
			if oldestKey == "" || loc.CachedAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = loc.CachedAt
			}
		}
		if oldestKey != "" {
			delete(g.cache, oldestKey)
		}
	}
	g.cache[ipStr] = location
	g.mutex.Unlock()

	return location, nil
}

// startAutoUpdateTask 启动自动更新任务
func (g *GeoIPService) startAutoUpdateTask() {
	ticker := time.NewTicker(g.updateInterval)
	defer ticker.Stop()

	g.log.Infof("GeoIP自动更新任务已启动，更新间隔: %v", g.updateInterval)

	for {
		select {
		case <-ticker.C:
			g.log.Info("开始自动更新GeoIP数据库...")
			if err := g.UpdateDatabase(context.Background()); err != nil {
				g.log.Errorf("自动更新GeoIP数据库失败: %v", err)
			} else {
				g.log.Info("GeoIP数据库自动更新成功")
			}
		case <-g.stopUpdateChan:
			g.log.Info("GeoIP自动更新任务已停止")
			return
		}
	}
}

// StopAutoUpdate 停止自动更新任务
func (g *GeoIPService) StopAutoUpdate() {
	if g.stopUpdateChan != nil {
		close(g.stopUpdateChan)
		g.stopUpdateChan = nil
	}
}

// UpdateDatabase 更新GeoIP数据库（增强版：重试机制）
func (g *GeoIPService) UpdateDatabase(ctx context.Context) error {
	// 检查数据库文件的修改时间
	fileInfo, err := os.Stat(g.config.DatabasePath)
	if err != nil {
		return fmt.Errorf("无法获取数据库文件信息: %w", err)
	}

	// 如果文件在最近7天内更新过，跳过更新
	if time.Since(fileInfo.ModTime()) < g.updateInterval {
		g.log.Infof("GeoIP数据库文件较新（%v），跳过更新", fileInfo.ModTime().Format("2006-01-02"))
		return nil
	}

	// 如果配置了更新URL，尝试下载（带重试）
	if g.updateURL != "" {
		g.log.Infof("从 %s 下载GeoIP数据库更新...", g.updateURL)
		
		// 重试机制：最多3次
		var lastErr error
		for retry := 0; retry < 3; retry++ {
			if retry > 0 {
				waitTime := time.Duration(retry) * 10 * time.Second
				g.log.Warnf("下载失败，%v 后重试（第%d次尝试）: %v", waitTime, retry+1, lastErr)
				time.Sleep(waitTime)
			}

			if err := g.downloadDatabase(ctx); err != nil {
				lastErr = err
				continue
			}

			// 下载成功，跳出重试循环
			lastErr = nil
			break
		}

		if lastErr != nil {
			return fmt.Errorf("下载数据库失败（已重试3次）: %w", lastErr)
		}
	} else {
		// 没有配置更新URL，只记录提示
		g.log.Warnf("GeoIP数据库文件已过期（%v），但未配置更新URL，请手动更新", fileInfo.ModTime().Format("2006-01-02"))
		g.log.Info("提示：可以从 https://dev.maxmind.com/geoip/geolite2-free-geolocation-data 下载最新数据库")
		return nil
	}

	// 重新加载数据库
	if err := g.loadDatabase(); err != nil {
		return fmt.Errorf("重新加载数据库失败: %w", err)
	}

	g.log.Info("GeoIP数据库更新成功")
	return nil
}

// downloadDatabase 下载GeoIP数据库（增强版：进度监控）
func (g *GeoIPService) downloadDatabase(ctx context.Context) error {
	// 创建HTTP客户端（增加超时时间）
	client := &http.Client{
		Timeout: 10 * time.Minute, // 10分钟超时（大文件可能需要更长时间）
	}

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", g.updateURL, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，HTTP状态码: %d", resp.StatusCode)
	}

	// 获取文件大小
	contentLength := resp.ContentLength
	if contentLength > 0 {
		g.log.Infof("开始下载GeoIP数据库，大小: %.2f MB", float64(contentLength)/(1024*1024))
	} else {
		g.log.Info("开始下载GeoIP数据库（大小未知）")
	}

	// 创建临时文件
	tmpFile := g.config.DatabasePath + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer file.Close()

	// 创建进度读取器
	progressReader := &progressReader{
		reader:        resp.Body,
		total:         contentLength,
		logger:        g.log,
		lastReportPct: -1,
	}

	// 复制数据（带进度监控）
	written, err := file.ReadFrom(progressReader)
	if err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("保存文件失败: %w", err)
	}
	file.Close()

	g.log.Infof("GeoIP数据库下载完成，大小: %.2f MB", float64(written)/(1024*1024))

	// 替换旧文件
	if err := os.Rename(tmpFile, g.config.DatabasePath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("替换数据库文件失败: %w", err)
	}

	return nil
}

// progressReader 进度读取器
type progressReader struct {
	reader        io.Reader
	total         int64
	read          int64
	logger        *logrus.Entry
	lastReportPct int
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)

	// 如果知道总大小，报告进度（每10%报告一次）
	if pr.total > 0 {
		pct := int(float64(pr.read) / float64(pr.total) * 100)
		if pct >= pr.lastReportPct+10 && pct <= 100 {
			pr.logger.Infof("下载进度: %d%% (%.2f MB / %.2f MB)",
				pct,
				float64(pr.read)/(1024*1024),
				float64(pr.total)/(1024*1024))
			pr.lastReportPct = pct
		}
	}

	return n, err
}

// UpdateGeoConfig 更新地理位置配置
func (g *GeoIPService) UpdateGeoConfig(newConfig config.GeoBlockingConfig) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	oldEnabled := g.config.Enabled
	oldDatabasePath := g.config.DatabasePath

	// 更新配置
	g.config = newConfig

	// 如果数据库路径发生变化，重新加载数据库
	if newConfig.DatabasePath != oldDatabasePath {
		if newConfig.Enabled && newConfig.DatabasePath != "" {
			if err := g.loadDatabase(); err != nil {
				g.log.Errorf("Failed to reload GeoIP database: %v", err)
				g.config.Enabled = false
				return fmt.Errorf("failed to reload database: %w", err)
			}
		}
	}

	// 记录配置变化
	if oldEnabled != newConfig.Enabled {
		if newConfig.Enabled {
			g.log.Info("GeoIP filtering enabled")
		} else {
			g.log.Info("GeoIP filtering disabled")
		}
	}

	g.log.Infof("GeoIP configuration updated: allowed_countries=%v, blocked_countries=%v",
		newConfig.AllowedCountries, newConfig.BlockedCountries)

	return nil
}

// GetStats 获取GeoIP服务统计信息
func (g *GeoIPService) GetStats() map[string]interface{} {
	g.mutex.RLock()
	defer g.mutex.RUnlock()

	stats := map[string]interface{}{
		"enabled":           g.config.Enabled,
		"database_path":     g.config.DatabasePath,
		"city_db_loaded":    g.cityDatabase != nil,
		"asn_db_loaded":     g.asnDatabase != nil,
		"last_update":       g.lastUpdate,
		"cache_size":        len(g.cache),
		"cache_max_size":    g.cacheSize,
		"cache_ttl_hours":   g.cacheTTL.Hours(),
		"allowed_countries": g.config.AllowedCountries,
		"blocked_countries": g.config.BlockedCountries,
		"allow_unknown":     g.config.AllowUnknown,
	}

	return stats
}

// ClearCache 清空缓存
func (g *GeoIPService) ClearCache() {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	g.cache = make(map[string]*GeoLocation)
	g.log.Info("GeoIP cache cleared")
}

// Close 关闭GeoIP服务
func (g *GeoIPService) Close() error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	var errs []error

	if g.cityDatabase != nil {
		if err := g.cityDatabase.Close(); err != nil {
			errs = append(errs, err)
		}
		g.cityDatabase = nil
	}

	if g.asnDatabase != nil {
		if err := g.asnDatabase.Close(); err != nil {
			errs = append(errs, err)
		}
		g.asnDatabase = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing databases: %v", errs)
	}

	return nil
}

// Middleware 创建地理位置过滤中间件
func (g *GeoIPService) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// 获取客户端IP
		clientIP := GetClientIP(r.RemoteAddr, map[string]string{
			"X-Forwarded-For": r.Header.Get("X-Forwarded-For"),
			"X-Real-IP":       r.Header.Get("X-Real-IP"),
		})

		// 检查地理位置访问权限
		result, err := g.CheckCountryAccess(clientIP)
		if err != nil {
			g.log.Errorf("GeoIP check error for %s: %v", clientIP, err)
			if !g.config.AllowUnknown {
				http.Error(w, "Access denied: location verification failed", http.StatusForbidden)
				return
			}
		}

		if !result.Allowed {
			g.log.Warnf("GeoIP blocked request from %s (%s): %s", clientIP, result.Country, result.Reason)
			http.Error(w, fmt.Sprintf("Access denied: %s", result.Reason), http.StatusForbidden)
			return
		}

		// 在请求上下文中添加地理位置信息
		if result.Location != nil {
			r.Header.Set("X-GeoIP-Country", result.Location.Country)
			r.Header.Set("X-GeoIP-Country-Code", result.Location.CountryCode)
			r.Header.Set("X-GeoIP-City", result.Location.City)
		}

		next.ServeHTTP(w, r)
	})
}
