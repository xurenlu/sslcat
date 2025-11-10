package web

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" // 导入 pprof 用于性能分析
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/ai"
	"github.com/xurenlu/sslcat/internal/assets"
	"github.com/xurenlu/sslcat/internal/cache"
	"github.com/xurenlu/sslcat/internal/compression"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ddos"
	"github.com/xurenlu/sslcat/internal/i18n"
	"github.com/xurenlu/sslcat/internal/imageopt"
	"github.com/xurenlu/sslcat/internal/logger"
	"github.com/xurenlu/sslcat/internal/metrics"
	"github.com/xurenlu/sslcat/internal/monitor"
	"github.com/xurenlu/sslcat/internal/notification"
	"github.com/xurenlu/sslcat/internal/notify"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/runner"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/slowrequest"
	"github.com/xurenlu/sslcat/internal/ssl"
	"github.com/xurenlu/sslcat/internal/statistics"
	"github.com/xurenlu/sslcat/internal/tracing"
	"github.com/xurenlu/sslcat/internal/tunnel"
	"github.com/xurenlu/sslcat/internal/waf"

	"io"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

// Server Web服务器
type Server struct {
	config           *config.Config
	proxyManager     *proxy.Manager
	securityManager  *security.Manager
	sslManager       *ssl.Manager
	notifier         *notify.Notifier
	templateRenderer *TemplateRenderer
	translator       *i18n.Translator
	mux              *http.ServeMux
	log              *logrus.Entry
	startTime        time.Time
	version          string
	leRedirectHost   string
	lastLECheck      time.Time
	lastConfigHash   string
	compressor       *compression.Compressor
	compressionCache *CompressionCache

	// 共享缓存
	sharedCache *cache.MemoryCache

	// 配置热重载
	configWatcher   *config.ConfigWatcher
	reloadManager   *config.ReloadManager
	configReloadAPI *ConfigReloadAPI

	// Prometheus指标
	prometheusMetrics *metrics.PrometheusMetrics

	// 请求追踪
	tracer *tracing.Tracer

	// WAF引擎
	wafEngine *waf.AdvancedEngine

	// 导入配置暂存
	pendingImportJSON string
	pendingImport     *config.Config
	pendingDiff       *config.ConfigDiff
	// Token 管理
	tokenStore *security.TokenStore
	// DNS 缓存管理
	dnsCache *DNSCache
	// 验证码管理
	captchaManager *CaptchaManager
	// DDoS 防护器
	ddosProtector *ddos.Protector
	// 审计轮转器
	auditRotator *logger.Rotator
	// 访问日志记录器
	accessLogger *logger.AccessLogger
	// 代理访问控制管理器
	proxyAuthManager *ProxyAuthManager
	// 用户管理器
	userManager *UserManager
	// 会话管理器
	sessionManager *SessionManager
	// 通知集成器
	notificationIntegrator *notification.NotificationIntegrator
	// Runner 模块
	gitServer *runner.GitServer
	// 统计收集器和API
	statisticsCollector *statistics.Collector
	statisticsAPI       *StatisticsAPI
	// 静态文件处理器
	staticHandler *StaticFileHandler
	// AI 安全分析器
	aiSecurityAnalyzer *ai.SecurityAnalyzer
	// 图片优化器
	imageOptimizer *imageopt.Optimizer

	// 监控管理器
	monitorManager *monitor.Manager
	// 慢请求管理器
	slowRequestManager *slowrequest.Manager

	// 隧道管理器
	tunnelManager *tunnel.Manager

	// Cluster runtime status
	clusterLastConfigSyncAt      time.Time
	clusterLastCertSyncAt        time.Time
	clusterMasterLastReachableAt time.Time
	clusterLastSyncError         string
}

// NewServer 创建Web服务器
func NewServer(cfg *config.Config, proxyMgr *proxy.Manager, secMgr *security.Manager, sslMgr *ssl.Manager, gitServer *runner.GitServer, notificationIntegrator *notification.NotificationIntegrator, version string) *Server {
	// 初始化压缩器
	compressor := compression.NewCompressor(compression.FromConfig(cfg))

	// 创建共享的内存缓存实例（合并压缩缓存和图片优化缓存）
	sharedCacheSizeMB := cfg.Server.SharedCacheMaxSizeMB
	if sharedCacheSizeMB <= 0 {
		sharedCacheSizeMB = 64
	}
	if sharedCacheSizeMB < 8 {
		sharedCacheSizeMB = 8
	}
	maxSharedCacheBytes := int64(sharedCacheSizeMB) * 1024 * 1024

	sharedCache := cache.NewMemoryCache(&cache.MemoryCacheConfig{
		Name:            "shared_cache",
		MaxEntries:      400, // 压缩200 + 图片200
		MaxSizeBytes:    maxSharedCacheBytes,
		MaxItemSize:     2 * 1024 * 1024, // 2MB
		DefaultTTL:      24 * time.Hour,  // 24小时
		CleanupInterval: 5 * time.Minute, // 统一使用5分钟清理间隔
	})

	// 使用共享缓存实例创建压缩缓存
	compressionCache := NewCompressionCacheWithCache(sharedCache)

	// 初始化Prometheus指标
	prometheusMetrics := metrics.NewPrometheusMetrics()

	// 初始化请求追踪器（10%采样率）
	tracer := tracing.NewTracer(
		"sslcat",
		tracing.NewRateSampler(0.1),
		tracing.NewLogReporter(),
	)

	// 初始化慢请求管理器（记录超过500ms的请求，最多保存1000条记录）
	slowRequestManager := slowrequest.NewManager(1000, 500*time.Millisecond)

	dataDir := cfg.Server.DataDir
	if dataDir == "" {
		dataDir = "./data"
	}

	// 初始化隧道管理器
	tunnelManager := tunnel.NewManager(cfg.Tunnels, dataDir, logrus.WithField("component", "tunnel_manager"))

	// 初始化图片优化器
	imageOptConfig := &imageopt.Config{
		Enabled:         cfg.ImageOptimization.Enabled,
		AutoWebP:        cfg.ImageOptimization.AutoWebP,
		WebPQuality:     cfg.ImageOptimization.WebPQuality,
		JPEGQuality:     cfg.ImageOptimization.JPEGQuality,
		PNGLevel:        cfg.ImageOptimization.PNGLevel,
		StripMetadata:   cfg.ImageOptimization.StripMetadata,
		AllowResize:     cfg.ImageOptimization.AllowResize,
		MaxWidth:        cfg.ImageOptimization.MaxWidth,
		MaxHeight:       cfg.ImageOptimization.MaxHeight,
		AllowedSizes:    cfg.ImageOptimization.AllowedSizes,
		CacheEnabled:    cfg.ImageOptimization.CacheEnabled,
		CacheTTL:        cfg.ImageOptimization.CacheTTL,
		MaxCacheSize:    cfg.ImageOptimization.MaxCacheSize,
		IncludePatterns: cfg.ImageOptimization.IncludePatterns,
		ExcludePatterns: cfg.ImageOptimization.ExcludePatterns,
	}
	// 设置默认值
	if imageOptConfig.WebPQuality == 0 {
		imageOptConfig.WebPQuality = 80
	}
	if imageOptConfig.JPEGQuality == 0 {
		imageOptConfig.JPEGQuality = 85
	}
	if imageOptConfig.PNGLevel == 0 {
		imageOptConfig.PNGLevel = 6
	}
	if imageOptConfig.MaxWidth == 0 {
		imageOptConfig.MaxWidth = 2000
	}
	if imageOptConfig.MaxHeight == 0 {
		imageOptConfig.MaxHeight = 2000
	}
	if imageOptConfig.CacheTTL == 0 {
		imageOptConfig.CacheTTL = 86400
	}
	if imageOptConfig.MaxCacheSize == 0 {
		imageOptConfig.MaxCacheSize = 200 * 1024 * 1024 // 从1GB减少到200MB
	}
	// 使用共享缓存实例创建图片优化器
	imageOptimizer := imageopt.NewOptimizerWithCache(imageOptConfig, sharedCache)

	// 初始化WAF引擎
	wafEngine := waf.NewAdvancedEngine()

	// 初始化翻译器（从嵌入读取）
	translator := i18n.NewTranslator(i18n.LangZhCN, "")
	// 通过嵌入 i18n 文件加载翻译
	if files, err := assets.ListI18nFiles(); err == nil {
		for _, f := range files {
			if b, err := assets.ReadI18nFile(f); err == nil {
				code := i18n.SupportedLanguage(strings.TrimSuffix(f, ".json"))
				_ = translator.SaveTranslations(code, func() map[string]string {
					m := make(map[string]string)
					_ = json.Unmarshal(b, &m)
					return m
				}())
			}
		}
	} else {
		logrus.Warnf("Failed to read embedded i18n files: %v", err)
	}

	// 初始化模板渲染器
	templateRenderer := NewTemplateRenderer(translator)

	server := &Server{
		config:             cfg,
		proxyManager:       proxyMgr,
		securityManager:    secMgr,
		sslManager:         sslMgr,
		notifier:           notify.NewFromEnv(),
		templateRenderer:   templateRenderer,
		translator:         translator,
		mux:                http.NewServeMux(),
		startTime:          time.Now(),
		version:            version,
		gitServer:          gitServer,
		compressor:         compressor,
		compressionCache:   compressionCache,
		prometheusMetrics:  prometheusMetrics,
		tracer:             tracer,
		imageOptimizer:     imageOptimizer,
		wafEngine:          wafEngine,
		slowRequestManager: slowRequestManager,
		tunnelManager:      tunnelManager,
		sharedCache:        sharedCache,
		log: logrus.WithFields(logrus.Fields{
			"component": "web_server",
		}),
	}

	// 初始化 TokenStore
	server.tokenStore = security.NewTokenStore("./data/tokens.json")

	// 初始化 DNS 缓存管理器
	server.dnsCache = NewDNSCache(sslMgr)

	// 初始化验证码管理器
	server.captchaManager = NewCaptchaManager()
	// 初始化 DDoS 防护器
	server.ddosProtector = ddos.NewProtector(notificationIntegrator)

	// 将 GeoIP 服务设置到 DDoS 防护器
	if secMgr != nil && secMgr.GetGeoIPService() != nil {
		server.ddosProtector.SetGeoIPService(secMgr.GetGeoIPService())
	}

	// 初始化代理访问控制管理器
	server.proxyAuthManager = NewProxyAuthManager(server.log)

	// 初始化用户管理器
	userManager, err := NewUserManager(server.log, "./data", "admin")
	if err != nil {
		logrus.Fatalf("初始化用户管理器失败: %v", err)
	}
	server.userManager = userManager

	// 初始化会话管理器（使用配置的存储类型）
	sessionStorage := cfg.Server.SessionStorage
	if sessionStorage == "" {
		sessionStorage = "file" // 默认使用文件存储
	}
	if cfg.Server.DataDir != "" {
		dataDir = cfg.Server.DataDir
	}
	if dataDir == "" {
		dataDir = "./data" // 默认数据目录
	}

	factory := NewSessionManagerFactory()
	sessionManager, err := factory.CreateSessionManager(server.log, sessionStorage, dataDir)
	if err != nil {
		logrus.Fatalf("创建会话管理器失败: %v", err)
	}
	server.sessionManager = sessionManager
	server.log.Infof("会话管理器已初始化，存储类型: %s，数据目录: %s", sessionStorage, dataDir)

	// 设置通知集成器
	server.notificationIntegrator = notificationIntegrator

	// 初始化统计收集器
	statsEnabled := true // 默认启用，可以通过配置控制
	server.statisticsCollector = statistics.NewCollector("./data/statistics", statsEnabled)
	server.statisticsAPI = NewStatisticsAPI(server.statisticsCollector, server)

	// 设置慢请求记录器到代理管理器
	slowRequestAdapter := slowrequest.NewAdapter(server.slowRequestManager)
	server.proxyManager.SetSlowRequestRecorder(slowRequestAdapter)

	// 初始化静态文件处理器
	server.staticHandler = NewStaticFileHandler(cfg)

	// 初始化 AI 安全分析器（如果启用）
	if cfg.AISecurity.Enabled && cfg.AISecurity.APIKey != "" {
		server.aiSecurityAnalyzer = ai.NewSecurityAnalyzer(cfg.AISecurity, notificationIntegrator)

		// 启动定时分析
		dataCollector := ai.NewDataCollector(
			server.ddosProtector,
			server.securityManager,
			cfg.AISecurity.AnalysisWindow,
		)
		server.aiSecurityAnalyzer.Start(dataCollector.Collect)

		logrus.Infof("AI 安全分析器已启动，模型: %s，间隔: %v",
			cfg.AISecurity.Model, cfg.AISecurity.CheckInterval)
	}

	// 初始化监控管理器（如果启用）
	if cfg.Monitoring.Enabled {
		memoryUsagePercent := cfg.Monitoring.MemoryMaxUsagePercent
		if memoryUsagePercent <= 0 {
			memoryUsagePercent = 20
		}
		if memoryUsagePercent < 5 {
			memoryUsagePercent = 5
		}
		if memoryUsagePercent > 90 {
			memoryUsagePercent = 90
		}
		releaseCooldownSec := cfg.Monitoring.MemoryReleaseCooldownSec
		if releaseCooldownSec < 60 {
			releaseCooldownSec = 300
		}
		server.monitorManager = monitor.NewManager(monitor.ManagerOptions{
			Enabled: cfg.Monitoring.Enabled,
			Memory: monitor.MemoryMonitorOptions{
				CheckInterval:       time.Minute,
				MaxSystemUsageRatio: memoryUsagePercent / 100.0,
				ReleaseCooldown:     time.Duration(releaseCooldownSec) * time.Second,
			},
		})
		server.monitorManager.Start()
		server.log.Info("监控管理器已启动")
	}

	// 初始化审计日志轮转器（10MB*10）
	if rot, err := logger.NewRotator("./data/audit.log", 10*1024*1024, 10); err == nil {
		server.auditRotator = rot
	}

	// 初始化访问日志记录器（可配置）
	if cfg.Server.AccessLogEnabled {
		format := logger.FormatNginx
		switch strings.ToLower(cfg.Server.AccessLogFormat) {
		case "apache":
			format = logger.FormatApache
		case "json":
			format = logger.FormatJSON
		}
		al, err := logger.NewAccessLogger(format, cfg.Server.AccessLogPath, true)
		if err == nil {
			// 覆盖默认大小/数量
			if cfg.Server.AccessLogMaxSize > 0 {
				al.SetMaxSize(cfg.Server.AccessLogMaxSize)
			}
			if cfg.Server.AccessLogMaxFiles > 0 {
				al.SetMaxFiles(cfg.Server.AccessLogMaxFiles)
			}
			server.accessLogger = al
		}
	}

	server.setupRoutes()

	// 设置图片优化器到代理管理器
	if server.imageOptimizer != nil && server.imageOptimizer.Config.Enabled {
		server.proxyManager.SetResponseProcessor(server.imageOptimizer)
		server.log.Info("Image optimizer enabled and integrated with proxy manager")
	}

	// 初始化配置文件哈希并启动热加载监听（Slave 模式）
	server.initConfigWatch()

	// 启动定时检查有效LE证书对应域名是否解析到本机公网IP
	go server.refreshLEPreferredHostLoop()

	// 初始化 DNS 缓存并启动定期更新
	server.initDNSCache()

	return server
}

// SetupConfigReload 设置配置热重载功能
func (s *Server) SetupConfigReload(configWatcher *config.ConfigWatcher, reloadManager *config.ReloadManager) {
	s.configWatcher = configWatcher
	s.reloadManager = reloadManager
	s.configReloadAPI = NewConfigReloadAPI(s, configWatcher, reloadManager)

	// 设置API路由
	s.configReloadAPI.SetupRoutes()

	s.log.Info("Config hot reload functionality enabled")
}

// UpdateConfig 更新服务器配置（热重载时调用）
func (s *Server) UpdateConfig(newConfig *config.Config) {
	s.log.Info("Updating server configuration")

	oldConfig := s.config

	// 清理旧配置相关的资源
	s.cleanupOldConfigResources(oldConfig, newConfig)

	s.config = newConfig
	if s.tunnelManager != nil {
		s.tunnelManager.SyncFromConfig(newConfig.Tunnels)
	}

	// 更新压缩器配置
	if s.compressor != nil {
		s.compressor = compression.NewCompressor(compression.FromConfig(newConfig))
		s.log.Info("Updated compressor configuration")
	}

	// 如果管理面板前缀发生变化，需要重新设置路由
	if oldConfig.AdminPrefix != newConfig.AdminPrefix {
		s.log.Infof("Admin prefix changed: %s -> %s", oldConfig.AdminPrefix, newConfig.AdminPrefix)
		// 注意：这里可能需要重新初始化路由，但这会比较复杂
		// 建议在文档中说明管理面板前缀变化需要重启服务
	}

	s.log.Info("Server configuration updated successfully")
}

// cleanupOldConfigResources 清理旧配置相关的资源
func (s *Server) cleanupOldConfigResources(oldConfig, newConfig *config.Config) {
	// 1. 清理DNS缓存（如果DNS提供商发生变化）
	if s.dnsCache != nil {
		oldProviders := make(map[string]bool)
		for _, p := range oldConfig.SSL.DNSProviders {
			if p.Enabled {
				oldProviders[p.Name] = true
			}
		}

		newProviders := make(map[string]bool)
		for _, p := range newConfig.SSL.DNSProviders {
			if p.Enabled {
				newProviders[p.Name] = true
			}
		}

		// 检查是否有变化
		hasChanges := false
		for name := range oldProviders {
			if !newProviders[name] {
				hasChanges = true
				break
			}
		}
		for name := range newProviders {
			if !oldProviders[name] {
				hasChanges = true
				break
			}
		}

		if hasChanges {
			s.log.Info("DNS providers changed, stopping old periodic update")
			s.dnsCache.StopPeriodicUpdate()

			// 重新初始化DNS缓存
			var enabledProviders []string
			for _, provider := range newConfig.SSL.DNSProviders {
				if provider.Enabled {
					enabledProviders = append(enabledProviders, provider.Name)
				}
			}
			s.dnsCache.UpdateAllProvidersCache(enabledProviders)
			s.dnsCache.StartPeriodicUpdate(enabledProviders, 5*time.Minute)
			s.log.Infof("DNS cache reinitialized for %d providers", len(enabledProviders))
		}
	}

	// 2. 清理GeoIP服务（如果数据库路径发生变化）
	if s.securityManager != nil {
		oldGeoPath := oldConfig.Security.GeoBlocking.DatabasePath
		newGeoPath := newConfig.Security.GeoBlocking.DatabasePath

		if oldGeoPath != newGeoPath {
			s.log.Info("GeoIP database path changed, will reload on next access")
			// GeoIPService 会在下次访问时自动重新加载
		}
	}

	// 3. 清理压缩缓存（如果压缩配置发生显著变化）- 异步执行
	if s.compressionCache != nil {
		if oldConfig.Compression.Enabled != newConfig.Compression.Enabled ||
			oldConfig.Compression.Level != newConfig.Compression.Level {
			s.log.Info("Compression config changed significantly, clearing cache asynchronously")
			go func() {
				s.compressionCache.Clear()
				s.log.Info("Compression cache cleared")
			}()
		}
	}

	// 4. 清理图片优化缓存（如果图片优化配置发生变化）- 异步执行
	if s.imageOptimizer != nil {
		if oldConfig.ImageOptimization.Enabled != newConfig.ImageOptimization.Enabled ||
			oldConfig.ImageOptimization.WebPQuality != newConfig.ImageOptimization.WebPQuality ||
			oldConfig.ImageOptimization.JPEGQuality != newConfig.ImageOptimization.JPEGQuality {
			s.log.Info("Image optimization config changed, clearing cache asynchronously")
			go func() {
				s.imageOptimizer.ClearCache()
				s.log.Info("Image optimization cache cleared")
			}()
		}
	}

	s.log.Debug("Old config resources cleanup completed")
}

// initDNSCache 初始化DNS缓存并启动定期更新
func (s *Server) initDNSCache() {
	// 获取所有启用的DNS提供商
	var enabledProviders []string
	for _, provider := range s.config.SSL.DNSProviders {
		if provider.Enabled {
			enabledProviders = append(enabledProviders, provider.Name)
		}
	}

	// 立即更新一次缓存
	s.dnsCache.UpdateAllProvidersCache(enabledProviders)

	// 启动定期更新（每5分钟更新一次）
	s.dnsCache.StartPeriodicUpdate(enabledProviders, 5*time.Minute)

	s.log.Infof("DNS cache initialized for %d providers: %v", len(enabledProviders), enabledProviders)
}

// initConfigWatch 计算初始哈希并启动后台监听
func (s *Server) initConfigWatch() {
	path := s.config.ConfigFile
	if path == "" {
		path = "/etc/sslcat/sslcat.conf"
	}
	if b, err := os.ReadFile(path); err == nil {
		sum := sha256.Sum256(b)
		s.lastConfigHash = hex.EncodeToString(sum[:])
	}
	go s.watchConfigFileLoop()
	go s.watchConfigFileFS()
}

// watchConfigFileLoop 定时检查配置文件变化并热加载（仅在 Slave 模式生效）
func (s *Server) watchConfigFileLoop() {
	// 优化：非集群模式下使用更长的间隔，减少不必要的检查
	interval := 5 * time.Second
	if !s.config.IsSlaveMode() {
		// 非集群模式下，使用 30 秒间隔，减少 CPU 占用
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if !s.config.IsSlaveMode() {
			// 非集群模式下，只做最基本的检查，避免频繁的文件读取
			continue
		}
		path := s.config.ConfigFile
		if path == "" {
			path = "/etc/sslcat/sslcat.conf"
		}
		b, err := os.ReadFile(path)
		if err != nil || len(b) == 0 {
			continue
		}
		sum := sha256.Sum256(b)
		hash := hex.EncodeToString(sum[:])
		if hash == s.lastConfigHash || hash == "" {
			continue
		}
		var newCfg config.Config
		if err := json.Unmarshal(b, &newCfg); err != nil {
			s.log.Warnf("Failed to parse synced config: %v", err)
			continue
		}
		// 保持配置文件路径
		newCfg.ConfigFile = s.config.ConfigFile
		// 应用新配置（就地更新）
		oldPrefix := s.config.AdminPrefix
		s.applyConfigInPlace(&newCfg)
		s.lastConfigHash = hash
		// 若前缀变化，重建路由
		if oldPrefix != s.config.AdminPrefix {
			s.mux = http.NewServeMux()
			s.setupRoutes()
		}
		s.log.Infof("Config reloaded from %s (cluster sync)", path)
	}
}

// watchConfigFileFS 使用 fsnotify 监听文件变化，触发热加载
func (s *Server) watchConfigFileFS() {
	// 仅 Slave 模式生效
	if !s.config.IsSlaveMode() {
		return
	}
	path := s.config.ConfigFile
	if path == "" {
		path = "/etc/sslcat/sslcat.conf"
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		s.log.Warnf("fsnotify init failed: %v", err)
		return
	}
	defer watcher.Close()

	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		s.log.Warnf("fsnotify add failed: %v", err)
		return
	}
	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			// 关注写入或重命名到目标文件
			if ev.Name == path && (ev.Op&fsnotify.Write == fsnotify.Write || ev.Op&fsnotify.Create == fsnotify.Create || ev.Op&fsnotify.Rename == fsnotify.Rename) {
				// 轻微延迟，等待写完成
				time.Sleep(150 * time.Millisecond)
				if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
					var newCfg config.Config
					if err := json.Unmarshal(b, &newCfg); err == nil {
						newCfg.ConfigFile = s.config.ConfigFile
						oldPrefix := s.config.AdminPrefix
						s.applyConfigInPlace(&newCfg)
						// 计算新哈希
						sum := sha256.Sum256(b)
						s.lastConfigHash = hex.EncodeToString(sum[:])
						if oldPrefix != s.config.AdminPrefix {
							s.mux = http.NewServeMux()
							s.setupRoutes()
						}
						s.log.Infof("Config reloaded by fsnotify from %s", path)
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			s.log.Debugf("fsnotify error: %v", err)
		}
	}
}

// applyConfigInPlace 将 newCfg 内容拷贝到现有 s.config，保持指针不变
func (s *Server) applyConfigInPlace(newCfg *config.Config) {
	if newCfg == nil {
		return
	}
	// 顶层字段拷贝
	s.config.Server = newCfg.Server
	s.config.SSL = newCfg.SSL
	s.config.Admin = newCfg.Admin
	s.config.Proxy = newCfg.Proxy
	s.config.Security = newCfg.Security
	s.config.AdminPrefix = newCfg.AdminPrefix
	s.config.Cluster = newCfg.Cluster
	s.config.StaticSites = newCfg.StaticSites
	s.config.PHPSites = newCfg.PHPSites
	s.config.CDNCache = newCfg.CDNCache
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 性能分析路由 (pprof) - 用于调试性能问题，仅允许本地访问
	if s.config.Server.EnablePprof {
		s.mux.HandleFunc("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
			// 安全检查：只允许本地访问
			clientIP := s.getClientIP(r)
			if !s.isPrivateIP(clientIP) && clientIP != "127.0.0.1" && clientIP != "::1" {
				http.Error(w, "Forbidden: pprof endpoint is only accessible from localhost", http.StatusForbidden)
				return
			}
			http.DefaultServeMux.ServeHTTP(w, r)
		})
		s.log.Info("pprof 性能分析端点已启用: /debug/pprof/")
	}

	// 根路径重定向
	s.mux.HandleFunc("/", s.handleRoot)

	// 管理面板路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/", s.handleAdmin)
	s.mux.HandleFunc(s.config.AdminPrefix+"/login", s.handleLogin)
	s.mux.HandleFunc(s.config.AdminPrefix+"/logout", s.handleLogout)
	// 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/dashboard", s.handleDashboard) // 已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/mobile", s.handleMobile) // 已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/charts", s.handleCharts) // 已迁移到前端SPA

	// 代理管理路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/proxy", s.handleProxy) // 已迁移到前端SPA
	// 注意：/proxy/add 和 /proxy/edit 现在由前端 SPA 处理，不再使用后端路由
	// s.mux.HandleFunc(s.config.AdminPrefix+"/proxy/add", s.handleProxyAdd)
	// s.mux.HandleFunc(s.config.AdminPrefix+"/proxy/edit", s.handleProxyEdit)
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy/delete", s.handleProxyDelete)

	// SSL管理路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/ssl", s.handleSSL) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/generate", s.handleSSLGenerate)

	// DNS管理路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/dns", s.handleDNS) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/dns/add", s.handleDNSAdd)
	s.mux.HandleFunc(s.config.AdminPrefix+"/dns/edit", s.handleDNSEdit)
	s.mux.HandleFunc(s.config.AdminPrefix+"/dns/delete", s.handleDNSDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/dns/config", s.handleDNSConfig)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/upload", s.handleSSLUpload)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/download", s.handleSSLDownload)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/delete", s.handleSSLDelete)
	// 从 acme-cache 同步证书到 certs/keys
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/sync-acme", s.handleSSLSyncACME)

	// 安全设置路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/security", s.handleSecurity) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/save", s.handleSecuritySave)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/blocked-ips", s.handleBlockedIPs)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security/unblock", s.handleUnblock)

	// 系统设置路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/settings", s.handleSettings) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/save", s.handleSettingsSave)
	// s.mux.HandleFunc(s.config.AdminPrefix+"/settings/first-setup", s.handleFirstTimeSetup) // GET 请求由前端 SPA 处理，POST 请求由下面的 API 路由处理
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/settings/first-setup", s.handleFirstTimeSetup) // POST 请求的 API 端点
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/change-password", s.handleChangePassword)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings/totp", s.handleTOTPSetup)

	// 用户管理路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/users", s.handleUsers) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/users/add", s.handleUserAdd)
	s.mux.HandleFunc(s.config.AdminPrefix+"/users/edit", s.handleUserEdit)
	s.mux.HandleFunc(s.config.AdminPrefix+"/users/delete", s.handleUserDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/users/logs", s.handleUserLogs)

	// 通知管理路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/notifications", s.handleNotifications) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/notifications/test", s.handleNotificationTest)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/notifications/stats", s.handleNotificationStats)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/notifications/history", s.handleNotificationHistory)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/notifications/test-channels", s.handleNotificationTestChannels)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/notifications/config", s.handleNotificationConfig)

	// AI 安全分析路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/ai-security", s.handleAISecurityPage) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ai-security/config", s.handleAISecurityConfigAPI)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ai-security/test", s.handleAISecurityTest)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ai-security/analyze-now", s.handleAISecurityAnalyzeNow)

	// CDN 缓存设置已整合到代理配置中

	// 静态站点管理 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/static-sites", s.handleStaticSites) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/static-sites/add", s.handleStaticSitesAdd)
	s.mux.HandleFunc(s.config.AdminPrefix+"/static-sites/delete", s.handleStaticSitesDelete)

	// PHP 站点管理 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites", s.handlePHPSites) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites/add", s.handlePHPSitesAdd)
	s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites/delete", s.handlePHPSitesDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites/security", s.handlePHPSecurity)
	s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites/optimization", s.handlePHPOptimization)

	// 紧急修复（忘记密码）
	s.mux.HandleFunc(s.config.AdminPrefix+"/help/recover", s.handleRecoverHelp)

	// 首次设置向导（已合并到 first-setup 中）

	// 配置导出/导入/预览/应用
	s.mux.HandleFunc(s.config.AdminPrefix+"/config/export", s.handleConfigExport)
	s.mux.HandleFunc(s.config.AdminPrefix+"/config/import", s.handleConfigImport)
	s.mux.HandleFunc(s.config.AdminPrefix+"/config/preview", s.handleConfigPreview)
	s.mux.HandleFunc(s.config.AdminPrefix+"/config/apply", s.handleConfigApply)

	// API路由
	// 认证相关 API
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/auth/login", s.handleAPIAuthLogin)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/auth/logout", s.handleAPIAuthLogout)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/auth/me", s.handleAPIAuthMe)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/auth/change-password", s.handleAPIChangePassword)

	// 用户管理 API
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/users", s.handleAPIUsers)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/users/", s.handleAPIUser)

	s.mux.HandleFunc(s.config.AdminPrefix+"/api/stats", s.handleAPIStats)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/proxy-rules", s.handleAPIProxyRules)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/proxy/rules", s.handleAPIProxyRules) // 兼容前端请求路径
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/proxy/rule", s.handleAPIProxyRule)   // 单个代理规则操作
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/proxy-rules/manage", s.handleAPIProxyRulesPost)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/proxy-rules/delete", s.handleAPIProxyRulesDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ssl-certs", s.handleAPISSLCerts)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ssl/generate", s.handleAPISSLGenerate)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ssl/retry", s.handleAPISSLRetry)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ssl/retry-config", s.handleAPISSLRetryConfig)

	// DNS API路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/dns/providers", s.handleAPIDNSProviders)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/dns/provider", s.handleAPIDNSProvidersPost)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/dns/providers/manage", s.handleAPIDNSProvidersPost)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/dns/providers/delete", s.handleAPIDNSProvidersDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/dns/validate", s.handleAPIDNSValidate)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/dns/request-cert", s.handleAPIDNSRequestCert)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/dns/config", s.handleAPIDNSConfig)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/dns/refresh", s.handleAPIDNSRefresh)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ssl/upload", s.handleAPISSLUpload)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/ssl/delete", s.handleAPISSLDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/settings", s.handleAPISettings)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/settings/update", s.handleAPISettingsUpdate)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/settings/basic", s.handleAPISettingsBasic)

	// 隧道管理 API
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tunnels/providers", s.handleAPITunnelProviders)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tunnels/providers/save", s.handleAPITunnelProvidersSave)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tunnels/providers/delete", s.handleAPITunnelProvidersDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tunnels/delete", s.handleAPITunnelDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tunnels/start", s.handleAPITunnelStart)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tunnels/stop", s.handleAPITunnelStop)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tunnels/status", s.handleAPITunnelStatus)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/security/unblock", s.handleAPISecurityUnblock)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/static-sites", s.handleAPIStaticSites)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/static-sites/delete", s.handleAPIStaticSitesDelete)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-sites", s.handleAPIPHPSites)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-sites/delete", s.handleAPIPHPSitesDelete)
	// PHP 安全功能 API
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-security/status", s.handleAPIPHPSecurityStatus)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-security/scan", s.handleAPIPHPSecurityScan)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-security/performance", s.handleAPIPHPSecurityPerformance)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-security/errors", s.handleAPIPHPSecurityErrors)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-security/config", s.handleAPIPHPSecurityConfig)
	// 高级安全功能 API
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-security/advanced-scan", s.handleAPIPHPAdvancedSecurityScan)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-security/auto-fix", s.handleAPIPHPSecurityAutoFix)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/php-security/recommendations", s.handleAPIPHPSecurityRecommendations)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/security-logs", s.handleAPISecurityLogs)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/audit", s.handleAPIAudit)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/tls-fingerprints", s.handleAPITLSFingerprints)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/security/attacks", s.handleAPISecurityAttacks)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cloud-storage/detect", s.handleAPICloudStorageDetect)

	// CDN缓存API
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cdn/stats", s.handleAPICDNStats)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cdn/objects", s.handleAPICDNObjects)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cdn/purge", s.handleAPICDNPurge)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cdn/rules", s.handleAPICDNRules)

	// 内存缓存统计API（统一的缓存管理）
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cache/stats", s.handleCacheStats)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cache/clear", s.handleCacheClear)

	// 统计API
	if s.statisticsAPI != nil {
		s.statisticsAPI.RegisterRoutes(s.mux, s.config.AdminPrefix+"/api")
	}

	// 慢请求API
	slowRequestAPI := NewSlowRequestAPI(s.slowRequestManager, s)
	slowRequestAPI.RegisterRoutes(s.mux, s.config.AdminPrefix+"/api")

	// Prometheus 指标
	s.mux.Handle("/metrics", s.prometheusMetrics.Handler())

	// 图片优化 API
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/image-optimization/config", s.handleAPIImageOptConfig)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/image-optimization/stats", s.handleAPIImageOptStats)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/image-optimization/cache/clear", s.handleAPIImageOptCacheClear)

	// 图形验证码
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/captcha/image", s.handleAPIImageCaptcha)
	// s.mux.HandleFunc(s.config.AdminPrefix+"/api/captcha", s.handleAPICaptcha) // 关闭验证码API

	// Token 管理路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/tokens", s.handleTokensPage) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/tokens/generate", s.handleTokenGeneratePage)
	s.mux.HandleFunc(s.config.AdminPrefix+"/tokens/delete", s.handleTokenDeleteAction)

	// 证书批量操作
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/download-all", s.handleSSLDownloadAll)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl/upload-all", s.handleSSLBulkUpload)

	// Runners 管理页面路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/runners", s.handleRunners) // 已迁移到前端SPA

	// Git Deploy Server 管理页面路由 - 页面路由已迁移到前端SPA
	// s.mux.HandleFunc(s.config.AdminPrefix+"/git-server", s.handleGitServer) // 已迁移到前端SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/git-server/create-app", s.handleCreateApp)
	s.mux.HandleFunc(s.config.AdminPrefix+"/git-server/server-config", s.handleServerConfig)

	// Favicon 处理（同时注册根路径和AdminPrefix路径）
	s.mux.HandleFunc("/favicon.ico", s.handleFavicon)
	s.mux.HandleFunc(s.config.AdminPrefix+"/favicon.ico", s.handleFavicon)

	// Runner API 路由
	s.registerRunnerRoutes()

	// 集群 API
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cluster/settings", s.handleAPIClusterSettings)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cluster/export-certs", s.handleAPIClusterExportCerts)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cluster/sync-certs", s.handleAPIClusterSyncCerts)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cluster/status", s.handleAPIClusterStatus)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/cluster/test-master", s.handleAPIClusterTestMaster)

	// 前端 SPA 路由 - 必须放在最后，作为 fallback
	s.setupFrontendRoutes()

	// 设置上游缓存路由
	s.setupUpstreamCacheRoutes()
}

// registerRunnerRoutes 注册 Runner API 路由
func (s *Server) registerRunnerRoutes() {
	// 创建 API 处理器，传递 webServer 引用以支持 localhost 认证豁免
	gitAPI := NewGitServerAPI(s.gitServer, s)
	runtimeAPI := NewRuntimeDetectorAPI()
	templateBase := s.config.AdminPrefix + "/api/git-server/templates"
	templateAPI := NewTemplateAPI(s.gitServer.GetTemplateManager(), templateBase)

	// Git 服务器 API 路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/apps", gitAPI.HandleApps) // GET: 列表, POST: 创建
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app", gitAPI.GetApp)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app/create", gitAPI.CreateApp) // 保留兼容性
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app/delete", gitAPI.DeleteApp)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app/env", gitAPI.UpdateAppEnv)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app/routing", gitAPI.UpdateAppRouting)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app/redeploy", gitAPI.RedeployApp)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app/reinstall-hooks", gitAPI.ReinstallHooks)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/apps/", gitAPI.HandleAppAction) // 支持 /apps/{name}/deploy 等

	// 服务器配置 API 路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/config", gitAPI.HandleServerConfig)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/config/update", gitAPI.UpdateServerConfig)

	// SSH 密钥管理 API 路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/ssh-keys", gitAPI.HandleSSHKeys)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/ssh-key/add", gitAPI.AddSSHKey)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/ssh-key/remove", gitAPI.RemoveSSHKey)

	// 推送历史和密钥绑定 API 路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/push-history", gitAPI.GetPushHistory)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app/bind-key", gitAPI.BindKeyToApp)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/app/unbind-key", gitAPI.UnbindKeyFromApp)

	// 日志查看 API 路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/logs", gitAPI.GetAppLogs)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/log-files", gitAPI.GetAppLogFiles)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/logs/stream", gitAPI.GetAppLogsStream)      // SSE
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/logs/stream-ws", gitAPI.GetAppLogsStreamWS) // WebSocket
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/logs/history", gitAPI.GetAppLogsHistory)

	// SSH 服务管理 API 路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/restart-sshd", gitAPI.RestartSSHD)

	if templateAPI != nil {
		s.mux.HandleFunc(templateBase, templateAPI.HandleTemplates)
		s.mux.HandleFunc(templateBase+"/reload", templateAPI.HandleTemplateReload)
		s.mux.HandleFunc(templateBase+"/", templateAPI.HandleTemplateDetail)
	}

	// 模板部署 API 路由
	if s.gitServer != nil && s.gitServer.GetDeployOrchestrator() != nil {
		templateDeployAPI := NewTemplateDeployAPI(s.gitServer, s.log.Logger)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/templates/deploy", templateDeployAPI.DeployFromTemplate)
		s.log.Info("模板部署 API 路由已注册")
	} else {
		s.log.Warn("GitServer 或 DeployOrchestrator 未启用，模板部署 API 路由未注册")
	}

	// 域名管理 API 路由
	if s.gitServer != nil {
		domainAPI := NewDomainAPI(s.gitServer, s.log.Logger)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/domains/add", domainAPI.AddDomain)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/domains/remove", domainAPI.RemoveDomain)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/domains", domainAPI.GetDomains)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/domains/verify-dns", domainAPI.VerifyDNS)
		s.log.Info("域名管理 API 路由已注册")
	}

	// 服务管理 API 路由
	if s.gitServer != nil {
		serviceAPI := NewServiceAPI(s.gitServer, s.log.Logger)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/services/status", serviceAPI.GetServiceStatus)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/services/restart", serviceAPI.RestartService)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/services/stop", serviceAPI.StopService)
		s.log.Info("服务管理 API 路由已注册")
	}

	// 凭证管理 API 路由
	if s.gitServer != nil {
		credentialAPI := NewCredentialAPI(s.gitServer, s.log.Logger)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/credentials", credentialAPI.GetCredentials)
		s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/credentials/regenerate", credentialAPI.RegenerateCredential)
		s.log.Info("凭证管理 API 路由已注册")
	}

	// Docker Registry API 路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/docker/images", gitAPI.GetDockerImages)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/docker/config", gitAPI.GetDockerConfig)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/docker/config/update", gitAPI.UpdateDockerConfig)
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/docker/test", gitAPI.TestDockerConnection)

	// 部署通知 API 路由（内部使用，由 Git hooks 调用）
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/internal/deploy-notification", gitAPI.HandleDeployNotification)

	// 运行时检测 API 路由
	s.mux.HandleFunc(s.config.AdminPrefix+"/api/runtime-detector/detect", runtimeAPI.DetectProject)
}

// ServeHTTP 实现http.Handler接口
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 记录请求开始时间（用于计算请求耗时）
	startTime := time.Now()

	// 根据转发规则决定是否启用追踪（减少 CPU 占用）
	var span *tracing.Span
	var ctx context.Context
	var enableTracing bool
	var enableMetrics bool

	// 查找匹配的转发规则
	matchedRule := s.findMatchingProxyRule(r)
	if matchedRule != nil {
		enableTracing = matchedRule.EnableTracing
		enableMetrics = matchedRule.EnableMetrics
	}

	if enableTracing {
		span, ctx = s.tracer.StartSpanFromHTTPRequest(r)
		r = r.WithContext(ctx)
		// 将追踪信息注入响应头
		span.InjectHTTPHeaders(w.Header())
	}

	// 包装 ResponseWriter 以捕获状态码和字节数（使用 statistics.go 中的类型）
	wrappedWriter := &responseWriter{
		ResponseWriter: w,
		statusCode:     200,
		written:        0,
	}

	// defer 记录访问日志、完成追踪、记录Prometheus指标（增强版：慢查询日志）
	defer func() {
		duration := time.Since(startTime)

		// 慢查询检测：超过5秒的请求
		if duration > 5*time.Second {
			s.log.Warnf("HTTP慢查询: method=%s, path=%s, duration=%v, status=%d, client=%s",
				r.Method, r.URL.Path, duration, wrappedWriter.statusCode, s.getClientIP(r))
		}

		// 根据转发规则完成追踪 Span（减少 CPU 占用）
		if enableTracing && span != nil {
			span.SetTag("http.status_code", fmt.Sprintf("%d", wrappedWriter.statusCode))
			span.SetTag("http.response_size", fmt.Sprintf("%d", wrappedWriter.written))
			if wrappedWriter.statusCode >= 400 {
				span.Success = false
				span.ErrorMessage = fmt.Sprintf("HTTP %d", wrappedWriter.statusCode)
			}
			span.Finish()
		}

		// 根据转发规则记录 Prometheus 指标（减少 CPU 占用）
		if enableMetrics {
			domain := r.Host
			if !strings.HasPrefix(r.URL.Path, s.config.AdminPrefix) {
				s.prometheusMetrics.RecordHTTPRequest(
					domain,
					r.Method,
					fmt.Sprintf("%d", wrappedWriter.statusCode),
					duration,
					wrappedWriter.written,
				)
			}
		}

		// 记录访问日志（保持现有功能）
		if s.accessLogger != nil {
			s.accessLogger.LogRequest(r, wrappedWriter.statusCode, wrappedWriter.written,
				duration, "", 0)
		}

		// 记录性能监控数据（如果监控系统启用）
		if s.monitorManager != nil {
			perfMonitor := s.monitorManager.GetPerformanceMonitor()
			isError := wrappedWriter.statusCode >= 400
			perfMonitor.RecordRequest(duration, isError)
		}
	}()

	// 只在调试模式下记录详细日志
	if s.config.Server.Debug {
		s.log.Debugf("=== ServeHTTP: %s %s from %s ===", r.Method, r.URL.Path, s.getClientIP(r))
	}
	// 若通过IP访问且存在可用的LE域名，强制跳转到 https://域名 + AdminPrefix（仅限管理面板路径或根）
	// 但排除 localhost/127.0.0.1，这些用于内部 API 调用
	host := r.Host
	hostOnly := host
	if idx := strings.Index(host, ":"); idx != -1 {
		hostOnly = host[:idx]
	}
	if net.ParseIP(hostOnly) != nil {
		// 检查是否为 localhost/127.0.0.1，这些不应该重定向
		isLocalhost := hostOnly == "127.0.0.1" || hostOnly == "::1" || hostOnly == "localhost"

		// 仅当访问管理面板路径时才重定向（但排除 localhost）
		if !isLocalhost && s.leRedirectHost != "" && strings.HasPrefix(r.URL.Path, s.config.AdminPrefix) {
			target := "https://" + s.leRedirectHost + r.RequestURI
			http.Redirect(wrappedWriter, r, target, http.StatusMovedPermanently)
			return
		}
	}

	// 语言切换：如果存在 ?lang= 参数，则设置 cookie 并重定向到去掉 lang 的同一路径
	if langParam := r.URL.Query().Get("lang"); langParam != "" {
		if s.isSupportedLanguage(langParam) {
			// 设置语言 cookie（180 天）
			http.SetCookie(wrappedWriter, &http.Cookie{
				Name:     "language",
				Value:    langParam,
				Path:     "/",
				MaxAge:   180 * 24 * 3600,
				HttpOnly: false,
				Secure:   r.TLS != nil,
			})
			// 立即切换当前会话语言
			s.translator.SetLanguage(i18n.SupportedLanguage(langParam))
			// 构造重定向URL（去掉 lang 参数）
			q := r.URL.Query()
			q.Del("lang")
			r.URL.RawQuery = q.Encode()
			http.Redirect(wrappedWriter, r, r.URL.String(), http.StatusFound)
			return
		}
	}

	// 安全中间件
	if !s.securityMiddleware(wrappedWriter, r) {
		return
	}

	// WAF 检测（开启时才生效）
	if s.config.Security.EnableWAF && s.wafEngine != nil {
		if events, blocked := s.wafEngine.CheckRequestAdvanced(r); blocked {
			s.log.Warnf("WAF blocked request from %s: %d events detected", s.getClientIP(r), len(events))
			http.Error(wrappedWriter, "Request blocked by WAF", http.StatusForbidden)
			return
		} else if len(events) > 0 {
			s.log.Infof("WAF detected %d security events from %s", len(events), s.getClientIP(r))
		}
	}

	// DDoS 防护检测（开启时才生效，但跳过管理面板登录）
	if s.config.Security.EnableDDOS && s.ddosProtector != nil && !strings.HasPrefix(r.URL.Path, s.config.AdminPrefix+"/login") {
		if blocked, reason := s.ddosProtector.CheckRequest(r); blocked {
			s.log.Warnf("DDoS protection blocked request from %s: %s", s.getClientIP(r), reason)
			http.Error(wrappedWriter, "Request blocked by DDoS protection", http.StatusTooManyRequests)
			return
		}
	}

	// 代理中间件
	if s.proxyMiddleware(wrappedWriter, r) {
		return
	}

	// 处理请求
	s.log.Debugf("Routing to mux for: %s %s", r.Method, r.URL.Path)

	// 应用统计中间件
	if s.statisticsAPI != nil {
		handler := s.statisticsAPI.RecordMiddleware(s.mux)
		handler.ServeHTTP(wrappedWriter, r)
	} else {
		s.mux.ServeHTTP(wrappedWriter, r)
	}
}

func (s *Server) isSupportedLanguage(lang string) bool {
	langs := s.translator.GetSupportedLanguages()
	if _, ok := langs[i18n.SupportedLanguage(lang)]; ok {
		return true
	}
	return false
}

// ProxyRequestWithAuth 带访问控制的代理请求处理
func (s *Server) ProxyRequestWithAuth(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 如果未开启认证，直接代理
	if !rule.AuthEnabled {
		s.proxyManager.ProxyRequest(w, r, rule)
		return
	}

	// 检查是否已通过认证
	if s.proxyAuthManager.CheckAuth(r, rule) {
		s.proxyManager.ProxyRequest(w, r, rule)
		return
	}

	// 处理登录请求
	if s.proxyAuthManager.ProcessLogin(w, r, rule) {
		return
	}

	// 显示登录页面
	s.proxyAuthManager.ShowLoginPage(w, r, rule, "")
}

// securityMiddleware 安全中间件
func (s *Server) securityMiddleware(w http.ResponseWriter, r *http.Request) bool {
	// 获取客户端信息
	clientIP := s.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	path := r.URL.Path

	// 检查是否被封禁
	if s.securityManager.IsBlocked(clientIP) {
		s.log.Warnf("Blocked IP attempted to access: %s", clientIP)
		http.Error(w, "IP address blocked", http.StatusForbidden)
		return false
	}

	// 检查User-Agent（localhost 请求豁免）
	// 使用 isLocalhostRequest 来确保无法通过伪造 HTTP 头部绕过检查
	if strings.HasPrefix(path, s.config.AdminPrefix) && !s.isLocalhostRequest(r) && (userAgent == "" || s.isCommonBotUserAgent(userAgent)) {
		s.log.Warnf("Suspicious User-Agent attempted to access admin panel: %s from %s", userAgent, clientIP)
		s.securityManager.LogAccess(clientIP, userAgent, path, false)
		http.Error(w, "Access denied", http.StatusForbidden)
		return false
	}

	// 记录访问日志
	s.securityManager.LogAccess(clientIP, userAgent, path, true)

	return true
}

// hasValidCertificate 检查域名是否有有效的非自签名证书
func (s *Server) hasValidCertificate(domain string) bool {
	// 尝试获取证书
	cert, err := s.sslManager.GetCertificate(domain)
	if err != nil || cert == nil || len(cert.Certificate) == 0 {
		return false
	}

	// 解析证书
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// 检查证书是否过期
	if time.Now().After(x509Cert.NotAfter) {
		return false
	}

	// 检查是否为自签名证书（自签名证书不应该强制HTTPS）
	isSelfSigned := x509Cert.Issuer.String() == x509Cert.Subject.String()

	// 如果是自签名证书，认为没有有效证书
	if isSelfSigned {
		return false
	}

	// 检查是否包含该域名
	if !s.domainMatchesCert(domain, x509Cert) {
		return false
	}

	return true
}

// domainMatchesCert 检查域名是否匹配证书
func (s *Server) domainMatchesCert(domain string, cert *x509.Certificate) bool {
	// 检查Subject Common Name
	if cert.Subject.CommonName == domain {
		return true
	}

	// 检查SAN（Subject Alternative Names）
	for _, san := range cert.DNSNames {
		if san == domain {
			return true
		}
		// 支持通配符匹配
		if strings.HasPrefix(san, "*.") {
			wildcardDomain := san[2:] // 去掉 "*."
			if strings.HasSuffix(domain, "."+wildcardDomain) || domain == wildcardDomain {
				return true
			}
		}
	}

	return false
}

// proxyMiddleware 代理中间件
func (s *Server) proxyMiddleware(w http.ResponseWriter, r *http.Request) bool {
	// 如果是管理面板路径，跳过代理
	if strings.HasPrefix(r.URL.Path, s.config.AdminPrefix) {
		return false
	}

	// 如果是调试路径，跳过代理
	if strings.HasPrefix(r.URL.Path, "/debug/") {
		return false
	}

	// 若命中 PHP 站点，则先交给 PHP 处理
	if s.tryServePHP(w, r) {
		return true
	}

	// 若匹配静态站点，则直接本地文件服务
	if s.serveStatic(w, r) {
		return true
	}

	// 获取域名
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// 查找代理配置
	rule := s.proxyManager.GetProxyConfig(host)
	if rule != nil && rule.Enabled {
		// 检查路径前缀匹配
		if !rule.MatchesPath(r.URL.Path) {
			s.log.Debugf("Request path %s does not match any prefix for domain %s", r.URL.Path, host)
			// 路径不匹配，继续查找其他规则或处理未匹配行为
		} else {
			s.log.Debugf("Request path %s matches prefix for domain %s", r.URL.Path, host)

			// 若仅允许HTTPS且当前为HTTP，需要检查是否有有效证书
			if rule.SSLOnly && r.TLS == nil {
				// 检查是否为本地IP或localhost，这些不需要强制HTTPS
				if net.ParseIP(host) != nil || host == "localhost" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "::1") {
					s.log.Debugf("SSL-only rule ignored for local IP/hostname: %s", host)
				} else {
					// 检查是否有有效的非自签名证书
					if s.hasValidCertificate(host) {
						target := "https://" + host + r.URL.RequestURI()
						s.log.Warnf("SSL-only rule, redirecting http->https for host=%s", host)
						http.Redirect(w, r, target, http.StatusMovedPermanently)
						return true
					} else {
						s.log.Debugf("SSL-only rule ignored for %s: no valid certificate found", host)
					}
				}
			}
			// 执行代理（带访问控制）
			s.ProxyRequestWithAuth(w, r, rule)
			return true
		}
	}

	// 没有找到（或规则未启用）代理配置，依据配置项处理
	switch s.config.Proxy.UnmatchedBehavior {
	case "302":
		target := s.config.Proxy.UnmatchedRedirectURL
		if target == "" {
			target = "https://sslcat.com"
		}
		s.log.Warnf("Unmatched proxy for host=%s path=%s, redirecting to %s", host, r.URL.Path, target)
		http.Redirect(w, r, target, http.StatusFound)
	case "blank":
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning blank", host, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	case "404":
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning 404", host, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 Not Found\n"))
		return true
	default: // "502"
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning 502", host, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("502 Bad Gateway\n\nPowered by sslcat-" + s.version + "\n"))
	}
	return true
}

// 工具函数

func (s *Server) getClientIP(r *http.Request) string {
	// 首先获取真实的连接来源 IP（RemoteAddr）
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	// 安全检查：只有当请求真的来自本地或可信代理时，才信任 HTTP 头部
	// 这样可以防止攻击者伪造 X-Real-IP 或 X-Forwarded-For 来绕过 localhost 检查
	isTrustedSource := s.isPrivateIP(remoteIP) || remoteIP == "127.0.0.1" || remoteIP == "::1"

	// 只有来自可信来源的请求才检查代理头部
	if isTrustedSource {
		// 优先检查Cloudflare头（但必须不是 localhost）
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			cfIP = strings.TrimSpace(cfIP)
			// 拒绝将 localhost 作为客户端 IP，防止绕过认证
			if !s.isLocalhostIP(cfIP) {
				return cfIP
			}
		}

		// 检查X-Real-IP（但必须不是 localhost）
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			realIP = strings.TrimSpace(realIP)
			// 拒绝将 localhost 作为客户端 IP，防止绕过认证
			if !s.isLocalhostIP(realIP) {
				return realIP
			}
		}

		// 检查X-Forwarded-For（但必须不是 localhost 或私有IP）
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				ip := strings.TrimSpace(ips[0])
				// 只返回非私有、非 localhost 的 IP
				if !s.isPrivateIP(ip) && !s.isLocalhostIP(ip) {
					return ip
				}
			}
		}
	}

	// 使用真实的 RemoteAddr
	return remoteIP
}

func (s *Server) isPrivateIP(ip string) bool {
	// 简单检查私有IP段
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "127.") ||
		ip == "::1"
}

// isLocalhostIP 检查 IP 是否为 localhost
// 用于防止攻击者伪造 HTTP 头部绕过认证
func (s *Server) isLocalhostIP(ip string) bool {
	return ip == "127.0.0.1" ||
		ip == "::1" ||
		strings.HasPrefix(ip, "127.") ||
		ip == "localhost"
}

// isLocalhostRequest 检查请求是否来自 localhost
// 用于内部 API 调用（如 sslcat-git-hook）的认证豁免
//
// 安全说明：
// 为了防止攻击者通过伪造 HTTP 头部（如 X-Real-IP: 127.0.0.1）绕过认证，
// 我们使用 RemoteAddr（TCP 连接的真实来源）来判断，而不是 getClientIP()
func (s *Server) isLocalhostRequest(r *http.Request) bool {
	// 使用 RemoteAddr 获取真实的 TCP 连接来源
	// 这个值无法通过 HTTP 头部伪造
	remoteAddr := r.RemoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		remoteAddr = remoteAddr[:idx]
	}

	// 检查是否是 localhost
	// 支持 IPv4 的 127.0.0.1 和 IPv6 的 ::1
	if remoteAddr == "127.0.0.1" ||
		remoteAddr == "::1" ||
		strings.HasPrefix(remoteAddr, "127.") {
		return true
	}

	return false
}

func (s *Server) isCommonBotUserAgent(ua string) bool {
	botUAs := []string{
		"bot", "crawler", "spider", "scraper", "curl", "wget",
	}
	uaLower := strings.ToLower(ua)
	for _, bot := range botUAs {
		if strings.Contains(uaLower, bot) {
			return true
		}
	}
	return false
}

func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	// 使用新的会话管理器检查认证
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		http.Redirect(w, r, s.config.AdminPrefix+"/login", http.StatusFound)
		return false
	}

	// 异步记录用户访问日志，避免阻塞响应
	go s.userManager.LogUserAction(
		session.Username,
		"page_access",
		r.URL.Path,
		fmt.Sprintf("访问页面: %s", r.URL.Path),
		s.getClientIP(r),
		r.Header.Get("User-Agent"),
	)

	return true
}

// getCurrentUser 获取当前登录用户信息
func (s *Server) getCurrentUser(r *http.Request) *User {
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		return nil
	}

	// 首先尝试从数据库获取用户信息
	user, err := s.userManager.GetUserByUsername(session.Username)
	if err == nil {
		return user
	}

	// 如果数据库中没有用户，检查是否是配置文件中的管理员
	if session.Username == s.config.Admin.Username {
		// 返回配置文件中的管理员用户信息
		return &User{
			Username: session.Username,
			Role:     session.Role, // 使用会话中存储的角色
			IsActive: true,
		}
	}

	s.log.Warnf("获取用户信息失败: %v", err)
	return nil
}

func (s *Server) getSystemStats() map[string]interface{} {
	proxyStats := s.proxyManager.GetProxyStats()
	uptime := time.Since(s.startTime)

	// 安全获取 proxyStats 中的值，避免类型错误或 nil 值
	getInt64 := func(key string, defaultValue int64) int64 {
		if v, ok := proxyStats[key]; ok {
			if val, ok := v.(int64); ok {
				return val
			}
			if val, ok := v.(int); ok {
				return int64(val)
			}
		}
		return defaultValue
	}

	getFloat64 := func(key string, defaultValue float64) float64 {
		if v, ok := proxyStats[key]; ok {
			if val, ok := v.(float64); ok {
				return val
			}
			if val, ok := v.(int); ok {
				return float64(val)
			}
			if val, ok := v.(int64); ok {
				return float64(val)
			}
		}
		return defaultValue
	}

	// 安全获取 publicIP，避免 DNS 解析异常导致程序崩溃
	var publicIP string
	func() {
		defer func() {
			if r := recover(); r != nil {
				s.log.Warnf("获取公网IP时发生异常: %v", r)
				publicIP = ""
			}
		}()
		publicIP = s.fetchPublicIPv4()
	}()

	totalRequests := getInt64("total_requests", 0)
	if totalRequests == 0 {
		totalRequests = getInt64("cached_proxies", 0)
	}

	return map[string]interface{}{
		// 前端期望的字段名（小写开头）
		"activeRules":   len(s.config.Proxy.Rules),
		"cachedProxies": totalRequests,
		"publicIP":      publicIP,
		"goVersion":     runtime.Version(),
		"version":       s.version, // 添加应用版本

		// 保持向后兼容的大写字段
		"ActiveRules":     len(s.config.Proxy.Rules),
		"CachedProxies":   getInt64("cached_proxies", 0),
		"TotalRequests":   totalRequests,
		"ErrorRate":       getFloat64("error_rate", 0),
		"QPS":             getFloat64("qps", 0),
		"AvgResponseTime": getFloat64("avg_response_time", 0),
		"Uptime":          int64(uptime.Seconds()),
		"UptimeString":    s.formatDuration(uptime),
		"SSLCertificates": len(s.sslManager.GetCertificateList()),
		"BlockedIPs":      len(s.securityManager.GetBlockedIPs()),
		"PublicIP":        publicIP,
		"Version":         s.version, // 向后兼容的大写版本
	}
}

func (s *Server) formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%d小时%d分钟", hours, minutes)
	} else if minutes > 0 {
		return fmt.Sprintf("%d分钟%d秒", minutes, seconds)
	} else {
		return fmt.Sprintf("%d秒", seconds)
	}
}

// 简单审计：写入 data/audit.log 为 JSON Lines
func (s *Server) audit(action, detail string) {
	t := time.Now().Format(time.RFC3339)
	rec := map[string]string{"time": t, "user": s.config.Admin.Username, "action": action, "detail": detail}
	b, _ := json.Marshal(rec)
	_ = os.MkdirAll("./data", 0755)
	// 使用轮转写入器（若可用）
	if s.auditRotator != nil {
		_, _ = s.auditRotator.Write(append(b, '\n'))
	} else {
		f, err := os.OpenFile("./data/audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer f.Close()
			f.Write(append(b, '\n'))
		}
	}
	if s.notifier != nil && s.notifier.Enabled() {
		m := map[string]any{"ts": t, "level": "info", "action": action, "detail": detail}
		s.notifier.SendJSON(m)
	}
}

// 保留扩展点：若未来需要根路径也跳转，可在此扩展

// 每31秒刷新一次首选LE域名（证书有效且解析到本机公网IP）
func (s *Server) refreshLEPreferredHostLoop() {
	ticker := time.NewTicker(31 * time.Second) // 使用质数间隔避免与其他定时器同时触发
	defer ticker.Stop()
	for range ticker.C {
		// 添加 panic 恢复，避免整个循环崩溃
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Errorf("refreshLEPreferredHost 发生 panic: %v", r)
				}
			}()
			s.refreshLEPreferredHost()
		}()
	}
}

func (s *Server) refreshLEPreferredHost() {
	if s.sslManager == nil {
		s.leRedirectHost = ""
		return
	}
	domain := s.sslManager.GetFirstValidLEDomain()
	if domain == "" {
		s.leRedirectHost = ""
		return
	}
	// 查询公网IP
	publicIP := s.fetchPublicIPv4()
	if publicIP == "" {
		// 获取不到公网IP，允许IP访问
		s.leRedirectHost = ""
		return
	}
	// DNS 解析 domain 并检查是否包含本机公网IP
	// 使用带超时的 DNS 解析，避免 CGO 异常
	ips, err := func() ([]net.IP, error) {
		type result struct {
			ips []net.IP
			err error
		}
		ch := make(chan result, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Warnf("DNS 解析时发生异常: %v", r)
					ch <- result{nil, fmt.Errorf("DNS 解析异常: %v", r)}
				}
			}()
			ips, err := net.LookupIP(domain)
			ch <- result{ips, err}
		}()

		select {
		case res := <-ch:
			return res.ips, res.err
		case <-time.After(2 * time.Second):
			return nil, fmt.Errorf("DNS 解析超时")
		}
	}()

	if err != nil {
		s.log.Warnf("DNS 解析失败: %v", err)
		s.leRedirectHost = ""
		return
	}
	for _, ip := range ips {
		if ip.To4() != nil && ip.String() == publicIP {
			s.leRedirectHost = domain
			return
		}
	}
	s.leRedirectHost = ""
}

func (s *Server) fetchPublicIPv4() string {
	// 使用更短的超时时间，避免阻塞
	client := &http.Client{
		Timeout: 2 * time.Second,
		// 禁用 DNS 缓存，避免潜在的 CGO 问题
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   1 * time.Second,
				KeepAlive: 0,
			}).DialContext,
		},
	}

	req, err := http.NewRequest("GET", "https://ip4.dev/myip", nil)
	if err != nil {
		return ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// handleFavicon 处理 favicon.ico 请求
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	// 返回一个简单的 16x16 像素的透明 PNG favicon
	favicon := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF,
		0x61, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
		0x42, 0x60, 0x82,
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400") // 缓存1天
	w.Write(favicon)
}

// findMatchingProxyRule 查找匹配的转发规则
func (s *Server) findMatchingProxyRule(r *http.Request) *config.ProxyRule {
	host := r.Host
	path := r.URL.Path

	// 移除端口号
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// 查找匹配的规则
	for i := range s.config.Proxy.Rules {
		rule := &s.config.Proxy.Rules[i]
		if !rule.Enabled {
			continue
		}

		// 域名匹配
		if rule.Domain != host {
			continue
		}

		// 路径前缀匹配
		if len(rule.PathPrefixes) > 0 {
			matched := false
			for _, prefix := range rule.PathPrefixes {
				if rule.PathExact {
					if path == prefix {
						matched = true
						break
					}
				} else {
					if strings.HasPrefix(path, prefix) {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
		}

		// 路径前缀规则匹配
		if len(rule.PathPrefixRules) > 0 {
			matched := false
			for _, pathRule := range rule.PathPrefixRules {
				if !pathRule.Enabled {
					continue
				}
				for _, prefix := range pathRule.Prefixes {
					if pathRule.Exact {
						if path == prefix {
							matched = true
							break
						}
					} else {
						if strings.HasPrefix(path, prefix) {
							matched = true
							break
						}
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
		}

		// 找到匹配的规则
		return rule
	}

	return nil
}

func (s *Server) updateSharedCache(sizeMB int) {
	if sizeMB < 8 {
		sizeMB = 8
	}
	maxBytes := int64(sizeMB) * 1024 * 1024

	s.log.Infof("更新共享缓存容量为 %d MB", sizeMB)

	newCache := cache.NewMemoryCache(&cache.MemoryCacheConfig{
		Name:            "shared_cache",
		MaxEntries:      400,
		MaxSizeBytes:    maxBytes,
		MaxItemSize:     2 * 1024 * 1024,
		DefaultTTL:      24 * time.Hour,
		CleanupInterval: 5 * time.Minute,
	})

	oldCache := s.sharedCache
	s.sharedCache = newCache

	if s.compressionCache != nil {
		s.compressionCache.SetMemoryCache(newCache)
	}

	if s.imageOptimizer != nil {
		s.imageOptimizer.SetMemoryCache(newCache)
	}

	if oldCache != nil && oldCache != newCache {
		oldCache.Close()
	}
}

func (s *Server) updateMemoryMonitor(maxUsagePercent float64, cooldownSec int) {
	if s.monitorManager == nil {
		return
	}
	if maxUsagePercent < 5 {
		maxUsagePercent = 5
	}
	if maxUsagePercent > 90 {
		maxUsagePercent = 90
	}
	if cooldownSec < 60 {
		cooldownSec = 60
	}
	opts := monitor.MemoryMonitorOptions{
		CheckInterval:       time.Minute,
		MaxSystemUsageRatio: maxUsagePercent / 100.0,
		ReleaseCooldown:     time.Duration(cooldownSec) * time.Second,
	}
	s.monitorManager.UpdateMemoryMonitorOptions(opts)
}
