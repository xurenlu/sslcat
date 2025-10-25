package security

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/logger"

	"github.com/sirupsen/logrus"
)

type TLSFPStat struct {
	FP    string `json:"fp"`
	Count int    `json:"count"`
}

// AccessLog 访问日志记录
type AccessLog struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
	Success   bool      `json:"success"`
}

// BlockedIP 被封禁的IP信息
type BlockedIP struct {
	IP         string    `json:"ip"`
	Reason     string    `json:"reason"`
	BlockTime  time.Time `json:"block_time"`
	ExpireTime time.Time `json:"expire_time"`
}

// Manager 安全管理器
type Manager struct {
	config        *config.Config
	accessLogs    map[string][]AccessLog
	blockedIPs    map[string]BlockedIP
	attemptCounts map[string]int
	lastAttempts  map[string][]time.Time
	// UA 违规计数：按IP维度记录
	uaInvalid1Min map[string][]time.Time
	uaInvalid5Min map[string][]time.Time
	// TLS 指纹计数
	tlsFPCounts map[string][]time.Time
	mutex       sync.RWMutex
	log         *logrus.Entry
	stopChan    chan struct{}
	// TLS 指纹持久化
	tlsFPRotator *logger.Rotator
	geoIPService *GeoIPService
	corsMiddleware *CORSMiddleware

	// 内存泄漏防护
	maxAccessLogEntries int // 每个IP的访问日志最多保留多少条
	maxBlockedIPs       int // 最多保留多少个被封禁的IP
	maxAttemptCounts    int // 最多保留多少个IP的尝试计数
	maxLastAttempts     int // 最多保留多少个IP的最后尝试时间
	maxUAInvalidEntries int // 最多保留多少个IP的UA违规记录
	maxTLSFPEntries     int // 最多保留多少个TLS指纹计数
	cleanupInterval     time.Duration // 清理间隔
}

// NewManager 创建安全管理器
func NewManager(cfg *config.Config) *Manager {
	// 初始化CORS中间件
	corsConfig := CORSConfig{
		Enabled:             cfg.Security.CORS.Enabled,
		AllowedOrigins:      cfg.Security.CORS.AllowedOrigins,
		AllowedMethods:      cfg.Security.CORS.AllowedMethods,
		AllowedHeaders:      cfg.Security.CORS.AllowedHeaders,
		ExposedHeaders:      cfg.Security.CORS.ExposedHeaders,
		AllowCredentials:    cfg.Security.CORS.AllowCredentials,
		MaxAge:              cfg.Security.CORS.MaxAge,
		AllowPrivateNetwork: cfg.Security.CORS.AllowPrivateNetwork,
	}
	corsMiddleware := NewCORSMiddleware(corsConfig)

	// 初始化地理位置IP服务
	geoIPService, err := NewGeoIPService(cfg.Security.GeoBlocking)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"component": "security_manager",
		}).Errorf("Failed to initialize GeoIP service: %v", err)
		// 创建一个禁用的服务实例，避免nil指针
		geoIPService, _ = NewGeoIPService(config.GeoBlockingConfig{
			Enabled: false,
		})
	}

	return &Manager{
		config:         cfg,
		accessLogs:     make(map[string][]AccessLog),
		blockedIPs:     make(map[string]BlockedIP),
		attemptCounts:  make(map[string]int),
		lastAttempts:   make(map[string][]time.Time),
		uaInvalid1Min:  make(map[string][]time.Time),
		uaInvalid5Min:  make(map[string][]time.Time),
		tlsFPCounts:    make(map[string][]time.Time),
		stopChan:       make(chan struct{}),
		geoIPService:   geoIPService,
		corsMiddleware: corsMiddleware,
		log: logrus.WithFields(logrus.Fields{
			"component": "security_manager",
		}),
		// 内存泄漏防护初始化
		maxAccessLogEntries: cfg.Security.MaxAccessLogEntries, 
		maxBlockedIPs:       cfg.Security.MaxBlockedIPs,
		maxAttemptCounts:    cfg.Security.MaxAttemptCounts,
		maxLastAttempts:     cfg.Security.MaxLastAttempts,
		maxUAInvalidEntries: cfg.Security.UAInvalidMaxTotal,
		maxTLSFPEntries:     cfg.Security.TLSFingerprintMaxTotal,
		cleanupInterval:     time.Duration(cfg.Security.CleanupIntervalMin) * time.Minute,
	}
}

// Start 启动安全管理器
func (m *Manager) Start() {
	m.log.Info("Starting security manager")

	// 加载被封禁的IP列表
	m.loadBlockedIPs()

	// 启动清理任务
	go m.cleanupTask()

	// 初始化 TLS 指纹日志轮转器（10MB*10）
	if rot, err := logger.NewRotator("./data/tls_fp.log", 10*1024*1024, 10); err == nil {
		m.tlsFPRotator = rot
	}
}

// Stop 停止安全管理器
func (m *Manager) Stop() {
	m.log.Info("Stopping security manager")
	close(m.stopChan)
	if m.tlsFPRotator != nil {
		_ = m.tlsFPRotator.Close()
	}
	if m.geoIPService != nil {
		_ = m.geoIPService.Close()
	}
}

// AccessLogsSnapshot 返回当前访问日志的只读快照（深拷贝切片，避免并发问题）
func (m *Manager) AccessLogsSnapshot() map[string][]AccessLog {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	out := make(map[string][]AccessLog, len(m.accessLogs))
	for ip, logs := range m.accessLogs {
		cp := make([]AccessLog, len(logs))
		copy(cp, logs)
		out[ip] = cp
	}
	return out
}

// IsBlocked 检查IP是否被封禁
func (m *Manager) IsBlocked(ip string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	blocked, exists := m.blockedIPs[ip]
	if !exists {
		return false
	}

	// 检查是否已过期
	if time.Now().After(blocked.ExpireTime) {
		delete(m.blockedIPs, ip)
		return false
	}

	return true
}

// LogAccess 记录访问日志
func (m *Manager) LogAccess(ip, userAgent, path string, success bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 检查User-Agent是否合法
	if m.config.Security.EnableUAFilter && !m.isValidUserAgent(userAgent) {
		m.log.Warnf("Suspicious User-Agent: %s from %s", userAgent, ip)
		now := time.Now()
		// 记录1分钟/5分钟窗口内的无效UA
		m.uaInvalid1Min[ip] = append(m.uaInvalid1Min[ip], now)
		m.uaInvalid5Min[ip] = append(m.uaInvalid5Min[ip], now)
		// 清理窗口外
		cut1 := now.Add(-1 * time.Minute)
		cut5 := now.Add(-5 * time.Minute)
		pruned1 := m.uaInvalid1Min[ip][:0]
		for _, t := range m.uaInvalid1Min[ip] {
			if t.After(cut1) {
				pruned1 = append(pruned1, t)
			}
		}
		m.uaInvalid1Min[ip] = pruned1
		pruned5 := m.uaInvalid5Min[ip][:0]
		for _, t := range m.uaInvalid5Min[ip] {
			if t.After(cut5) {
				pruned5 = append(pruned5, t)
			}
		}
		m.uaInvalid5Min[ip] = pruned5

		// 阈值（配置可调，未配置则使用默认）
		max1 := m.config.Security.UAInvalidMax1Min
		if max1 <= 0 {
			max1 = 30
		}
		max5 := m.config.Security.UAInvalidMax5Min
		if max5 <= 0 {
			max5 = 100
		}
		if len(m.uaInvalid1Min[ip]) >= max1 || len(m.uaInvalid5Min[ip]) >= max5 {
			m.blockIP(ip, fmt.Sprintf("Too many invalid UA: %d in 1min, %d in 5min", len(m.uaInvalid1Min[ip]), len(m.uaInvalid5Min[ip])))
			delete(m.uaInvalid1Min, ip)
			delete(m.uaInvalid5Min, ip)
		}
		return
	}

	// 记录访问日志
	accessLog := AccessLog{
		IP:        ip,
		UserAgent: userAgent,
		Path:      path,
		Timestamp: time.Now(),
		Success:   success,
	}

	m.accessLogs[ip] = append(m.accessLogs[ip], accessLog)

	// 限制日志数量（放宽）：只保留最近3000条
	if len(m.accessLogs[ip]) > 3000 {
		m.accessLogs[ip] = m.accessLogs[ip][len(m.accessLogs[ip])-3000:]
	}

	// 如果不是成功访问，检查是否需要封禁
	if !success {
		m.checkAndBlock(ip)
	}
}

// LogTLSFingerprint 记录 TLS 指纹（单位时间窗口）
func (m *Manager) LogTLSFingerprint(fingerprint, ip string) {
	if fingerprint == "" {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	now := time.Now()
	arr := append(m.tlsFPCounts[fingerprint], now)
	// 清理窗口外
	window := time.Duration(m.config.Security.TLSFingerprintWindowSec) * time.Second
	if window <= 0 {
		window = time.Minute
	}
	cut := now.Add(-window)
	pruned := arr[:0]
	for _, t := range arr {
		if t.After(cut) {
			pruned = append(pruned, t)
		}
	}
	m.tlsFPCounts[fingerprint] = pruned
	// 阈值告警
	maxPerMin := m.config.Security.TLSFingerprintMaxPerMin
	if maxPerMin <= 0 {
		maxPerMin = 6000
	}
	if len(pruned) > maxPerMin {
		m.log.Warnf("TLS fingerprint too active fp=%s count=%d ip=%s", fingerprint, len(pruned), ip)
	}

	// 追加写入 JSON Lines（轮转器优先）
	rec := map[string]any{
		"time": time.Now().Format(time.RFC3339),
		"fp":   fingerprint,
		"ip":   ip,
	}
	if b, err := json.Marshal(rec); err == nil {
		if m.tlsFPRotator != nil {
			_, _ = m.tlsFPRotator.Write(append(b, '\n'))
		} else {
			_ = os.MkdirAll("./data", 0755)
			if f, err := os.OpenFile("./data/tls_fp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				_, _ = f.Write(append(b, '\n'))
				_ = f.Close()
			}
		}
	}
}

// GetTLSFingerprintStats 返回最近窗口内的指纹计数（按降序）
func (m *Manager) GetTLSFingerprintStats() []TLSFPStat {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	now := time.Now()
	window := time.Duration(m.config.Security.TLSFingerprintWindowSec) * time.Second
	if window <= 0 {
		window = time.Minute
	}
	cut := now.Add(-window)
	tmp := make([]TLSFPStat, 0, len(m.tlsFPCounts))
	for fp, times := range m.tlsFPCounts {
		cnt := 0
		for _, t := range times {
			if t.After(cut) {
				cnt++
			}
		}
		if cnt > 0 {
			tmp = append(tmp, TLSFPStat{FP: fp, Count: cnt})
		}
	}
	sort.Slice(tmp, func(i, j int) bool { return tmp[i].Count > tmp[j].Count })
	topN := m.config.Security.TLSFingerprintTopN
	if topN <= 0 {
		topN = 20
	}
	if len(tmp) > topN {
		tmp = tmp[:topN]
	}
	return tmp
}

type TLSFPStatEx struct {
	FP       string `json:"fp"`
	Count    int    `json:"count"`
	LastSeen string `json:"last_seen"`
}

func (m *Manager) GetTLSFingerprintStatsEx() []TLSFPStatEx {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	now := time.Now()
	window := time.Duration(m.config.Security.TLSFingerprintWindowSec) * time.Second
	if window <= 0 {
		window = time.Minute
	}
	cut := now.Add(-window)
	var out []TLSFPStatEx
	for fp, times := range m.tlsFPCounts {
		cnt := 0
		last := time.Time{}
		for _, t := range times {
			if t.After(cut) {
				cnt++
				if t.After(last) {
					last = t
				}
			}
		}
		if cnt > 0 {
			out = append(out, TLSFPStatEx{FP: fp, Count: cnt, LastSeen: last.Format(time.RFC3339)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if top := m.config.Security.TLSFingerprintTopN; top > 0 && len(out) > top {
		out = out[:top]
	}
	return out
}

// HashTLSRaw 计算原始字符串的 SHA256 指纹
func HashTLSRaw(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// checkAndBlock 检查并封禁IP
func (m *Manager) checkAndBlock(ip string) {
	now := time.Now()
	// 更新失败次数
	m.attemptCounts[ip]++
	// 记录失败时间
	m.lastAttempts[ip] = append(m.lastAttempts[ip], now)
	// 清理过期的失败记录（5分钟前）
	var validAttempts []time.Time
	for _, attempt := range m.lastAttempts[ip] {
		if now.Sub(attempt) <= 5*time.Minute {
			validAttempts = append(validAttempts, attempt)
		}
	}
	m.lastAttempts[ip] = validAttempts
	// 检查1分钟内失败次数
	recentAttempts := 0
	for _, attempt := range m.lastAttempts[ip] {
		if now.Sub(attempt) <= time.Minute {
			recentAttempts++
		}
	}
	// 检查5分钟内失败次数
	fiveMinAttempts := len(m.lastAttempts[ip])
	// 封禁条件
	if recentAttempts >= m.config.Security.MaxAttempts ||
		fiveMinAttempts >= m.config.Security.MaxAttempts5Min {
		m.blockIP(ip, fmt.Sprintf("Too many failed attempts: %d in 1min, %d in 5min",
			recentAttempts, fiveMinAttempts))
	}
}

// blockIP 封禁IP
func (m *Manager) blockIP(ip, reason string) {
	blocked := BlockedIP{
		IP:         ip,
		Reason:     reason,
		BlockTime:  time.Now(),
		ExpireTime: time.Now().Add(m.config.Security.BlockDuration),
	}
	m.blockedIPs[ip] = blocked
	m.saveBlockedIPs()
	m.log.Warnf("Blocked IP %s: %s", ip, reason)
}

// isValidUserAgent 检查User-Agent是否合法
func (m *Manager) isValidUserAgent(userAgent string) bool {
	if userAgent == "" {
		return false
	}
	for _, allowed := range m.config.Security.AllowedUserAgents {
		if strings.Contains(userAgent, allowed) {
			return true
		}
	}
	return false
}

// CheckIPAccess 检查IP访问权限
func (m *Manager) CheckIPAccess(ip string) (bool, string) {
	// 检查IP黑名单
	if m.isInBlacklist(ip) {
		return false, "IP is in blacklist"
	}

	// 检查IP白名单
	if len(m.config.Security.IPWhitelist) > 0 {
		if !m.isInWhitelist(ip) {
			return false, "IP is not in whitelist"
		}
	}

	return true, ""
}

// isInBlacklist 检查IP是否在黑名单中
func (m *Manager) isInBlacklist(ip string) bool {
	for _, blockedIP := range m.config.Security.IPBlacklist {
		if m.matchIPOrCIDR(ip, blockedIP) {
			return true
		}
	}
	return false
}

// isInWhitelist 检查IP是否在白名单中
func (m *Manager) isInWhitelist(ip string) bool {
	for _, allowedIP := range m.config.Security.IPWhitelist {
		if m.matchIPOrCIDR(ip, allowedIP) {
			return true
		}
	}
	return false
}

// matchIPOrCIDR 匹配IP地址或CIDR网段
func (m *Manager) matchIPOrCIDR(ip, pattern string) bool {
	// 如果pattern不包含/，则是单个IP地址
	if !strings.Contains(pattern, "/") {
		return ip == pattern
	}

	// CIDR网段匹配
	_, network, err := net.ParseCIDR(pattern)
	if err != nil {
		m.log.Warnf("Invalid CIDR pattern: %s", pattern)
		return false
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	return network.Contains(clientIP)
}

// GetCORSMiddleware 获取CORS中间件
func (m *Manager) GetCORSMiddleware() *CORSMiddleware {
	return m.corsMiddleware
}

// UpdateCORSConfig 更新CORS配置
func (m *Manager) UpdateCORSConfig(config config.CORSConfig) {
	corsConfig := CORSConfig{
		Enabled:             config.Enabled,
		AllowedOrigins:      config.AllowedOrigins,
		AllowedMethods:      config.AllowedMethods,
		AllowedHeaders:      config.AllowedHeaders,
		ExposedHeaders:      config.ExposedHeaders,
		AllowCredentials:    config.AllowCredentials,
		MaxAge:              config.MaxAge,
		AllowPrivateNetwork: config.AllowPrivateNetwork,
	}
	m.corsMiddleware = NewCORSMiddleware(corsConfig)
	m.log.Info("CORS configuration updated")
}

// loadBlockedIPs 加载被封禁的IP列表
func (m *Manager) loadBlockedIPs() {
	blockFile := m.config.Security.BlockFile
	if _, err := os.Stat(blockFile); os.IsNotExist(err) {
		return
	}

	file, err := os.Open(blockFile)
	if err != nil {
		m.log.Errorf("Failed to open block file: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var blocked BlockedIP
		if err := json.Unmarshal(scanner.Bytes(), &blocked); err != nil {
			m.log.Errorf("Failed to parse blocked record: %v", err)
			continue
		}

		// 只加载未过期的封禁记录
		if time.Now().Before(blocked.ExpireTime) {
			m.blockedIPs[blocked.IP] = blocked
		}
	}

	m.log.Infof("Loaded %d blocked IP records", len(m.blockedIPs))
}

// saveBlockedIPs 保存被封禁的IP列表
func (m *Manager) saveBlockedIPs() {
	blockFile := m.config.Security.BlockFile

	// 确保目录存在
	dir := filepath.Dir(blockFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		m.log.Errorf("Failed to create block file directory: %v", err)
		return
	}

	file, err := os.Create(blockFile)
	if err != nil {
		m.log.Errorf("Failed to create block file: %v", err)
		return
	}
	defer file.Close()

	for _, blocked := range m.blockedIPs {
		data, err := json.Marshal(blocked)
		if err != nil {
			m.log.Errorf("Failed to serialize blocked record: %v", err)
			continue
		}

		if _, err := file.Write(append(data, '\n')); err != nil {
			m.log.Errorf("Failed to write blocked record: %v", err)
		}
	}
}

// cleanupTask 清理任务
func (m *Manager) cleanupTask() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.stopChan:
			return
		}
	}
}

// cleanup 清理过期的数据
func (m *Manager) cleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()

	// 清理过期的封禁记录
	for ip, blocked := range m.blockedIPs {
		if now.After(blocked.ExpireTime) {
			delete(m.blockedIPs, ip)
		}
	}

	// 限制被封禁IP的数量
	if len(m.blockedIPs) > m.maxBlockedIPs {
		m.log.Warnf("Blocked IPs count exceeded limit, pruning from %d to %d", len(m.blockedIPs), m.maxBlockedIPs)
		m.pruneMapByTime(m.blockedIPs, m.maxBlockedIPs)
	}

	// 清理过期的访问日志
	for ip, logs := range m.accessLogs {
		var validLogs []AccessLog
		for _, log := range logs {
			if now.Sub(log.Timestamp) <= 24*time.Hour {
				validLogs = append(validLogs, log)
			}
		}
		if len(validLogs) == 0 {
			delete(m.accessLogs, ip)
		} else {
			// 限制每个IP的日志数量
			if len(validLogs) > m.maxAccessLogEntries {
				validLogs = validLogs[len(validLogs)-m.maxAccessLogEntries:]
			}
			m.accessLogs[ip] = validLogs
		}
	}

	// 限制访问日志IP的数量
	if len(m.accessLogs) > m.maxAttemptCounts {
		m.log.Warnf("Access logs IP count exceeded limit, pruning from %d to %d", len(m.accessLogs), m.maxAttemptCounts)
		m.pruneMapByLastAccessTime(m.accessLogs, m.maxAttemptCounts)
	}

	// 清理过期的失败记录和尝试计数
	for ip, attempts := range m.lastAttempts {
		var validAttempts []time.Time
		for _, attempt := range attempts {
			if now.Sub(attempt) <= 5*time.Minute {
				validAttempts = append(validAttempts, attempt)
			}
		}
		if len(validAttempts) == 0 {
			delete(m.lastAttempts, ip)
			delete(m.attemptCounts, ip)
		} else {
			// 限制每个IP的尝试次数
			if len(validAttempts) > m.maxLastAttempts {
				validAttempts = validAttempts[len(validAttempts)-m.maxLastAttempts:]
			}
			m.lastAttempts[ip] = validAttempts
		}
	}

	// 限制失败尝试IP的数量
	if len(m.attemptCounts) > m.maxAttemptCounts {
		m.log.Warnf("Attempt counts IP count exceeded limit, pruning from %d to %d", len(m.attemptCounts), m.maxAttemptCounts)
		m.pruneMap(m.attemptCounts, m.maxAttemptCounts)
	}

	// 清理过期的 UA 违规记录
	for ip := range m.uaInvalid1Min {
		m.pruneUAInvalidEntries(ip, now)
	}
	// 限制 UA 违规记录的数量
	if len(m.uaInvalid1Min) > m.maxUAInvalidEntries {
		m.log.Warnf("UA invalid entries count exceeded limit, pruning from %d to %d", len(m.uaInvalid1Min), m.maxUAInvalidEntries)
		m.pruneMap(m.uaInvalid1Min, m.maxUAInvalidEntries)
	}

	// 清理过期的 TLS 指纹计数
	for fp, times := range m.tlsFPCounts {
		var validTimes []time.Time
		window := time.Duration(m.config.Security.TLSFingerprintWindowSec) * time.Second
		if window <= 0 {
			window = time.Minute
		}
		cut := now.Add(-window)
		for _, t := range times {
			if t.After(cut) {
				validTimes = append(validTimes, t)
			}
		}
		if len(validTimes) == 0 {
			delete(m.tlsFPCounts, fp)
		} else {
			// 限制每个指纹的计数数量
			if len(validTimes) > m.maxTLSFPEntries {
				validTimes = validTimes[len(validTimes)-m.maxTLSFPEntries:]
			}
			m.tlsFPCounts[fp] = validTimes
		}
	}

	// 限制 TLS 指纹计数器的数量
	if len(m.tlsFPCounts) > m.maxTLSFPEntries {
		m.log.Warnf("TLS fingerprint entries count exceeded limit, pruning from %d to %d", len(m.tlsFPCounts), m.maxTLSFPEntries)
		m.pruneMap(m.tlsFPCounts, m.maxTLSFPEntries)
	}
}

// pruneMap 裁剪map，删除最旧的元素
func (m *Manager) pruneMap(data interface{}, maxEntries int) {
	switch v := data.(type) {
	case map[string]BlockedIP:
		if len(v) <= maxEntries {
			return
		}
		// 按 BlockTime 排序并删除
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return v[keys[i]].BlockTime.Before(v[keys[j]].BlockTime)
		})
		for i := 0; i < len(v)-maxEntries; i++ {
			delete(v, keys[i])
		}
	case map[string]int:
		if len(v) <= maxEntries {
			return
		}
		// 随机删除一些，或者根据某种策略删除
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		for i := 0; i < len(v)-maxEntries; i++ {
			delete(v, keys[i])
		}
	case map[string][]time.Time:
		if len(v) <= maxEntries {
			return
		}
		// 按最早时间戳排序并删除
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(v[keys[i]]) == 0 || len(v[keys[j]]) == 0 {
				return false
			}
			return v[keys[i]][0].Before(v[keys[j]][0])
		})
		for i := 0; i < len(v)-maxEntries; i++ {
			delete(v, keys[i])
		}
	case map[string][]AccessLog:
		if len(v) <= maxEntries {
			return
		}
		// 按最早日志时间戳排序并删除
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(v[keys[i]]) == 0 || len(v[keys[j]]) == 0 {
				return false
			}
			return v[keys[i]][0].Timestamp.Before(v[keys[j]][0].Timestamp)
		})
		for i := 0; i < len(v)-maxEntries; i++ {
			delete(v, keys[i])
		}
	}
}

// pruneMapByTime 裁剪 map，删除最旧的元素（基于BlockTime或ExpireTime）
func (m *Manager) pruneMapByTime(data interface{}, maxEntries int) {
	switch v := data.(type) {
	case map[string]BlockedIP:
		if len(v) <= maxEntries {
			return
		}
		// 按 ExpireTime 排序并删除
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return v[keys[i]].ExpireTime.Before(v[keys[j]].ExpireTime)
		})
		for i := 0; i < len(v)-maxEntries; i++ {
			delete(v, keys[i])
		}
	}
}

// pruneMapByLastAccessTime 裁剪 map，删除最旧的元素（基于AccessLog的LastAccessTime）
func (m *Manager) pruneMapByLastAccessTime(data interface{}, maxEntries int) {
	switch v := data.(type) {
	case map[string][]AccessLog:
		if len(v) <= maxEntries {
			return
		}
		// 按 AccessLog 最后一条的时间排序并删除
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(v[keys[i]]) == 0 || len(v[keys[j]]) == 0 {
				return false
			}
			return v[keys[i]][len(v[keys[i]])-1].Timestamp.Before(v[keys[j]][len(v[keys[j]])-1].Timestamp)
		})
		for i := 0; i < len(v)-maxEntries; i++ {
			delete(v, keys[i])
		}
	}
}

// pruneUAInvalidEntries 清理UA违规记录
func (m *Manager) pruneUAInvalidEntries(ip string, now time.Time) {
	cut1 := now.Add(-1 * time.Minute)
	cut5 := now.Add(-5 * time.Minute)

	// 清理1分钟窗口
	pruned1 := m.uaInvalid1Min[ip][:0]
	for _, t := range m.uaInvalid1Min[ip] {
		if t.After(cut1) {
			pruned1 = append(pruned1, t)
		}
	}
	m.uaInvalid1Min[ip] = pruned1

	// 清理5分钟窗口
	pruned5 := m.uaInvalid5Min[ip][:0]
	for _, t := range m.uaInvalid5Min[ip] {
		if t.After(cut5) {
			pruned5 = append(pruned5, t)
		}
	}
	m.uaInvalid5Min[ip] = pruned5
}

// GetClientIP 获取客户端真实IP
func GetClientIP(remoteAddr string, headers map[string]string) string {
	// 优先使用X-Forwarded-For
	if xff := headers["X-Forwarded-For"]; xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 使用X-Real-IP
	if xri := headers["X-Real-IP"]; xri != "" {
		return strings.TrimSpace(xri)
	}

	// 使用RemoteAddr
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}

	return host
}

// GetBlockedIPs 获取被封禁的IP列表
func (m *Manager) GetBlockedIPs() []BlockedIP {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var blockedList []BlockedIP
	for _, blocked := range m.blockedIPs {
		// 只返回未过期的IP
		if time.Now().Before(blocked.ExpireTime) {
			blockedList = append(blockedList, blocked)
		}
	}

	return blockedList
}

// UnblockIP 解除IP封禁
func (m *Manager) UnblockIP(ip string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.blockedIPs[ip]; exists {
		delete(m.blockedIPs, ip)
		delete(m.attemptCounts, ip)
		delete(m.lastAttempts, ip)
		m.log.Infof("Manually unblocked IP: %s", ip)
	}
}

// GetAccessLogs 获取访问日志
func (m *Manager) GetAccessLogs(ip string, limit int) []AccessLog {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	logs, exists := m.accessLogs[ip]
	if !exists {
		return nil
	}

	// 返回最新的日志
	if limit > 0 && len(logs) > limit {
		return logs[len(logs)-limit:]
	}

	return logs
}

// GetSecurityStats 获取安全统计信息
func (m *Manager) GetSecurityStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	totalBlocked := 0
	recentAttempts := 0
	now := time.Now()
	oneHourAgo := now.Add(-time.Hour)

	// 统计被封禁的IP数量
	for _, blocked := range m.blockedIPs {
		if now.Before(blocked.ExpireTime) {
			totalBlocked++
		}
	}

	// 统计最近一小时的失败尝试次数
	for _, logs := range m.accessLogs {
		for _, log := range logs {
			if !log.Success && log.Timestamp.After(oneHourAgo) {
				recentAttempts++
			}
		}
	}

	stats := map[string]interface{}{
		"blocked_ips":      totalBlocked,
		"recent_attempts":  recentAttempts,
		"total_access_ips": len(m.accessLogs),
	}

	// 添加地理位置服务统计信息
	if m.geoIPService != nil {
		stats["geoip"] = m.geoIPService.GetStats()
	}

	return stats
}

// CheckGeoAccess 检查IP的地理位置访问权限
func (m *Manager) CheckGeoAccess(ip string) (*GeoFilterResult, error) {
	if m.geoIPService == nil {
		return &GeoFilterResult{
			Allowed: true,
			Reason:  "GeoIP service not available",
		}, nil
	}

	return m.geoIPService.CheckCountryAccess(ip)
}

// GetGeoLocation 获取IP的地理位置信息
func (m *Manager) GetGeoLocation(ip string) (*GeoLocation, error) {
	if m.geoIPService == nil {
		return nil, fmt.Errorf("GeoIP service not available")
	}

	return m.geoIPService.GetLocation(ip)
}

// GetGeoIPService 获取地理位置IP服务
func (m *Manager) GetGeoIPService() *GeoIPService {
	return m.geoIPService
}

// UpdateGeoConfig 更新地理位置配置
func (m *Manager) UpdateGeoConfig(config config.GeoBlockingConfig) error {
	// 重新初始化地理位置服务
	if m.geoIPService != nil {
		_ = m.geoIPService.Close()
	}

	geoIPService, err := NewGeoIPService(config)
	if err != nil {
		return fmt.Errorf("failed to update GeoIP service: %w", err)
	}

	m.geoIPService = geoIPService
	m.log.Info("GeoIP configuration updated")

	return nil
}
