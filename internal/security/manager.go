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
	"github.com/xurenlu/sslcat/internal/threatintel"

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

// BlockedUserAgent 被封禁的User-Agent信息
type BlockedUserAgent struct {
	UserAgent  string    `json:"user_agent"`
	Reason     string    `json:"reason"`
	BlockTime  time.Time `json:"block_time"`
	ExpireTime time.Time `json:"expire_time"`
}

// WhitelistEntry IP白名单条目
type WhitelistEntry struct {
	Value       string    `json:"value"`       // IP或CIDR（如 "192.168.1.1" 或 "192.168.1.0/24"）
	Description string    `json:"description"` // 描述信息（可选）
	CreatedAt   time.Time `json:"created_at"`  // 创建时间
	UpdatedAt   time.Time `json:"updated_at"`  // 更新时间
}

// Manager 安全管理器
type Manager struct {
	config            *config.Config
	accessLogs        map[string][]AccessLog
	blockedIPs        map[string]BlockedIP
	blockedUserAgents map[string]BlockedUserAgent // User-Agent封禁列表
	attemptCounts     map[string]int
	lastAttempts      map[string][]time.Time
	// UA 违规计数：按IP维度记录
	uaInvalid1Min map[string][]time.Time
	uaInvalid5Min map[string][]time.Time
	// TLS 指纹计数
	tlsFPCounts map[string][]time.Time
	// TOTP-only 登录失败计数（独立于普通登录）
	totpOnlyAttemptCounts map[string]int
	totpOnlyLastAttempts  map[string][]time.Time
	mutex                 sync.RWMutex
	log                   *logrus.Entry
	stopChan              chan struct{}
	// TLS 指纹持久化
	tlsFPRotator   *logger.Rotator
	geoIPService   *GeoIPService
	corsMiddleware *CORSMiddleware

	// IP白名单
	whitelistEntries map[string]WhitelistEntry // value -> WhitelistEntry

	// 威胁情报管理器
	threatIntelManager *threatintel.ThreatIntelManager

	// 内存泄漏防护
	maxAccessLogEntries int           // 每个IP的访问日志最多保留多少条
	maxBlockedIPs       int           // 最多保留多少个被封禁的IP
	maxAttemptCounts    int           // 最多保留多少个IP的尝试计数
	maxLastAttempts     int           // 最多保留多少个IP的最后尝试时间
	maxUAInvalidEntries int           // 最多保留多少个IP的UA违规记录
	maxTLSFPEntries     int           // 最多保留多少个TLS指纹计数
	cleanupInterval     time.Duration // 清理间隔

	// 持久化队列：避免并发写盘导致旧快照覆盖新状态
	blockedPersistCh   chan struct{}
	whitelistPersistCh chan struct{}
	persistWG          sync.WaitGroup
	// 文件级串行保护，防止绕过队列时并发写同一文件
	blockedPersistMu   sync.Mutex
	whitelistPersistMu sync.Mutex
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
		config:                cfg,
		accessLogs:            make(map[string][]AccessLog),
		blockedIPs:            make(map[string]BlockedIP),
		blockedUserAgents:     make(map[string]BlockedUserAgent),
		attemptCounts:         make(map[string]int),
		lastAttempts:          make(map[string][]time.Time),
		uaInvalid1Min:         make(map[string][]time.Time),
		uaInvalid5Min:         make(map[string][]time.Time),
		tlsFPCounts:           make(map[string][]time.Time),
		totpOnlyAttemptCounts: make(map[string]int),
		totpOnlyLastAttempts:  make(map[string][]time.Time),
		stopChan:              make(chan struct{}),
		geoIPService:          geoIPService,
		corsMiddleware:        corsMiddleware,
		whitelistEntries:      make(map[string]WhitelistEntry),
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
		blockedPersistCh:    make(chan struct{}, 1),
		whitelistPersistCh:  make(chan struct{}, 1),
	}
}

// GetName 获取组件名称
func (m *Manager) GetName() string {
	return "SecurityManager"
}

// Reload 重载安全管理器配置
func (m *Manager) Reload(newConfig *config.Config) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.log.Info("Reloading security manager configuration")
	m.config = newConfig

	// 重新初始化 CORS 中间件
	corsConfig := CORSConfig{
		Enabled:             newConfig.Security.CORS.Enabled,
		AllowedOrigins:      newConfig.Security.CORS.AllowedOrigins,
		AllowedMethods:      newConfig.Security.CORS.AllowedMethods,
		AllowedHeaders:      newConfig.Security.CORS.AllowedHeaders,
		ExposedHeaders:      newConfig.Security.CORS.ExposedHeaders,
		AllowCredentials:    newConfig.Security.CORS.AllowCredentials,
		MaxAge:              newConfig.Security.CORS.MaxAge,
		AllowPrivateNetwork: newConfig.Security.CORS.AllowPrivateNetwork,
	}
	m.corsMiddleware = NewCORSMiddleware(corsConfig)

	// 更新内存泄漏防护设置
	m.maxAccessLogEntries = newConfig.Security.MaxAccessLogEntries
	m.maxBlockedIPs = newConfig.Security.MaxBlockedIPs
	m.maxAttemptCounts = newConfig.Security.MaxAttemptCounts
	m.maxLastAttempts = newConfig.Security.MaxLastAttempts
	m.maxUAInvalidEntries = newConfig.Security.UAInvalidMaxTotal
	m.maxTLSFPEntries = newConfig.Security.TLSFingerprintMaxTotal

	if newConfig.Security.CleanupIntervalMin > 0 {
		m.cleanupInterval = time.Duration(newConfig.Security.CleanupIntervalMin) * time.Minute
	}

	return nil
}

// Validate 验证配置是否适用于此组件
func (m *Manager) Validate(newConfig *config.Config) error {
	// 基本验证已经在 config.Validate() 中完成
	return nil
}

// Start 启动安全管理器
func (m *Manager) Start() {
	m.log.Info("Starting security manager")

	// 加载被封禁的IP列表
	m.loadBlockedIPs()

	// 加载IP白名单
	m.loadWhitelist()

	// 启动清理任务
	go m.cleanupTask()
	m.startPersistWorkers()

	// 初始化 TLS 指纹日志轮转器（10MB*10）
	if rot, err := logger.NewRotator("./data/tls_fp.log", 10*1024*1024, 10); err == nil {
		m.tlsFPRotator = rot
	}
}

// Stop 停止安全管理器
func (m *Manager) Stop() {
	m.log.Info("Stopping security manager")
	close(m.stopChan)
	m.persistWG.Wait()
	if m.tlsFPRotator != nil {
		_ = m.tlsFPRotator.Close()
	}
	if m.geoIPService != nil {
		_ = m.geoIPService.Close()
	}
}

func (m *Manager) startPersistWorkers() {
	m.persistWG.Add(2)
	go m.persistWorker(m.blockedPersistCh, m.saveBlockedIPs)
	go m.persistWorker(m.whitelistPersistCh, m.saveWhitelist)
}

func (m *Manager) persistWorker(ch <-chan struct{}, saveFn func()) {
	defer m.persistWG.Done()
	for {
		select {
		case <-ch:
			// 合并短时间内高频触发，减少写盘抖动
			timer := time.NewTimer(30 * time.Millisecond)
			select {
			case <-timer.C:
			case <-m.stopChan:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				saveFn()
				return
			}

			for {
				select {
				case <-ch:
					continue
				default:
					saveFn()
					goto next
				}
			}
		case <-m.stopChan:
			// 停止前尽量冲刷一次队列里的最后状态
			select {
			case <-ch:
				for {
					select {
					case <-ch:
						continue
					default:
						saveFn()
						return
					}
				}
			default:
				return
			}
		}
	next:
	}
}

func (m *Manager) queueBlockedPersist() {
	select {
	case m.blockedPersistCh <- struct{}{}:
	default:
	}
}

func (m *Manager) queueWhitelistPersist() {
	select {
	case m.whitelistPersistCh <- struct{}{}:
	default:
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
	if m.IsWhitelisted(ip) {
		return false
	}

	m.mutex.RLock()
	blocked, exists := m.blockedIPs[ip]
	m.mutex.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(blocked.ExpireTime) {
		// 过期条目用写锁清理（不能在 RLock 下 delete map）
		m.mutex.Lock()
		if b, ok := m.blockedIPs[ip]; ok && time.Now().After(b.ExpireTime) {
			delete(m.blockedIPs, ip)
		}
		m.mutex.Unlock()
		return false
	}

	return true
}

// LogAccess 记录访问日志
func (m *Manager) LogAccess(ip, userAgent, path string, success bool) {
	// 修复：先在锁外进行威胁情报检查（避免持锁执行复杂操作）
	if m.threatIntelManager != nil && path != "" {
		if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
			// 检查完整URL
			if isThreat, level, desc := m.CheckThreatIntel(path, threatintel.IOCTypeURL); isThreat && level >= threatintel.ThreatLevelHigh {
				m.log.Warnf("检测到恶意URL %s from %s: %s", path, ip, desc)
			}
			// 提取域名检查
			parts := strings.Split(strings.TrimPrefix(path, "https://"), "/")
			if len(parts) > 0 {
				domain := parts[0]
				if isThreat, level, desc := m.CheckThreatIntel(domain, threatintel.IOCTypeDomain); isThreat && level >= threatintel.ThreatLevelHigh {
					m.log.Warnf("检测到恶意域名 %s from %s: %s", domain, ip, desc)
				}
			}
		}
	}

	var blockedReason string
	now := time.Now()

	func() {
		if success && !m.config.Security.EnableUAFilter {
			if !m.mutex.TryLock() {
				return
			}
		} else {
			m.mutex.Lock()
		}
		defer m.mutex.Unlock()

		// 检查User-Agent是否合法
		if m.config.Security.EnableUAFilter && !m.isValidUserAgent(userAgent) {
			m.log.Warnf("Suspicious User-Agent: %s from %s", userAgent, ip)
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
				reason := fmt.Sprintf("Too many invalid UA: %d in 1min, %d in 5min", len(m.uaInvalid1Min[ip]), len(m.uaInvalid5Min[ip]))
				if m.blockIPLocked(ip, reason, now) {
					blockedReason = reason
				}
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
			Timestamp: now,
			Success:   success,
		}

		m.accessLogs[ip] = append(m.accessLogs[ip], accessLog)

		maxAccessLogs := m.maxAccessLogEntries
		if maxAccessLogs <= 0 {
			maxAccessLogs = 3000
		}
		if len(m.accessLogs[ip]) > maxAccessLogs {
			m.accessLogs[ip] = m.accessLogs[ip][len(m.accessLogs[ip])-maxAccessLogs:]
		}

		// 如果不是成功访问，检查是否需要封禁
		if !success {
			blockedReason = m.checkAndBlockLocked(ip, now)
		}
	}()

	if blockedReason != "" {
		m.queueBlockedPersist()
		m.log.Warnf("Blocked IP %s: %s", ip, blockedReason)
	}
}

// LogTLSFingerprint 记录 TLS 指纹（单位时间窗口）
func (m *Manager) LogTLSFingerprint(fingerprint, ip string) {
	if fingerprint == "" {
		return
	}

	// 先准备要写入的数据(在锁外面)
	now := time.Now()
	rec := map[string]any{
		"time": now.Format(time.RFC3339),
		"fp":   fingerprint,
		"ip":   ip,
	}

	// 锁内只做内存操作,不做文件I/O
	var shouldWarn bool
	var warnCount int
	func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()

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

		// 阈值告警检查(只记录是否需要告警,不在锁内打日志)
		maxPerMin := m.config.Security.TLSFingerprintMaxPerMin
		if maxPerMin <= 0 {
			maxPerMin = 6000
		}
		if len(pruned) > maxPerMin {
			shouldWarn = true
			warnCount = len(pruned)
		}
	}()

	// 锁外执行告警日志
	if shouldWarn {
		m.log.Warnf("TLS fingerprint too active fp=%s count=%d ip=%s", fingerprint, warnCount, ip)
	}

	// 锁外执行文件I/O操作
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

// checkAndBlockLocked 检查失败窗口并在需要时直接更新封禁缓存
// 调用方必须已经持有 m.mutex.Lock()
func (m *Manager) checkAndBlockLocked(ip string, now time.Time) string {
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
	maxAttempts := m.config.Security.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 900
	}
	maxAttempts5Min := m.config.Security.MaxAttempts5Min
	if maxAttempts5Min <= 0 {
		maxAttempts5Min = 3000
	}
	if recentAttempts >= maxAttempts ||
		fiveMinAttempts >= maxAttempts5Min {
		reason := fmt.Sprintf("Too many failed attempts: %d in 1min, %d in 5min",
			recentAttempts, fiveMinAttempts)
		if m.blockIPLocked(ip, reason, now) {
			return reason
		}
	}
	return ""
}

// blockIP 封禁IP
func (m *Manager) blockIP(ip, reason string) {
	now := time.Now()
	var blocked bool
	m.mutex.Lock()
	blocked = m.blockIPLocked(ip, reason, now)
	m.mutex.Unlock()
	if !blocked {
		return
	}

	// 异步保存到文件（避免持锁执行 I/O）
	m.queueBlockedPersist()
	m.log.Warnf("Blocked IP %s: %s", ip, reason)
}

// blockIPLocked 在已持锁前提下更新封禁缓存
func (m *Manager) blockIPLocked(ip, reason string, now time.Time) bool {
	if m.isWhitelistedLocked(ip) {
		m.log.Infof("Skipped blocking IP %s (in whitelist): %s", ip, reason)
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	m.blockedIPs[ip] = BlockedIP{
		IP:         ip,
		Reason:     reason,
		BlockTime:  now,
		ExpireTime: now.Add(m.config.Security.BlockDuration),
	}
	return true
}

// BlockIP 手动封禁IP（公开方法）
func (m *Manager) BlockIP(ip string, duration time.Duration, reason string) {
	// 检查白名单，白名单中的IP不会被封禁
	if m.IsWhitelisted(ip) {
		m.log.Infof("Skipped manually blocking IP %s (in whitelist): %s", ip, reason)
		return
	}

	now := time.Now()
	expireTime := now.Add(duration)

	blocked := BlockedIP{
		IP:         ip,
		Reason:     reason,
		BlockTime:  now,
		ExpireTime: expireTime,
	}

	// 修复：快速更新内存，然后在锁外执行 I/O
	m.mutex.Lock()
	m.blockedIPs[ip] = blocked
	m.mutex.Unlock()

	// 异步保存到文件（避免持锁执行 I/O）
	m.queueBlockedPersist()
	m.log.Warnf("Manually blocked IP %s: %s (duration: %v)", ip, reason, duration)
}

// BlockUserAgent 手动封禁User-Agent
func (m *Manager) BlockUserAgent(userAgent string, duration time.Duration, reason string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if userAgent == "" {
		return
	}

	now := time.Now()
	expireTime := now.Add(duration)
	if duration == 0 {
		// 永久封禁（设置一个很远的未来时间）
		expireTime = time.Now().Add(100 * 365 * 24 * time.Hour)
	}

	blocked := BlockedUserAgent{
		UserAgent:  userAgent,
		Reason:     reason,
		BlockTime:  now,
		ExpireTime: expireTime,
	}
	m.blockedUserAgents[userAgent] = blocked
	m.log.Warnf("Manually blocked User-Agent %s: %s (duration: %v)", userAgent, reason, duration)
}

// UnblockUserAgent 解除User-Agent封禁
func (m *Manager) UnblockUserAgent(userAgent string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.blockedUserAgents[userAgent]; exists {
		delete(m.blockedUserAgents, userAgent)
		m.log.Infof("Manually unblocked User-Agent: %s", userAgent)
	}
}

// GetBlockedUserAgents 获取被封禁的User-Agent列表
func (m *Manager) GetBlockedUserAgents() []BlockedUserAgent {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var blockedList []BlockedUserAgent
	now := time.Now()
	for _, blocked := range m.blockedUserAgents {
		// 只返回未过期的User-Agent
		if now.Before(blocked.ExpireTime) {
			blockedList = append(blockedList, blocked)
		}
	}

	return blockedList
}

// IsUserAgentBlocked 检查User-Agent是否被封禁
func (m *Manager) IsUserAgentBlocked(userAgent string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if userAgent == "" {
		return false
	}

	blocked, exists := m.blockedUserAgents[userAgent]
	if !exists {
		return false
	}

	// 检查是否已过期
	if time.Now().After(blocked.ExpireTime) {
		return false
	}

	return true
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
	// 先检查IP白名单（白名单优先级最高，即使在威胁情报库中也放行）
	if m.IsWhitelisted(ip) {
		return true, ""
	}

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

	// 检查威胁情报库
	isThreat, threatLevel, description := m.CheckThreatIntel(ip, threatintel.IOCTypeIP)
	if isThreat {
		// 对于高危和严重威胁，直接拒绝
		if threatLevel >= threatintel.ThreatLevelHigh {
			return false, fmt.Sprintf("威胁情报阻断: %s", description)
		}
		// 对于中等威胁，记录日志但允许访问（可根据配置调整行为）
		m.log.Warnf("检测到中等威胁IP %s: %s", ip, description)
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
// 注意：此方法应该在锁外调用，避免持锁执行 I/O
func (m *Manager) saveBlockedIPs() {
	m.blockedPersistMu.Lock()
	defer m.blockedPersistMu.Unlock()

	// 获取数据快照，避免持锁执行 I/O
	m.mutex.RLock()
	// 创建封禁列表的副本，避免在 I/O 期间持有锁
	blockedIPs := make(map[string]BlockedIP, len(m.blockedIPs))
	for k, v := range m.blockedIPs {
		blockedIPs[k] = v
	}
	m.mutex.RUnlock()

	lines := make([][]byte, 0, len(blockedIPs))
	for _, blocked := range blockedIPs {
		data, err := json.Marshal(blocked)
		if err != nil {
			m.log.Errorf("Failed to serialize blocked record: %v", err)
			continue
		}
		lines = append(lines, data)
	}
	if err := writeJSONLinesAtomically(m.config.Security.BlockFile, lines); err != nil {
		m.log.Errorf("Failed to persist blocked IPs: %v", err)
	}
}

func writeJSONLinesAtomically(targetPath string, lines [][]byte) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory failed: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".persist-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file failed: %w", err)
	}
	tmpPath := tmpFile.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	for _, line := range lines {
		if _, err := tmpFile.Write(line); err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("write temp file failed: %w", err)
		}
		if _, err := tmpFile.Write([]byte{'\n'}); err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("write temp newline failed: %w", err)
		}
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp file failed: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file failed: %w", err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("rename temp file failed: %w", err)
	}

	// 最后同步目录元数据，尽量降低崩溃后丢文件窗口
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}

	success = true
	return nil
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

	// 清理过期的User-Agent封禁记录
	for ua, blocked := range m.blockedUserAgents {
		if now.After(blocked.ExpireTime) {
			delete(m.blockedUserAgents, ua)
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
	_, exists := m.blockedIPs[ip]
	if exists {
		delete(m.blockedIPs, ip)
		delete(m.attemptCounts, ip)
		delete(m.lastAttempts, ip)
	}
	m.mutex.Unlock()

	if exists {
		// 异步保存到文件（避免持锁执行 I/O）
		m.queueBlockedPersist()
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

// CheckTOTPOnlyLoginSecurity 检查 TOTP-only 登录的安全性
// 返回 (是否允许, 错误信息, 是否需要验证码)
func (m *Manager) CheckTOTPOnlyLoginSecurity(ip string) (bool, string, bool) {
	if blocked, reason := m.CheckIPAccess(ip); !blocked {
		return false, reason, false
	}
	if m.IsBlocked(ip) {
		return false, "IP已被封禁", false
	}

	// 在锁内完成计算，收集需要封禁的信息后释放锁，再执行 I/O
	var shouldBlock bool
	var blockReason string

	m.mutex.Lock()
	now := time.Now()

	var validAttempts []time.Time
	if attempts, exists := m.totpOnlyLastAttempts[ip]; exists {
		for _, attempt := range attempts {
			if now.Sub(attempt) <= 15*time.Minute {
				validAttempts = append(validAttempts, attempt)
			}
		}
		m.totpOnlyLastAttempts[ip] = validAttempts
	}

	recentAttempts := len(validAttempts)

	oneMinAttempts := 0
	for _, attempt := range validAttempts {
		if now.Sub(attempt) <= time.Minute {
			oneMinAttempts++
		}
	}

	if oneMinAttempts >= 3 {
		m.mutex.Unlock()
		return true, "", true
	}
	if recentAttempts >= 5 {
		blockReason = fmt.Sprintf("TOTP-only登录失败次数过多: %d次/15分钟", recentAttempts)
		shouldBlock = true
		m.blockedIPs[ip] = BlockedIP{
			IP:         ip,
			Reason:     blockReason,
			BlockTime:  now,
			ExpireTime: now.Add(m.config.Security.BlockDuration),
		}
	}
	m.mutex.Unlock()

	if shouldBlock {
		m.queueBlockedPersist()
		m.log.Warnf("Blocked IP %s: %s", ip, blockReason)
		return false, "TOTP-only登录失败次数过多，IP已被临时封禁15分钟", false
	}

	return true, "", false
}

// RecordTOTPOnlyLoginFailure 记录 TOTP-only 登录失败
func (m *Manager) RecordTOTPOnlyLoginFailure(ip string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()
	m.totpOnlyAttemptCounts[ip]++
	if m.totpOnlyLastAttempts[ip] == nil {
		m.totpOnlyLastAttempts[ip] = make([]time.Time, 0)
	}
	m.totpOnlyLastAttempts[ip] = append(m.totpOnlyLastAttempts[ip], now)

	m.log.Warnf("TOTP-only登录失败: IP=%s, 失败次数=%d", ip, m.totpOnlyAttemptCounts[ip])
}

// ClearTOTPOnlyLoginAttempts 清除 TOTP-only 登录失败记录（登录成功时调用）
func (m *Manager) ClearTOTPOnlyLoginAttempts(ip string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.totpOnlyAttemptCounts, ip)
	delete(m.totpOnlyLastAttempts, ip)
}

// getWhitelistFile 获取白名单文件路径
func (m *Manager) getWhitelistFile() string {
	// 使用与BlockFile相同的目录，文件名改为whitelist.json
	blockFile := m.config.Security.BlockFile
	dir := filepath.Dir(blockFile)
	return filepath.Join(dir, "whitelist.json")
}

// loadWhitelist 加载IP白名单
func (m *Manager) loadWhitelist() {
	whitelistFile := m.getWhitelistFile()
	if _, err := os.Stat(whitelistFile); os.IsNotExist(err) {
		return
	}

	file, err := os.Open(whitelistFile)
	if err != nil {
		m.log.Errorf("Failed to open whitelist file: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry WhitelistEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			m.log.Errorf("Failed to parse whitelist record: %v", err)
			continue
		}

		// 验证并规范化CIDR格式
		normalized, err := m.parseCIDR(entry.Value)
		if err != nil {
			m.log.Warnf("Invalid whitelist entry %s: %v", entry.Value, err)
			continue
		}

		entry.Value = normalized
		m.whitelistEntries[normalized] = entry
	}

	m.log.Infof("Loaded %d whitelist entries", len(m.whitelistEntries))
}

// saveWhitelist 保存IP白名单
// 注意：此方法应该在锁外调用，传入白名单的副本
func (m *Manager) saveWhitelist() {
	m.whitelistPersistMu.Lock()
	defer m.whitelistPersistMu.Unlock()

	// 获取当前时间快照，避免持锁执行 I/O
	m.mutex.RLock()
	// 创建白名单的副本，避免在 I/O 期间持有锁
	entries := make(map[string]WhitelistEntry, len(m.whitelistEntries))
	for k, v := range m.whitelistEntries {
		entries[k] = v
	}
	m.mutex.RUnlock()

	lines := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err != nil {
			m.log.Errorf("Failed to serialize whitelist record: %v", err)
			continue
		}
		lines = append(lines, data)
	}
	if err := writeJSONLinesAtomically(m.getWhitelistFile(), lines); err != nil {
		m.log.Errorf("Failed to persist whitelist: %v", err)
	}
}

// parseCIDR 解析和规范化CIDR格式
func (m *Manager) parseCIDR(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("empty value")
	}

	// 检查是否是单个IP地址
	if !strings.Contains(value, "/") {
		ip := net.ParseIP(value)
		if ip == nil {
			return "", fmt.Errorf("invalid IP address: %s", value)
		}
		// 转换为/32格式
		if ip.To4() != nil {
			return fmt.Sprintf("%s/32", ip.String()), nil
		}
		return fmt.Sprintf("%s/128", ip.String()), nil
	}

	// 验证CIDR格式
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR format: %s, error: %v", value, err)
	}

	return value, nil
}

// IsWhitelisted 检查IP是否在白名单中
func (m *Manager) IsWhitelisted(ip string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.isWhitelistedLocked(ip)
}

// isWhitelistedLocked 在已持锁前提下检查白名单
func (m *Manager) isWhitelistedLocked(ip string) bool {
	if ip == "" {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 先检查精确匹配（单个IP）
	if _, exists := m.whitelistEntries[ip]; exists {
		return true
	}
	// 检查/32和/128格式
	if _, exists := m.whitelistEntries[fmt.Sprintf("%s/32", ip)]; exists {
		return true
	}
	if _, exists := m.whitelistEntries[fmt.Sprintf("%s/128", ip)]; exists {
		return true
	}

	// 检查CIDR网段匹配
	for value := range m.whitelistEntries {
		if strings.Contains(value, "/") {
			_, network, err := net.ParseCIDR(value)
			if err != nil {
				continue
			}
			if network.Contains(parsedIP) {
				return true
			}
		}
	}

	return false
}

// AddWhitelistEntry 添加白名单条目
func (m *Manager) AddWhitelistEntry(value, description string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 解析和规范化CIDR格式
	normalized, err := m.parseCIDR(value)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR format: %v", err)
	}

	// 检查是否已存在
	if _, exists := m.whitelistEntries[normalized]; exists {
		return fmt.Errorf("whitelist entry already exists: %s", normalized)
	}

	now := time.Now()
	entry := WhitelistEntry{
		Value:       normalized,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	m.whitelistEntries[normalized] = entry
	// 异步保存到文件（避免持锁执行 I/O）
	m.queueWhitelistPersist()
	m.log.Infof("Added whitelist entry: %s", normalized)

	return nil
}

// RemoveWhitelistEntry 删除白名单条目
func (m *Manager) RemoveWhitelistEntry(value string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 规范化值
	normalized, err := m.parseCIDR(value)
	if err != nil {
		return fmt.Errorf("invalid IP or CIDR format: %v", err)
	}

	if _, exists := m.whitelistEntries[normalized]; !exists {
		return fmt.Errorf("whitelist entry not found: %s", normalized)
	}

	delete(m.whitelistEntries, normalized)
	// 异步保存到文件（避免持锁执行 I/O）
	m.queueWhitelistPersist()
	m.log.Infof("Removed whitelist entry: %s", normalized)

	return nil
}

// UpdateWhitelistEntry 更新白名单条目
func (m *Manager) UpdateWhitelistEntry(oldValue, newValue, description string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 规范化旧值
	oldNormalized, err := m.parseCIDR(oldValue)
	if err != nil {
		return fmt.Errorf("invalid old IP or CIDR format: %v", err)
	}

	// 规范化新值
	newNormalized, err := m.parseCIDR(newValue)
	if err != nil {
		return fmt.Errorf("invalid new IP or CIDR format: %v", err)
	}

	// 检查旧值是否存在
	entry, exists := m.whitelistEntries[oldNormalized]
	if !exists {
		return fmt.Errorf("whitelist entry not found: %s", oldNormalized)
	}

	// 如果新值和旧值不同，检查新值是否已存在
	if newNormalized != oldNormalized {
		if _, exists := m.whitelistEntries[newNormalized]; exists {
			return fmt.Errorf("whitelist entry already exists: %s", newNormalized)
		}
		// 删除旧值
		delete(m.whitelistEntries, oldNormalized)
	}

	// 更新条目
	entry.Value = newNormalized
	entry.Description = description
	entry.UpdatedAt = time.Now()
	m.whitelistEntries[newNormalized] = entry

	// 异步保存到文件（避免持锁执行 I/O）
	m.queueWhitelistPersist()
	m.log.Infof("Updated whitelist entry: %s -> %s", oldNormalized, newNormalized)

	return nil
}

// GetWhitelistEntries 获取所有白名单条目
func (m *Manager) GetWhitelistEntries() []WhitelistEntry {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entries := make([]WhitelistEntry, 0, len(m.whitelistEntries))
	for _, entry := range m.whitelistEntries {
		entries = append(entries, entry)
	}

	// 按创建时间排序
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].CreatedAt.Before(entries[j].CreatedAt)
	})

	return entries
}

// GetCIDRType 获取CIDR类型描述
func GetCIDRType(cidr string) string {
	if !strings.Contains(cidr, "/") {
		return "单个IP"
	}

	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "其他网段"
	}

	maskStr := parts[1]
	mask := 0
	fmt.Sscanf(maskStr, "%d", &mask)

	switch mask {
	case 32:
		return "单个IP"
	case 24:
		return "C段"
	case 16:
		return "B段"
	case 8:
		return "A段"
	default:
		if mask > 24 && mask < 32 {
			return fmt.Sprintf("/%d网段", mask)
		} else if mask > 16 && mask < 24 {
			return fmt.Sprintf("/%d网段", mask)
		} else if mask > 8 && mask < 16 {
			return fmt.Sprintf("/%d网段", mask)
		} else {
			return fmt.Sprintf("/%d网段", mask)
		}
	}
}

// SetThreatIntelManager 设置威胁情报管理器
func (m *Manager) SetThreatIntelManager(tim *threatintel.ThreatIntelManager) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.threatIntelManager = tim
	m.log.Info("Threat intelligence manager linked to security manager")
}

// CheckThreatIntel 检查IP/域名/URL是否在威胁情报库中
// 返回: (isThreat, threatLevel, description)
func (m *Manager) CheckThreatIntel(value string, iocType threatintel.IOCType) (bool, threatintel.ThreatLevel, string) {
	m.mutex.RLock()
	tim := m.threatIntelManager
	m.mutex.RUnlock()

	if tim == nil {
		return false, threatintel.ThreatLevelLow, ""
	}

	ioc, found := tim.CheckIOC(value, iocType)
	if !found {
		return false, threatintel.ThreatLevelLow, ""
	}

	// 只有中等及以上威胁级别才认为是威胁
	if ioc.ThreatLevel >= threatintel.ThreatLevelMedium {
		return true, ioc.ThreatLevel, fmt.Sprintf("[%s] %s - 来源: %s", ioc.ThreatLevel.String(), ioc.Description, ioc.Source)
	}

	return false, ioc.ThreatLevel, ioc.Description
}
