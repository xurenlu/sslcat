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
}

// NewManager 创建安全管理器
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		config:        cfg,
		accessLogs:    make(map[string][]AccessLog),
		blockedIPs:    make(map[string]BlockedIP),
		attemptCounts: make(map[string]int),
		lastAttempts:  make(map[string][]time.Time),
		uaInvalid1Min: make(map[string][]time.Time),
		uaInvalid5Min: make(map[string][]time.Time),
		tlsFPCounts:   make(map[string][]time.Time),
		stopChan:      make(chan struct{}),
		log: logrus.WithFields(logrus.Fields{
			"component": "security_manager",
		}),
	}
}

// Start 启动安全管理器
func (m *Manager) Start() {
	m.log.Info("Starting security manager")

	// 加载被封禁的IP列表
	m.loadBlockedIPs()

	// 启动清理任务
	go m.cleanupTask()
}

// Stop 停止安全管理器
func (m *Manager) Stop() {
	m.log.Info("Stopping security manager")
	close(m.stopChan)
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

	// 追加写入 JSON Lines（持久化）
	rec := map[string]any{
		"time": time.Now().Format(time.RFC3339),
		"fp":   fingerprint,
		"ip":   ip,
	}
	if b, err := json.Marshal(rec); err == nil {
		_ = os.MkdirAll("./data", 0755)
		if f, err := os.OpenFile("./data/tls_fp.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			_, _ = f.Write(append(b, '\n'))
			_ = f.Close()
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
	ticker := time.NewTicker(time.Minute)
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
			m.accessLogs[ip] = validLogs
		}
	}

	// 清理过期的失败记录
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
			m.lastAttempts[ip] = validAttempts
		}
	}

	// 清理过期的 TLS 指纹计数
	for fp, times := range m.tlsFPCounts {
		var validTimes []time.Time
		for _, t := range times {
			if now.Sub(t) <= time.Duration(m.config.Security.TLSFingerprintWindowSec)*time.Second {
				validTimes = append(validTimes, t)
			}
		}
		if len(validTimes) == 0 {
			delete(m.tlsFPCounts, fp)
		} else {
			m.tlsFPCounts[fp] = validTimes
		}
	}
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

	return map[string]interface{}{
		"blocked_ips":      totalBlocked,
		"recent_attempts":  recentAttempts,
		"total_access_ips": len(m.accessLogs),
	}
}
