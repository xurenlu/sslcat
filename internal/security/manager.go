package security

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"withssl/internal/config"

	"github.com/sirupsen/logrus"
)

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
	mutex         sync.RWMutex
	log           *logrus.Entry
	stopChan      chan struct{}
}

// NewManager 创建安全管理器
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		config:        cfg,
		accessLogs:    make(map[string][]AccessLog),
		blockedIPs:    make(map[string]BlockedIP),
		attemptCounts: make(map[string]int),
		lastAttempts:  make(map[string][]time.Time),
		stopChan:      make(chan struct{}),
		log: logrus.WithFields(logrus.Fields{
			"component": "security_manager",
		}),
	}
}

// Start 启动安全管理器
func (m *Manager) Start() {
	m.log.Info("启动安全管理器")

	// 加载被封禁的IP列表
	m.loadBlockedIPs()

	// 启动清理任务
	go m.cleanupTask()
}

// Stop 停止安全管理器
func (m *Manager) Stop() {
	m.log.Info("停止安全管理器")
	close(m.stopChan)
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
	if !m.isValidUserAgent(userAgent) {
		m.log.Warnf("可疑的User-Agent: %s from %s", userAgent, ip)
		m.blockIP(ip, "Invalid User-Agent")
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

	// 限制日志数量，只保留最近100条
	if len(m.accessLogs[ip]) > 100 {
		m.accessLogs[ip] = m.accessLogs[ip][len(m.accessLogs[ip])-100:]
	}

	// 如果不是成功访问，检查是否需要封禁
	if !success {
		m.checkAndBlock(ip)
	}
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

	// 保存到文件
	m.saveBlockedIPs()

	m.log.Warnf("封禁IP %s: %s", ip, reason)
}

// isValidUserAgent 检查User-Agent是否合法
func (m *Manager) isValidUserAgent(userAgent string) bool {
	// 空User-Agent不合法
	if userAgent == "" {
		return false
	}

	// 检查是否包含允许的User-Agent前缀
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
		m.log.Errorf("打开封禁文件失败: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var blocked BlockedIP
		if err := json.Unmarshal(scanner.Bytes(), &blocked); err != nil {
			m.log.Errorf("解析封禁记录失败: %v", err)
			continue
		}

		// 只加载未过期的封禁记录
		if time.Now().Before(blocked.ExpireTime) {
			m.blockedIPs[blocked.IP] = blocked
		}
	}

	m.log.Infof("加载了 %d 个封禁IP记录", len(m.blockedIPs))
}

// saveBlockedIPs 保存被封禁的IP列表
func (m *Manager) saveBlockedIPs() {
	blockFile := m.config.Security.BlockFile

	// 确保目录存在
	dir := filepath.Dir(blockFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		m.log.Errorf("创建封禁文件目录失败: %v", err)
		return
	}

	file, err := os.Create(blockFile)
	if err != nil {
		m.log.Errorf("创建封禁文件失败: %v", err)
		return
	}
	defer file.Close()

	for _, blocked := range m.blockedIPs {
		data, err := json.Marshal(blocked)
		if err != nil {
			m.log.Errorf("序列化封禁记录失败: %v", err)
			continue
		}

		if _, err := file.Write(append(data, '\n')); err != nil {
			m.log.Errorf("写入封禁记录失败: %v", err)
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
