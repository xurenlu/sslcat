package bot

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// WhitelistManager 白名单管理器
type WhitelistManager struct {
	storage *WhitelistStorage
	cache   map[string]*WhitelistEntry // key: "ip:domain"
	logger  *logrus.Entry
	mutex   sync.RWMutex
}

// WhitelistEntry 白名单条目
type WhitelistEntry struct {
	ID              int       `json:"id"`
	IP              string    `json:"ip"`
	Domain          string    `json:"domain"`
	TokenHash       string    `json:"token_hash"`
	AddedAt         time.Time `json:"added_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	VerifiedCount   int       `json:"verified_count"`
	LastVerifiedAt  time.Time `json:"last_verified_at"`
	UserAgentHash   string    `json:"user_agent_hash"`
}

// NewWhitelistManager 创建白名单管理器
func NewWhitelistManager(logger *logrus.Logger, dbPath string) (*WhitelistManager, error) {
	storage, err := NewWhitelistStorage(dbPath)
	if err != nil {
		return nil, err
	}

	wm := &WhitelistManager{
		storage: storage,
		cache:   make(map[string]*WhitelistEntry),
		logger:  logger.WithField("component", "whitelist_manager"),
	}

	// 加载现有白名单到缓存
	if err := wm.loadCache(); err != nil {
		logger.WithError(err).Warn("Failed to load whitelist cache")
	}

	// 启动清理协程
	go wm.cleanupRoutine()

	return wm, nil
}

// Add 添加到白名单
func (wm *WhitelistManager) Add(ip, domain, token string, duration time.Duration) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	expiresAt := time.Now().Add(duration)
	
	entry := &WhitelistEntry{
		IP:             ip,
		Domain:         domain,
		TokenHash:      hashString(token),
		AddedAt:        time.Now(),
		ExpiresAt:      expiresAt,
		VerifiedCount:  1,
		LastVerifiedAt: time.Now(),
		UserAgentHash:  "",
	}

	// 保存到数据库
	if err := wm.storage.Add(entry); err != nil {
		return err
	}

	// 更新缓存
	key := wm.makeKey(ip, domain)
	wm.cache[key] = entry

	wm.logger.WithFields(logrus.Fields{
		"ip":         ip,
		"domain":     domain,
		"expires_at": expiresAt,
	}).Info("Added to whitelist")

	return nil
}

// Remove 从白名单移除
func (wm *WhitelistManager) Remove(ip, domain string) error {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	// 从数据库删除
	if err := wm.storage.Remove(ip, domain); err != nil {
		return err
	}

	// 从缓存删除
	key := wm.makeKey(ip, domain)
	delete(wm.cache, key)

	wm.logger.WithFields(logrus.Fields{
		"ip":     ip,
		"domain": domain,
	}).Info("Removed from whitelist")

	return nil
}

// IsWhitelisted 检查是否在白名单中
func (wm *WhitelistManager) IsWhitelisted(ip, domain string) bool {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	key := wm.makeKey(ip, domain)
	entry, exists := wm.cache[key]

	if !exists {
		return false
	}

	// 检查是否过期
	if time.Now().After(entry.ExpiresAt) {
		// 过期，异步删除
		go wm.Remove(ip, domain)
		return false
	}

	// 更新最后验证时间和计数
	go wm.updateVerification(ip, domain)

	return true
}

// Get 获取白名单条目
func (wm *WhitelistManager) Get(ip, domain string) (*WhitelistEntry, bool) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	key := wm.makeKey(ip, domain)
	entry, exists := wm.cache[key]

	if !exists {
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry, true
}

// List 列出所有白名单条目
func (wm *WhitelistManager) List() ([]*WhitelistEntry, error) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	entries := make([]*WhitelistEntry, 0, len(wm.cache))
	now := time.Now()

	for _, entry := range wm.cache {
		// 只返回未过期的条目
		if now.Before(entry.ExpiresAt) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// ListByDomain 列出指定域名的白名单条目
func (wm *WhitelistManager) ListByDomain(domain string) ([]*WhitelistEntry, error) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	entries := make([]*WhitelistEntry, 0)
	now := time.Now()

	for _, entry := range wm.cache {
		if entry.Domain == domain && now.Before(entry.ExpiresAt) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// Count 获取白名单数量
func (wm *WhitelistManager) Count() int {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()

	count := 0
	now := time.Now()

	for _, entry := range wm.cache {
		if now.Before(entry.ExpiresAt) {
			count++
		}
	}

	return count
}

// updateVerification 更新验证信息
func (wm *WhitelistManager) updateVerification(ip, domain string) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	key := wm.makeKey(ip, domain)
	entry, exists := wm.cache[key]

	if !exists {
		return
	}

	entry.VerifiedCount++
	entry.LastVerifiedAt = time.Now()

	// 更新数据库
	if err := wm.storage.UpdateVerification(ip, domain); err != nil {
		wm.logger.WithError(err).Warn("Failed to update verification in database")
	}
}

// loadCache 加载缓存
func (wm *WhitelistManager) loadCache() error {
	entries, err := wm.storage.List()
	if err != nil {
		return err
	}

	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	for _, entry := range entries {
		// 只加载未过期的条目
		if time.Now().Before(entry.ExpiresAt) {
			key := wm.makeKey(entry.IP, entry.Domain)
			wm.cache[key] = entry
		}
	}

	wm.logger.Infof("Loaded %d entries to whitelist cache", len(wm.cache))

	return nil
}

// cleanupRoutine 定期清理过期条目
func (wm *WhitelistManager) cleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		wm.cleanup()
	}
}

// cleanup 清理过期条目
func (wm *WhitelistManager) cleanup() {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()

	now := time.Now()
	expiredKeys := []string{}

	// 找出过期的条目
	for key, entry := range wm.cache {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// 删除过期条目
	for _, key := range expiredKeys {
		entry := wm.cache[key]
		delete(wm.cache, key)

		// 从数据库删除
		if err := wm.storage.Remove(entry.IP, entry.Domain); err != nil {
			wm.logger.WithError(err).Warn("Failed to remove expired entry from database")
		}
	}

	if len(expiredKeys) > 0 {
		wm.logger.Infof("Cleaned up %d expired whitelist entries", len(expiredKeys))
	}

	// 清理数据库中的过期条目
	if err := wm.storage.CleanupExpired(); err != nil {
		wm.logger.WithError(err).Warn("Failed to cleanup expired entries in database")
	}
}

// makeKey 生成缓存键
func (wm *WhitelistManager) makeKey(ip, domain string) string {
	return ip + ":" + domain
}

// Close 关闭白名单管理器
func (wm *WhitelistManager) Close() error {
	if wm.storage != nil {
		return wm.storage.Close()
	}
	return nil
}

