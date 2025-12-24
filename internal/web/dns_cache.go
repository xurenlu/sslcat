package web

import (
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/ssl"
)

// DNSCache DNS缓存管理器
type DNSCache struct {
	cache       map[string]*DNSProviderCache // 提供商名称 -> 缓存数据
	mutex       sync.RWMutex
	sslManager  *ssl.Manager
	stopChan    chan struct{} // 停止定期更新
	ticker      *time.Ticker  // 定期更新的ticker
	updateMutex sync.Mutex    // 保护启动/停止操作
}

// DNSProviderCache DNS提供商缓存数据
type DNSProviderCache struct {
	Domains     []ssl.DomainInfo `json:"domains"`
	DomainCount int              `json:"domain_count"`
	LastUpdate  time.Time        `json:"last_update"`
	Error       string           `json:"error,omitempty"`
	Updating    bool             `json:"updating"`
}

// NewDNSCache 创建DNS缓存管理器
func NewDNSCache(sslManager *ssl.Manager) *DNSCache {
	return &DNSCache{
		cache:      make(map[string]*DNSProviderCache),
		sslManager: sslManager,
	}
}

// GetProviderCache 获取提供商缓存数据
func (c *DNSCache) GetProviderCache(providerName string) *DNSProviderCache {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if cache, exists := c.cache[providerName]; exists {
		return cache
	}

	// 如果缓存不存在，返回空数据
	return &DNSProviderCache{
		Domains:     []ssl.DomainInfo{},
		DomainCount: 0,
		LastUpdate:  time.Time{},
		Error:       "缓存未初始化",
		Updating:    false,
	}
}

// UpdateProviderCache 更新提供商缓存（异步）
func (c *DNSCache) UpdateProviderCache(providerName string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 如果正在更新，跳过
	if cache, exists := c.cache[providerName]; exists && cache.Updating {
		return
	}

	// 标记为正在更新
	c.cache[providerName] = &DNSProviderCache{
		Domains:     []ssl.DomainInfo{},
		DomainCount: 0,
		LastUpdate:  time.Now(),
		Error:       "",
		Updating:    true,
	}

	// 异步更新
	go c.updateProviderCacheAsync(providerName)
}

// updateProviderCacheAsync 异步更新提供商缓存
func (c *DNSCache) updateProviderCacheAsync(providerName string) {
	domains, err := c.sslManager.GetDNSProviderDomains(providerName)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err != nil {
		c.cache[providerName] = &DNSProviderCache{
			Domains:     []ssl.DomainInfo{},
			DomainCount: 0,
			LastUpdate:  time.Now(),
			Error:       err.Error(),
			Updating:    false,
		}
	} else {
		// 只统计 type 为 "domain" 的项（排除 DNS 记录）
		domainCount := 0
		totalCount := len(domains)
		for _, domain := range domains {
			if domain.Type == "domain" {
				domainCount++
			}
		}
		
		c.cache[providerName] = &DNSProviderCache{
			Domains:     domains,
			DomainCount: domainCount,
			LastUpdate:  time.Now(),
			Error:       "",
			Updating:    false,
		}
		
		// 调试信息：如果域名数为0但总记录数不为0，说明可能有问题
		if domainCount == 0 && totalCount > 0 {
			// 记录所有记录类型以便调试
			typeCount := make(map[string]int)
			for _, d := range domains {
				typeCount[d.Type] = typeCount[d.Type] + 1
			}
		}
	}
}

// UpdateAllProvidersCache 更新所有提供商缓存
func (c *DNSCache) UpdateAllProvidersCache(providers []string) {
	for _, providerName := range providers {
		c.UpdateProviderCache(providerName)
	}
}

// GetCacheStatus 获取缓存状态
func (c *DNSCache) GetCacheStatus() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	status := make(map[string]interface{})
	for name, cache := range c.cache {
		status[name] = map[string]interface{}{
			"domain_count": cache.DomainCount,
			"last_update":  cache.LastUpdate,
			"error":        cache.Error,
			"updating":     cache.Updating,
		}
	}

	return status
}

// StartPeriodicUpdate 启动定期更新（线程安全）
func (c *DNSCache) StartPeriodicUpdate(providers []string, interval time.Duration) {
	c.updateMutex.Lock()
	defer c.updateMutex.Unlock()

	// 停止旧的更新任务（如果存在）
	c.stopPeriodicUpdateLocked()

	// 启动新的更新任务
	c.stopChan = make(chan struct{})
	c.ticker = time.NewTicker(interval)

	go func() {
		defer c.ticker.Stop()
		for {
			select {
			case <-c.ticker.C:
				c.UpdateAllProvidersCache(providers)
			case <-c.stopChan:
				return
			}
		}
	}()
}

// StopPeriodicUpdate 停止定期更新（线程安全）
func (c *DNSCache) StopPeriodicUpdate() {
	c.updateMutex.Lock()
	defer c.updateMutex.Unlock()

	c.stopPeriodicUpdateLocked()
}

// stopPeriodicUpdateLocked 停止定期更新（内部方法，假设已持有锁）
func (c *DNSCache) stopPeriodicUpdateLocked() {
	if c.ticker != nil {
		c.ticker.Stop()
		c.ticker = nil
	}
	if c.stopChan != nil {
		close(c.stopChan)
		c.stopChan = nil
	}
}

// IsCacheValid 检查缓存是否有效
func (c *DNSCache) IsCacheValid(providerName string, maxAge time.Duration) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	cache, exists := c.cache[providerName]
	if !exists {
		return false
	}

	return time.Since(cache.LastUpdate) < maxAge && cache.Error == ""
}
