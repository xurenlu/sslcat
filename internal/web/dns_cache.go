package web

import (
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/ssl"
)

// DNSCache DNS缓存管理器
type DNSCache struct {
	cache      map[string]*DNSProviderCache // 提供商名称 -> 缓存数据
	mutex      sync.RWMutex
	sslManager *ssl.Manager
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
		c.cache[providerName] = &DNSProviderCache{
			Domains:     domains,
			DomainCount: len(domains),
			LastUpdate:  time.Now(),
			Error:       "",
			Updating:    false,
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

// StartPeriodicUpdate 启动定期更新
func (c *DNSCache) StartPeriodicUpdate(providers []string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			c.UpdateAllProvidersCache(providers)
		}
	}()
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
