package cache

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// CacheWarmer 缓存预热器
type CacheWarmer struct {
	urls      []string      // 需要预热的URL列表
	interval  time.Duration // 预热间隔
	log       *logrus.Entry // 日志记录器
	client    *http.Client  // HTTP客户端
	isRunning bool          // 是否正在运行
	mutex     sync.RWMutex  // 并发控制
}

// NewCacheWarmer 创建缓存预热器
func NewCacheWarmer(urls []string, interval time.Duration) *CacheWarmer {
	return &CacheWarmer{
		urls:     urls,
		interval: interval,
		log: logrus.WithFields(logrus.Fields{
			"component": "cache_warmer",
		}),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start 启动缓存预热
func (cw *CacheWarmer) Start(baseURL string) {
	cw.mutex.Lock()
	if cw.isRunning {
		cw.mutex.Unlock()
		cw.log.Warn("Cache warmer is already running")
		return
	}
	cw.isRunning = true
	cw.mutex.Unlock()

	cw.log.Infof("Starting cache warmer for %d URLs", len(cw.urls))

	// 立即预热一次
	cw.warmUp(baseURL)

	// 定时预热
	ticker := time.NewTicker(cw.interval)
	go func() {
		for range ticker.C {
			cw.mutex.RLock()
			running := cw.isRunning
			cw.mutex.RUnlock()

			if !running {
				ticker.Stop()
				return
			}

			cw.warmUp(baseURL)
		}
	}()
}

// Stop 停止缓存预热
func (cw *CacheWarmer) Stop() {
	cw.mutex.Lock()
	defer cw.mutex.Unlock()

	if !cw.isRunning {
		return
	}

	cw.isRunning = false
	cw.log.Info("Cache warmer stopped")
}

// warmUp 执行预热
func (cw *CacheWarmer) warmUp(baseURL string) {
	if len(cw.urls) == 0 {
		return
	}

	cw.log.Debugf("Starting cache warmup for %d URLs", len(cw.urls))

	successCount := 0
	failCount := 0

	// 并发预热（最多5个并发）
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, urlPath := range cw.urls {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()

			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := cw.warmCache(baseURL, path); err != nil {
				cw.log.Debugf("Failed to warm cache for %s: %v", path, err)
				failCount++
			} else {
				successCount++
			}
		}(urlPath)
	}

	wg.Wait()

	cw.log.Infof("Cache warmup completed: %d success, %d failed", successCount, failCount)
}

// warmCache 预热单个URL
func (cw *CacheWarmer) warmCache(baseURL, path string) error {
	// 构建完整URL
	fullURL, err := url.JoinPath(baseURL, path)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// 创建请求
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// 设置Accept-Encoding头以触发压缩
	req.Header.Set("Accept-Encoding", "gzip, br")
	req.Header.Set("Accept", "*/*")

	// 发送请求
	resp, err := cw.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return nil
}

// AddURL 添加需要预热的URL
func (cw *CacheWarmer) AddURL(url string) {
	cw.mutex.Lock()
	defer cw.mutex.Unlock()

	// 检查是否已存在
	for _, existingURL := range cw.urls {
		if existingURL == url {
			return
		}
	}

	cw.urls = append(cw.urls, url)
	cw.log.Debugf("Added URL to warmup list: %s", url)
}

// RemoveURL 移除URL
func (cw *CacheWarmer) RemoveURL(url string) {
	cw.mutex.Lock()
	defer cw.mutex.Unlock()

	for i, existingURL := range cw.urls {
		if existingURL == url {
			cw.urls = append(cw.urls[:i], cw.urls[i+1:]...)
			cw.log.Debugf("Removed URL from warmup list: %s", url)
			return
		}
	}
}

// GetURLs 获取当前预热的URL列表
func (cw *CacheWarmer) GetURLs() []string {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()

	urls := make([]string, len(cw.urls))
	copy(urls, cw.urls)
	return urls
}
