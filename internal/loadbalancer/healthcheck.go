package loadbalancer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HealthChecker 健康检查器
type HealthChecker struct {
	lb     *LoadBalancer
	client *http.Client
	log    *logrus.Entry

	// 控制健康检查的停止
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewHealthChecker 创建健康检查器
func NewHealthChecker(lb *LoadBalancer) *HealthChecker {
	ctx, cancel := context.WithCancel(context.Background())

	// 创建自定义的HTTP客户端
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 跳过TLS验证，允许自签名证书
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second, // 默认超时
	}

	return &HealthChecker{
		lb:     lb,
		client: client,
		ctx:    ctx,
		cancel: cancel,
		log: logrus.WithFields(logrus.Fields{
			"component": "healthchecker",
		}),
	}
}

// StartHealthCheck 启动健康检查
func (lb *LoadBalancer) StartHealthCheck() {
	if !lb.config.HealthCheckEnabled {
		lb.log.Info("Health check is disabled")
		return
	}

	checker := NewHealthChecker(lb)

	// 设置检查间隔，强制最小间隔为 30 秒，避免过于频繁的健康检查
	interval := lb.config.HealthCheckInterval
	minInterval := 30 * time.Second

	if interval <= 0 {
		interval = 61 * time.Second // 默认 61 秒（质数间隔）
	} else if interval < minInterval {
		lb.log.Warnf("Health check interval %v is too short, using minimum: %v", interval, minInterval)
		interval = minInterval
	}

	lb.log.Infof("Starting health check with interval: %v", interval)

	// 立即进行一次健康检查
	checker.checkAllBackends()

	// 启动定时健康检查
	ticker := time.NewTicker(interval)
	lb.healthCheckTicker = ticker
	lb.healthCheckDone = make(chan bool)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checker.checkAllBackends()
			case <-lb.healthCheckDone:
				lb.log.Info("Health check stopped")
				return
			case <-checker.ctx.Done():
				lb.log.Info("Health check context cancelled")
				return
			}
		}
	}()
}

// StopHealthCheck 停止健康检查
func (lb *LoadBalancer) StopHealthCheck() {
	// 安全关闭 channel，防止重复关闭导致 panic
	if lb.healthCheckDone != nil {
		select {
		case <-lb.healthCheckDone:
			// Already closed
		default:
			close(lb.healthCheckDone)
		}
		lb.healthCheckDone = nil
	}

	if lb.healthCheckTicker != nil {
		lb.healthCheckTicker.Stop()
		lb.healthCheckTicker = nil
	}

	lb.log.Info("Health check stopped")
}

// checkAllBackends 检查所有后端的健康状态
func (hc *HealthChecker) checkAllBackends() {
	backends := hc.lb.GetAllBackends()

	hc.log.Debugf("Checking health of %d backends", len(backends))

	// 限制并发数量，避免一次性启动过多 goroutine 导致 CPU 峰值
	// 最多同时检查 20 个后端
	maxConcurrent := 20
	if len(backends) < maxConcurrent {
		maxConcurrent = len(backends)
	}

	semaphore := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for i := range backends {
		wg.Add(1)
		semaphore <- struct{}{} // 获取信号量

		go func(backend *Backend) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量
			hc.checkBackendHealth(backend)
		}(&backends[i])
	}

	wg.Wait()
	hc.log.Debugf("Health check completed for all backends")
}

// checkBackendHealth 检查单个后端的健康状态
func (hc *HealthChecker) checkBackendHealth(backend *Backend) {
	startTime := time.Now()

	// 如果后端禁用了健康检查，跳过
	if !backend.HealthCheckEnabled {
		hc.log.Debugf("Health check disabled for backend: %s", backend.ID)
		return
	}

	// 设置健康检查超时
	timeout := backend.HealthCheckTimeout
	if timeout <= 0 {
		timeout = hc.lb.config.HealthCheckTimeout
	}
	if timeout <= 0 {
		timeout = 5 * time.Second // 默认5秒
	}

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(hc.ctx, timeout)
	defer cancel()

	// 构建健康检查URL
	healthCheckPath := backend.HealthCheckPath
	if healthCheckPath == "" {
		healthCheckPath = "/" // 默认检查根路径
	}

	url := backend.GetURL(healthCheckPath)

	// 设置HTTP方法
	method := backend.HealthCheckMethod
	if method == "" {
		method = "GET" // 默认GET方法
	}

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		hc.handleHealthCheckFailure(backend, fmt.Errorf("failed to create request: %w", err))
		return
	}

	// 设置User-Agent
	req.Header.Set("User-Agent", "SSLcat-HealthChecker/1.0")

	// 如果配置了TLS服务器名称，设置Host头
	if backend.TLSServerName != "" {
		req.Host = backend.TLSServerName
	}

	// 执行健康检查请求
	resp, err := hc.client.Do(req)
	if err != nil {
		hc.handleHealthCheckFailure(backend, fmt.Errorf("request failed: %w", err))
		return
	}
	defer resp.Body.Close()

	// 检查响应状态码
	expectedStatusCode := backend.ExpectedStatusCode
	if expectedStatusCode == 0 {
		expectedStatusCode = 200 // 默认期望200状态码
	}

	responseTime := time.Since(startTime)
	backend.UpdateResponseTime(responseTime)

	if resp.StatusCode == expectedStatusCode {
		hc.handleHealthCheckSuccess(backend, responseTime)
	} else {
		hc.handleHealthCheckFailure(backend, fmt.Errorf("unexpected status code: %d, expected: %d", resp.StatusCode, expectedStatusCode))
	}
}

// handleHealthCheckSuccess 处理健康检查成功
func (hc *HealthChecker) handleHealthCheckSuccess(backend *Backend, responseTime time.Duration) {
	wasHealthy := backend.IsHealthy()
	backend.LastHealthCheck = time.Now()

	if !wasHealthy {
		// 从不健康状态恢复
		backend.SetHealthy(true)
		hc.log.Infof("Backend %s (%s) recovered, response time: %v",
			backend.ID, backend.GetAddress(), responseTime)

		// 触发健康状态变化回调
		if hc.lb.onHealthChangeCb != nil {
			go hc.lb.onHealthChangeCb(backend, true)
		}
	} else {
		hc.log.Debugf("Backend %s (%s) is healthy, response time: %v",
			backend.ID, backend.GetAddress(), responseTime)
	}
}

// handleHealthCheckFailure 处理健康检查失败
func (hc *HealthChecker) handleHealthCheckFailure(backend *Backend, err error) {
	wasHealthy := backend.IsHealthy()
	backend.LastFailure = time.Now()
	backend.LastHealthCheck = time.Now()
	backend.IncrementFailures()

	if wasHealthy {
		// 从健康状态变为不健康
		backend.SetHealthy(false)
		hc.log.Warnf("Backend %s (%s) marked as unhealthy: %v",
			backend.ID, backend.GetAddress(), err)

		// 触发健康状态变化回调
		if hc.lb.onHealthChangeCb != nil {
			go hc.lb.onHealthChangeCb(backend, false)
		}
	} else {
		hc.log.Debugf("Backend %s (%s) still unhealthy: %v",
			backend.ID, backend.GetAddress(), err)
	}
}

// IsBackendHealthy 检查后端是否健康（同步检查）
func (hc *HealthChecker) IsBackendHealthy(backend *Backend) bool {
	// 创建临时的上下文和客户端进行同步检查
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthCheckPath := backend.HealthCheckPath
	if healthCheckPath == "" {
		healthCheckPath = "/"
	}

	url := backend.GetURL(healthCheckPath)

	method := backend.HealthCheckMethod
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "SSLcat-HealthChecker/1.0")

	if backend.TLSServerName != "" {
		req.Host = backend.TLSServerName
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	expectedStatusCode := backend.ExpectedStatusCode
	if expectedStatusCode == 0 {
		expectedStatusCode = 200
	}

	return resp.StatusCode == expectedStatusCode
}

// TestConnection 测试连接（TCP层面的连接测试）
func (hc *HealthChecker) TestConnection(backend *Backend) error {
	timeout := backend.HealthCheckTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	conn, err := net.DialTimeout("tcp", backend.GetAddress(), timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", backend.GetAddress(), err)
	}
	defer conn.Close()

	return nil
}

// GetHealthStatus 获取所有后端的健康状态
func (hc *HealthChecker) GetHealthStatus() map[string]bool {
	backends := hc.lb.GetAllBackends()
	status := make(map[string]bool)

	for _, backend := range backends {
		status[backend.ID] = backend.IsHealthy()
	}

	return status
}

// ForceHealthCheck 强制执行健康检查
func (hc *HealthChecker) ForceHealthCheck() {
	hc.log.Info("Forcing health check for all backends")
	hc.checkAllBackends()
}

// SetBackendHealth 手动设置后端健康状态（用于测试或紧急情况）
func (hc *HealthChecker) SetBackendHealth(backendID string, healthy bool) error {
	backend, err := hc.lb.GetBackend(backendID)
	if err != nil {
		return err
	}

	wasHealthy := backend.IsHealthy()
	backend.SetHealthy(healthy)

	if wasHealthy != healthy {
		hc.log.Infof("Manually set backend %s health status to: %v", backendID, healthy)

		// 触发健康状态变化回调
		if hc.lb.onHealthChangeCb != nil {
			go hc.lb.onHealthChangeCb(backend, healthy)
		}
	}

	return nil
}
