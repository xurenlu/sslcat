package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xurenlu/sslcat/internal/cache"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/loadbalancer"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"

	"github.com/sirupsen/logrus"
)

// contextKey 类型安全的 context key
type contextKey string

const (
	proxyRuleKey      contextKey = "proxyRule"
	proxyBackendKey   contextKey = "proxyBackend"
	proxyStartTimeKey contextKey = "proxyStartTime"
	cdnEnabledKey     contextKey = "cdnEnabled"
)

// loggingTransport 包装Transport以记录实际发送的请求
type loggingTransport struct {
	base   http.RoundTripper
	log    *logrus.Entry
	config *config.Config
}

// ResponseProcessor 响应处理器接口
type ResponseProcessor interface {
	ProcessResponse(data []byte, contentType string, r *http.Request) ([]byte, string, error)
}

// Manager 代理管理器
type Manager struct {
	config          *config.Config
	sslManager      *ssl.Manager
	securityManager *security.Manager
	proxyCache      map[string]*httputil.ReverseProxy
	cacheMutex      sync.RWMutex
	cdnCache        *cache.CDNCache
	upstreamCache   *cache.UpstreamCache
	log             *logrus.Entry
	version         string

	// 负载均衡器
	loadBalancers map[string]loadbalancer.BalancerInterface // domain -> load balancer
	lbMutex       sync.RWMutex
	lbFactory     *loadbalancer.BalancerFactory

	// 响应处理器（可选，用于图片优化等）
	responseProcessor ResponseProcessor

	// 慢请求记录器
	slowRequestRecorder SlowRequestRecorder

	// 性能优化：buffer 池，复用 WebSocket 和 copyData 的缓冲区
	bufferPool *sync.Pool

	// 性能优化：header key 规范化缓存，避免重复转换
	headerKeyCache map[string]string
	headerKeyMutex sync.RWMutex

	// 性能优化：header map 对象池，复用 map[string]string 对象
	headerMapPool *sync.Pool
}

// NewManager 创建代理管理器
func NewManager(cfg *config.Config, sslMgr *ssl.Manager, secMgr *security.Manager, cdn *cache.CDNCache, version string) *Manager {
	manager := &Manager{
		config:              cfg,
		sslManager:          sslMgr,
		securityManager:     secMgr,
		proxyCache:          make(map[string]*httputil.ReverseProxy),
		cdnCache:            cdn,
		upstreamCache:       cache.NewUpstreamCache(cfg),
		version:             version,
		loadBalancers:       make(map[string]loadbalancer.BalancerInterface),
		lbFactory:           loadbalancer.NewBalancerFactory(),
		slowRequestRecorder: &NoOpSlowRequestRecorder{}, // 默认使用空操作记录器
		log: logrus.WithFields(logrus.Fields{
			"component": "proxy_manager",
		}),
		// 性能优化：初始化 buffer 池，复用 32KB 缓冲区
		// 这样可以减少内存分配和 GC 压力，特别是在高并发 WebSocket 场景下
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024) // 32KB buffer
			},
		},
		// 性能优化：初始化 header key 缓存
		headerKeyCache: make(map[string]string),
		// 性能优化：初始化 header map 对象池，复用 map[string]string 对象
		// 预分配容量为 8，适合大多数 header 数量场景
		headerMapPool: &sync.Pool{
			New: func() interface{} {
				return make(map[string]string, 8)
			},
		},
	}

	// 初始化负载均衡器
	manager.initializeLoadBalancers()

	return manager
}

// SetSlowRequestRecorder 设置慢请求记录器
func (m *Manager) SetSlowRequestRecorder(recorder SlowRequestRecorder) {
	m.slowRequestRecorder = recorder
}

// getCanonicalHeaderKey 获取规范化后的 header key（带缓存）
func (m *Manager) getCanonicalHeaderKey(key string) string {
	// 先检查缓存
	m.headerKeyMutex.RLock()
	if canonical, exists := m.headerKeyCache[key]; exists {
		m.headerKeyMutex.RUnlock()
		return canonical
	}
	m.headerKeyMutex.RUnlock()

	// 缓存未命中，规范化并缓存
	canonical := http.CanonicalHeaderKey(key)
	m.headerKeyMutex.Lock()
	// 限制缓存大小，避免内存泄漏（最多缓存1000个key）
	if len(m.headerKeyCache) < 1000 {
		m.headerKeyCache[key] = canonical
	}
	m.headerKeyMutex.Unlock()

	return canonical
}

// deleteHeadersIfExist 批量删除 header（只在存在时删除，减少无效操作）
func (m *Manager) deleteHeadersIfExist(headers http.Header, keys []string) {
	for _, key := range keys {
		// 使用规范化后的 key 检查是否存在（避免 headers.Del 内部的重复规范化）
		canonicalKey := m.getCanonicalHeaderKey(key)
		if _, exists := headers[canonicalKey]; exists {
			// 直接使用规范化后的 key 删除，避免 headers.Del 再次规范化
			delete(headers, canonicalKey)
		}
	}
}

// deleteHeadersBatch 批量删除 header（不检查是否存在，用于确定需要删除的场景）
func (m *Manager) deleteHeadersBatch(headers http.Header, keys []string) {
	// 使用规范化后的 key 直接删除，避免 headers.Del 内部的规范化开销
	for _, key := range keys {
		canonicalKey := m.getCanonicalHeaderKey(key)
		delete(headers, canonicalKey)
	}
}

// getHeaderMap 从对象池获取 header map
func (m *Manager) getHeaderMap() map[string]string {
	return m.headerMapPool.Get().(map[string]string)
}

// putHeaderMap 归还 header map 到对象池
func (m *Manager) putHeaderMap(headerMap map[string]string) {
	// 清空 map 但保留容量
	for k := range headerMap {
		delete(headerMap, k)
	}
	m.headerMapPool.Put(headerMap)
}

// setHeadersBatch 批量设置 header
func (m *Manager) setHeadersBatch(headers http.Header, headerMap map[string]string) {
	for key, value := range headerMap {
		if value == "" {
			headers.Del(key)
		} else {
			headers.Set(key, value)
		}
	}
}

// setHeadersBatchFromPool 批量设置 header（使用对象池）
// 这个函数内部使用对象池获取 map，使用完后自动归还
func (m *Manager) setHeadersBatchFromPool(headers http.Header, fn func(map[string]string)) {
	headerMap := m.getHeaderMap()
	defer m.putHeaderMap(headerMap)
	
	// 调用回调函数填充 map
	fn(headerMap)
	
	// 批量设置 header
	m.setHeadersBatch(headers, headerMap)
}

// SetResponseProcessor 设置响应处理器
func (m *Manager) SetResponseProcessor(processor ResponseProcessor) {
	m.responseProcessor = processor
}

// Start 启动代理管理器
func (m *Manager) Start() error {
	m.log.Info("Starting proxy manager")

	// 启动上游缓存清理器
	if m.upstreamCache != nil {
		m.upstreamCache.StartCleaner()
		m.log.Info("Started upstream cache cleaner")
	}

	return nil
}

// Stop 停止代理管理器
func (m *Manager) Stop() {
	m.log.Info("Stopping proxy manager")

	// 停止所有负载均衡器的健康检查
	m.lbMutex.RLock()
	for _, lb := range m.loadBalancers {
		lb.StopHealthCheck()
	}
	m.lbMutex.RUnlock()
	
	// 停止缓存清理器
	if m.upstreamCache != nil {
		m.upstreamCache.StopCleaner()
		m.log.Info("Stopped upstream cache cleaner")
	}
	if m.cdnCache != nil {
		m.cdnCache.StopCleaner()
		m.log.Info("Stopped CDN cache cleaner")
	}
	
	m.log.Info("Proxy manager stopped")
}

// initializeLoadBalancers 初始化负载均衡器
func (m *Manager) initializeLoadBalancers() {
	for _, rule := range m.config.Proxy.Rules {
		if rule.LoadBalancerEnabled && len(rule.LoadBalancerBackends) > 0 {
			if err := m.createLoadBalancer(&rule); err != nil {
				m.log.Errorf("Failed to create load balancer for domain %s: %v", rule.Domain, err)
			}
		}
	}
}

// createLoadBalancer 为指定域名创建负载均衡器
func (m *Manager) createLoadBalancer(rule *config.ProxyRule) error {
	// 使用统一的后端配置
	effectiveBackends := rule.GetEffectiveBackends()

	// 转换配置格式
	var backends []loadbalancer.Backend
	for i, proxyBackend := range effectiveBackends {
		if !proxyBackend.Enabled {
			continue
		}

		backend := loadbalancer.Backend{
			ID:       proxyBackend.ID,
			Host:     proxyBackend.Host,
			Port:     proxyBackend.Port,
			Weight:   proxyBackend.Weight,
			Priority: proxyBackend.Priority,

			// 健康检查配置
			HealthCheckEnabled:  rule.HealthCheckEnabled || proxyBackend.HealthCheckEnabled,
			HealthCheckPath:     m.getHealthCheckPath(rule, &proxyBackend),
			HealthCheckInterval: m.getDuration(rule.HealthCheckInterval, proxyBackend.HealthCheckInterval, 30),
			HealthCheckTimeout:  m.getDuration(rule.HealthCheckTimeout, proxyBackend.HealthCheckTimeout, 5),
			HealthCheckMethod:   m.getHealthCheckMethod(rule, &proxyBackend),
			ExpectedStatusCode:  m.getExpectedStatusCode(rule, &proxyBackend),

			// 连接配置
			MaxConnections:      proxyBackend.MaxConnections,
			ConnectTimeout:      m.getDuration(0, proxyBackend.ConnectTimeout, 30),
			ReadTimeout:         m.getDuration(0, proxyBackend.ReadTimeout, 30),
			WriteTimeout:        m.getDuration(0, proxyBackend.WriteTimeout, 30),
			KeepAliveTimeout:    m.getDuration(0, proxyBackend.KeepAliveTimeout, 30),
			TLSHandshakeTimeout: time.Duration(10) * time.Second,

			// SSL/TLS配置
			TLSEnabled:    proxyBackend.TLSEnabled,
			TLSInsecure:   proxyBackend.TLSInsecure,
			TLSServerName: proxyBackend.TLSServerName,

			// 故障转移配置
			MaxRetries:        m.getInt(rule.MaxRetries, proxyBackend.MaxRetries, 3),
			RetryInterval:     m.getDuration(rule.RetryInterval, proxyBackend.RetryInterval, 1),
			FailureThreshold:  m.getInt(rule.FailureThreshold, proxyBackend.FailureThreshold, 3),
			RecoveryThreshold: m.getInt(rule.RecoveryThreshold, proxyBackend.RecoveryThreshold, 2),

			// 元数据
			Metadata: proxyBackend.Metadata,
		}

		// 设置默认ID
		if backend.ID == "" {
			backend.ID = fmt.Sprintf("%s_backend_%d", rule.Domain, i)
		}

		// 设置默认权重
		if backend.Weight <= 0 {
			backend.Weight = 1
		}

		backends = append(backends, backend)
	}

	if len(backends) == 0 {
		return fmt.Errorf("no enabled backends found for domain %s", rule.Domain)
	}

	// 创建负载均衡器配置
	algorithm := loadbalancer.Algorithm(rule.LoadBalancerAlgorithm)
	if algorithm == "" {
		algorithm = loadbalancer.RoundRobin
	}

	lbConfig := loadbalancer.LoadBalancerConfig{
		Algorithm:           algorithm,
		Backends:            backends,
		HealthCheckEnabled:  rule.HealthCheckEnabled,
		HealthCheckInterval: time.Duration(rule.HealthCheckInterval) * time.Second,
		HealthCheckTimeout:  time.Duration(rule.HealthCheckTimeout) * time.Second,

		// 会话保持配置
		SessionAffinityEnabled: rule.SessionAffinityEnabled,
		SessionAffinityMethod:  rule.SessionAffinityMethod,
		SessionAffinityCookie:  rule.SessionAffinityCookie,
		SessionAffinityHeader:  rule.SessionAffinityHeader,
		SessionAffinityTTL:     rule.SessionAffinityTTL,

		// 故障转移配置
		FailoverEnabled: rule.FailoverEnabled,
		MaxRetries:      rule.MaxRetries,
		RetryInterval:   time.Duration(rule.RetryInterval) * time.Second,
	}

	// 创建负载均衡器
	lb, err := m.lbFactory.CreateBalancer(lbConfig)
	if err != nil {
		return fmt.Errorf("failed to create load balancer: %w", err)
	}

	// 设置事件回调
	lb.OnBackendHealthChange(func(backend *loadbalancer.Backend, isHealthy bool) {
		status := "unhealthy"
		if isHealthy {
			status = "healthy"
		}
		m.log.Infof("Backend %s (%s:%d) for domain %s is now %s",
			backend.ID, backend.Host, backend.Port, rule.Domain, status)
	})

	// 存储负载均衡器
	m.lbMutex.Lock()
	m.loadBalancers[rule.Domain] = lb
	m.lbMutex.Unlock()

	m.log.Infof("Created load balancer for domain %s with %d backends using %s algorithm",
		rule.Domain, len(backends), algorithm)

	return nil
}

// 辅助方法
func (m *Manager) getHealthCheckPath(rule *config.ProxyRule, backend *config.ProxyBackend) string {
	if backend.HealthCheckPath != "" {
		return backend.HealthCheckPath
	}
	if rule.HealthCheckPath != "" {
		return rule.HealthCheckPath
	}
	return "/"
}

func (m *Manager) getHealthCheckMethod(rule *config.ProxyRule, backend *config.ProxyBackend) string {
	if backend.HealthCheckMethod != "" {
		return backend.HealthCheckMethod
	}
	if rule.HealthCheckMethod != "" {
		return rule.HealthCheckMethod
	}
	return "GET"
}

func (m *Manager) getExpectedStatusCode(rule *config.ProxyRule, backend *config.ProxyBackend) int {
	if backend.ExpectedStatusCode > 0 {
		return backend.ExpectedStatusCode
	}
	if rule.ExpectedStatusCode > 0 {
		return rule.ExpectedStatusCode
	}
	return 200
}

func (m *Manager) getDuration(ruleValue, backendValue, defaultValue int) time.Duration {
	if backendValue > 0 {
		return time.Duration(backendValue) * time.Second
	}
	if ruleValue > 0 {
		return time.Duration(ruleValue) * time.Second
	}
	return time.Duration(defaultValue) * time.Second
}

func (m *Manager) getInt(ruleValue, backendValue, defaultValue int) int {
	if backendValue > 0 {
		return backendValue
	}
	if ruleValue > 0 {
		return ruleValue
	}
	return defaultValue
}

// handleLoadBalancedRequest 处理负载均衡请求
func (m *Manager) handleLoadBalancedRequest(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 获取负载均衡器
	m.lbMutex.RLock()
	lb, exists := m.loadBalancers[rule.Domain]
	m.lbMutex.RUnlock()

	if !exists {
		m.log.Errorf("Load balancer not found for domain: %s", rule.Domain)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	// 选择后端服务器
	backend, err := lb.SelectBackend(r)
	if err != nil {
		m.log.Errorf("Failed to select backend for domain %s: %v", rule.Domain, err)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	m.log.Infof("Selected backend %s (%s:%d) for request to %s",
		backend.ID, backend.Host, backend.Port, rule.Domain)

	// 创建临时的ProxyRule用于传统代理逻辑
	tempRule := *rule
	tempRule.Target = backend.Host
	tempRule.Port = backend.Port
	tempRule.LoadBalancerEnabled = false // 避免递归

	// 记录后端选择
	r.Header.Set("X-Selected-Backend", backend.ID)
	r.Header.Set("X-Backend-Address", backend.GetAddress())

	// 使用传统的代理逻辑处理请求
	m.proxyToBackend(w, r, &tempRule, backend)
}

// proxyToBackend 代理请求到指定后端
func (m *Manager) proxyToBackend(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule, backend *loadbalancer.Backend) {
	startTime := time.Now()

	// 上游缓存检查（仅对GET/HEAD请求）
	if m.upstreamCache != nil && (r.Method == "GET" || r.Method == "HEAD") {
		if m.upstreamCache.Serve(w, r) {
			m.log.Debugf("Served from upstream cache for %s %s", r.Method, r.URL.Path)
			return
		}
	}

	// CDN 缓存直出（仅 GET/HEAD，且全局或域名启用）
	cdnEnabled := m.config.CDNCache.Enabled || (rule != nil && rule.CDNEnabled)
	if m.cdnCache != nil && cdnEnabled {
		// 临时修改请求Host为后端域名，确保缓存路径一致性
		originalHost := r.Host
		if rule != nil {
			backendHost := m.extractHostFromTarget(rule.Target, rule.Port)
			r.Host = backendHost
		}
		served := m.cdnCache.ServeIfFreshWithConfig(w, r, cdnEnabled)
		// 恢复原始Host
		r.Host = originalHost
		if served {
			m.log.Debugf("Served from CDN cache for %s %s", r.Method, r.URL.Path)
			return
		}
	}

	// 获取或创建反向代理
	proxy := m.getOrCreateProxy(rule)
	if proxy == nil {
		backend.IncrementFailures()
		http.Error(w, "Failed to create proxy", http.StatusInternalServerError)
		return
	}

	// 获取真实客户端IP
	clientIP := m.getClientIP(r)

	// 透明代理 - 正确设置所有必要的头部
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	// 检查是否启用了CDN缓存（全局或域名级别）
	isCloudStorage := m.isCloudStorageService(rule.Target)

	// 保存追踪头部（在清理其他头部之前）
	traceHeaders := m.ExtractTraceHeaders(r)

	// 在CDN模式或云存储模式下，预先清理可能存在的代理头部
	// 性能优化：使用批量删除，减少函数调用和规范化开销
	if cdnEnabled || isCloudStorage {
		// 基础代理头部列表
		proxyHeaders := []string{
			"X-Forwarded-For",
			"X-Forwarded-Host",
			"X-Forwarded-Proto",
			"X-Forwarded-Port",
			"X-Real-IP",
			"X-Forwarded-Server",
			"X-Original-URI",
			"X-Original-Method",
		}
		m.deleteHeadersIfExist(r.Header, proxyHeaders)

		// 对于云服务，进行更彻底的头部清理
		if isCloudStorage {
			cloudHeaders := []string{
				"X-Forwarded",
				"X-Client-IP",
				"X-Cluster-Client-IP",
				"Forwarded-For",
				"Forwarded",
				"CF-Connecting-IP",
			}
			m.deleteHeadersIfExist(r.Header, cloudHeaders)

			// 处理可能导致防盗链问题的Referer
			if referer := r.Header.Get("Referer"); referer != "" && strings.Contains(referer, "local.") {
				r.Header.Del("Referer")
				m.log.Debugf("Pre-removed local Referer for cloud service: %s", referer)
			}
		}

		m.log.Debugf("Pre-cleaned proxy headers for %s (CDN: %v, 云服务: %v)", r.Host, cdnEnabled, isCloudStorage)
	}

	if !cdnEnabled && !isCloudStorage {
		// 非CDN且非云服务模式：设置标准的代理头部
		// 性能优化：批量设置 header，减少函数调用
		port := m.getPort(r)
		proxyHeaders := map[string]string{
			"X-Forwarded-Proto": scheme,
			"X-Forwarded-Host":  r.Host,
			"X-Forwarded-Port":  port,
			"X-Real-IP":         clientIP,
		}
		m.setHeadersBatch(r.Header, proxyHeaders)

		// 处理自定义上游请求头部
		if len(rule.UpstreamRequestHeaders) > 0 {
			// 使用对象池优化：从对象池获取 map，使用后归还
			upstreamHeaders := m.getHeaderMap()
			defer m.putHeaderMap(upstreamHeaders)
			for key, value := range rule.UpstreamRequestHeaders {
				trimmedKey := strings.TrimSpace(key)
				if trimmedKey != "" {
					upstreamHeaders[trimmedKey] = value
				}
			}
			m.setHeadersBatch(r.Header, upstreamHeaders)
		}

		// 正确处理 X-Forwarded-For 链
		if existing := r.Header.Get("X-Forwarded-For"); existing != "" {
			r.Header.Set("X-Forwarded-For", existing+", "+clientIP)
		} else {
			r.Header.Set("X-Forwarded-For", clientIP)
		}

		// 设置原始请求信息
		originalHeaders := map[string]string{
			"X-Forwarded-Server": "sslcat",
			"X-Original-URI":      r.RequestURI,
			"X-Original-Method":   r.Method,
		}
		m.setHeadersBatch(r.Header, originalHeaders)

		m.log.Debugf("Added proxy headers (non-CDN, non-cloud mode) for %s", r.Host)
	}

	// 重新注入追踪头部（确保追踪信息传递到上游）
	m.InjectTraceHeaders(r, traceHeaders)

	// 执行代理
	// 在 ModifyResponse 中做缓存落盘（全局或域名启用）
	// 修复：避免重复设置 ModifyResponse，防止递归调用链
	// 如果 ModifyResponse 已经被设置过，使用 context 传递请求特定信息
	if proxy.ModifyResponse == nil {
		// 只在第一次设置 ModifyResponse
		proxy.ModifyResponse = func(resp *http.Response) error {
			// 从 context 获取请求特定信息
			ctx := resp.Request.Context()
			ruleFromCtx, _ := ctx.Value(proxyRuleKey).(*config.ProxyRule)
			backendFromCtx, _ := ctx.Value(proxyBackendKey).(*loadbalancer.Backend)
			startTimeFromCtx, _ := ctx.Value(proxyStartTimeKey).(time.Time)
			cdnEnabledFromCtx, _ := ctx.Value(cdnEnabledKey).(bool)

			// 验证关键信息是否存在
			if ruleFromCtx == nil {
				m.log.Warnf("proxyRule not found in context, this should not happen for request %s %s", resp.Request.Method, resp.Request.URL.Path)
			}
			if backendFromCtx == nil {
				m.log.Warnf("proxyBackend not found in context, this should not happen for request %s %s", resp.Request.Method, resp.Request.URL.Path)
			}

			// 计算响应时间
			var responseTime time.Duration
			if !startTimeFromCtx.IsZero() {
				responseTime = time.Since(startTimeFromCtx)
			}

			// 更新后端响应时间
			if backendFromCtx != nil {
				backendFromCtx.UpdateResponseTime(responseTime)
			}

			// 记录响应详情
			m.logResponseDetails(resp, ruleFromCtx)

			// 检查并记录慢请求
			if m.slowRequestRecorder.IsSlowRequest(responseTime) {
				// 获取内容大小
				contentSize := int64(0)
				if resp.ContentLength > 0 {
					contentSize = resp.ContentLength
				}

				// 获取规则名称（使用Domain作为规则名）
				ruleName := ""
				if ruleFromCtx != nil {
					ruleName = ruleFromCtx.Domain
				}

				// 记录慢请求
				if backendFromCtx != nil && ruleFromCtx != nil {
					m.slowRequestRecorder.RecordSlowRequest(
						resp.Request,
						resp.StatusCode,
						responseTime,
						backendFromCtx.ID,
						backendFromCtx.GetAddress(),
						ruleFromCtx.Target,
						ruleName,
						contentSize,
						nil, // 这里可以传递错误信息
					)
				}
			}

			// 移除可能的安全头，让目标服务器自己设置
			// 性能优化：批量删除
			securityHeaders := []string{
				"Strict-Transport-Security",
				"X-Frame-Options",
				"X-Content-Type-Options",
			}
			m.deleteHeadersBatch(resp.Header, securityHeaders)

			// 添加代理标识和后端信息
			resp.Header.Set("X-Proxy-By", "SSLcat/"+m.version)

			// 处理自定义响应头部
			if ruleFromCtx != nil && len(ruleFromCtx.ResponseHeaders) > 0 {
				// 使用对象池优化：从对象池获取 map，使用后归还
				responseHeaders := m.getHeaderMap()
				defer m.putHeaderMap(responseHeaders)
				for key, value := range ruleFromCtx.ResponseHeaders {
					trimmedKey := strings.TrimSpace(key)
					if trimmedKey != "" {
						responseHeaders[trimmedKey] = value
					}
				}
				m.setHeadersBatch(resp.Header, responseHeaders)
			}

			// 设置后端信息
			if backendFromCtx != nil {
				backendHeaders := map[string]string{
					"X-Backend-ID":      backendFromCtx.ID,
					"X-Backend-Address": backendFromCtx.GetAddress(),
					"X-Response-Time":    responseTime.String(),
				}
				m.setHeadersBatch(resp.Header, backendHeaders)
			}

			// 上游缓存存储（仅对GET/HEAD请求的静态资源）
			if m.upstreamCache != nil && (resp.Request.Method == "GET" || resp.Request.Method == "HEAD") {
				// 异步存储到上游缓存，避免影响响应性能
				go func() {
					if err := m.upstreamCache.Store(resp.Request, resp); err != nil {
						m.log.Debugf("Failed to store upstream cache for %s: %v", resp.Request.URL.String(), err)
					}
				}()
			}

			// CDN 缓存落盘（全局或域名启用）
			if m.cdnCache != nil && cdnEnabledFromCtx {
				if ruleFromCtx != nil && ruleFromCtx.CDNDefaultTTLSeconds > 0 {
					resp.Header.Set("X-SSLcat-CDN-Default-TTL", strconv.Itoa(ruleFromCtx.CDNDefaultTTLSeconds))
				}
				// 临时修改请求Host为后端域名，确保缓存路径一致性
				originalHost := resp.Request.Host
				if ruleFromCtx != nil {
					backendHost := m.extractHostFromTarget(ruleFromCtx.Target, ruleFromCtx.Port)
					resp.Request.Host = backendHost
				}
				m.cdnCache.MaybeStoreWithConfig(resp, cdnEnabledFromCtx)
				// 恢复原始Host
				resp.Request.Host = originalHost
				if ruleFromCtx != nil {
					resp.Header.Del("X-SSLcat-CDN-Default-TTL")
				}
			}

			return nil
		}
	}

	// 将请求特定信息放入 context
	ctx := r.Context()
	ctx = context.WithValue(ctx, proxyRuleKey, rule)
	ctx = context.WithValue(ctx, proxyBackendKey, backend)
	ctx = context.WithValue(ctx, proxyStartTimeKey, startTime)
	ctx = context.WithValue(ctx, cdnEnabledKey, cdnEnabled)
	r = r.WithContext(ctx)

	// 设置错误处理
	// 修复：避免重复设置 ErrorHandler，防止递归调用链
	if proxy.ErrorHandler == nil {
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			// 从 context 获取后端信息
			ctx := r.Context()
			backendFromCtx, _ := ctx.Value(proxyBackendKey).(*loadbalancer.Backend)

			if backendFromCtx != nil {
				backendFromCtx.IncrementFailures()
				backendFromCtx.DecrementConnections() // 确保连接计数正确
				m.log.Errorf("Proxy error to backend %s (%s): %v", backendFromCtx.ID, backendFromCtx.GetAddress(), err)

				// 默认错误处理
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprintf(w, `
				<html>
				<head><title>Proxy Error</title></head>
				<body>
					<h1>502 Bad Gateway</h1>
					<p>Unable to connect to backend %s (%s)</p>
					<p>Error: %v</p>
					<hr>
					<p><small>Powered by sslcat-%s</small></p>
				</body>
				</html>
				`, backendFromCtx.ID, backendFromCtx.GetAddress(), err, m.version)
			} else {
				// 如果没有后端信息，使用通用错误处理
				m.log.Errorf("Proxy error: %v", err)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprintf(w, `
				<html>
				<head><title>Proxy Error</title></head>
				<body>
					<h1>502 Bad Gateway</h1>
					<p>Unable to connect to upstream server</p>
					<p>Error: %v</p>
					<hr>
					<p><small>Powered by sslcat-%s</small></p>
				</body>
				</html>
				`, err, m.version)
			}
		}
	}

	// 执行代理请求
	proxy.ServeHTTP(w, r)

	// 请求完成后减少连接计数
	backend.DecrementConnections()
}

// PurgeCDN 清理 CDN 缓存
func (m *Manager) PurgeCDN(matchType, pattern, mediaCSV string) error {
	if m.cdnCache == nil {
		return nil
	}
	if matchType == "" || strings.EqualFold(matchType, "all") {
		return m.cdnCache.PurgeAll()
	}
	return m.cdnCache.PurgeByCondition(matchType, pattern, mediaCSV)
}

// PurgeUpstreamCache 清理上游缓存
func (m *Manager) PurgeUpstreamCache(pattern string) error {
	if m.upstreamCache == nil {
		return fmt.Errorf("upstream cache not enabled")
	}

	if pattern == "" || pattern == "all" {
		return m.upstreamCache.PurgeAll()
	}

	return m.upstreamCache.PurgeByPattern(pattern)
}

// GetUpstreamCacheStats 获取上游缓存统计信息
func (m *Manager) GetUpstreamCacheStats() map[string]interface{} {
	if m.upstreamCache == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	return m.upstreamCache.GetStats()
}

// GetProxyConfig 获取指定域名的代理配置
func (m *Manager) GetProxyConfig(domain string) *config.ProxyRule {
	return m.config.GetProxyRule(domain)
}

// GetCDNCache 返回缓存器（只读访问）
func (m *Manager) GetCDNCache() interface{ Stats() map[string]any } {
	return m.cdnCache
}

// ProxyRequest 代理请求
func (m *Manager) ProxyRequest(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 检查是否为WebSocket升级请求
	if m.isWebSocketUpgrade(r) {
		m.log.Infof("Detected WebSocket upgrade request for %s", r.Host)
		m.HandleWebSocketOptimized(w, r, rule)
		return
	}

	// 记录原始请求信息
	m.logRequestDetails(r, "INCOMING_REQUEST", rule)

	// 检查是否启用负载均衡（基于后端数量自动判断）
	if rule.IsLoadBalanced() {
		m.handleLoadBalancedRequest(w, r, rule)
		return
	}

	// CDN 缓存直出（仅 GET/HEAD，且全局或域名启用）
	cdnEnabled := m.config.CDNCache.Enabled || (rule != nil && rule.CDNEnabled)
	if m.cdnCache != nil && cdnEnabled {
		// 临时修改请求Host为后端域名，确保缓存路径一致性
		originalHost := r.Host
		if rule != nil {
			backendHost := m.extractHostFromTarget(rule.Target, rule.Port)
			r.Host = backendHost
		}
		served := m.cdnCache.ServeIfFreshWithConfig(w, r, cdnEnabled)
		// 恢复原始Host
		r.Host = originalHost
		if served {
			m.log.Debugf("Served from CDN cache for %s %s", r.Method, r.URL.Path)
			return
		}
	}
	// 获取或创建反向代理
	proxy := m.getOrCreateProxy(rule)

	// 获取真实客户端IP
	clientIP := m.getClientIP(r)

	// 透明代理 - 正确设置所有必要的头部
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	// 检查是否启用了CDN缓存（全局或域名级别）
	// cdnEnabled 已在上面定义
	isCloudStorage := m.isCloudStorageService(rule.Target)

	// 在CDN模式或云存储模式下，预先清理可能存在的代理头部
	// 性能优化：使用批量删除，减少函数调用和规范化开销
	if cdnEnabled || isCloudStorage {
		// 基础代理头部列表
		proxyHeaders := []string{
			"X-Forwarded-For",
			"X-Forwarded-Host",
			"X-Forwarded-Proto",
			"X-Forwarded-Port",
			"X-Real-IP",
			"X-Forwarded-Server",
			"X-Original-URI",
			"X-Original-Method",
		}
		m.deleteHeadersIfExist(r.Header, proxyHeaders)

		// 对于云服务，进行更彻底的头部清理
		if isCloudStorage {
			cloudHeaders := []string{
				"X-Forwarded",
				"X-Client-IP",
				"X-Cluster-Client-IP",
				"Forwarded-For",
				"Forwarded",
				"CF-Connecting-IP",
			}
			m.deleteHeadersIfExist(r.Header, cloudHeaders)

			// 处理可能导致防盗链问题的Referer
			if referer := r.Header.Get("Referer"); referer != "" && strings.Contains(referer, "local.") {
				r.Header.Del("Referer")
				m.log.Debugf("Pre-removed local Referer for cloud service: %s", referer)
			}
		}

		m.log.Debugf("Pre-cleaned proxy headers for %s (CDN: %v, 云服务: %v)", r.Host, cdnEnabled, isCloudStorage)
	}

	if !cdnEnabled && !isCloudStorage {
		// 非CDN且非云服务模式：设置标准的代理头部
		// 性能优化：批量设置 header，减少函数调用
		port := m.getPort(r)
		proxyHeaders := map[string]string{
			"X-Forwarded-Proto": scheme,
			"X-Forwarded-Host":  r.Host,
			"X-Forwarded-Port":  port,
			"X-Real-IP":         clientIP,
		}
		m.setHeadersBatch(r.Header, proxyHeaders)

		// 处理自定义上游请求头部
		if len(rule.UpstreamRequestHeaders) > 0 {
			// 使用对象池优化：从对象池获取 map，使用后归还
			upstreamHeaders := m.getHeaderMap()
			defer m.putHeaderMap(upstreamHeaders)
			for key, value := range rule.UpstreamRequestHeaders {
				trimmedKey := strings.TrimSpace(key)
				if trimmedKey != "" {
					upstreamHeaders[trimmedKey] = value
				}
			}
			m.setHeadersBatch(r.Header, upstreamHeaders)
		}

		// 正确处理 X-Forwarded-For 链
		if existing := r.Header.Get("X-Forwarded-For"); existing != "" {
			r.Header.Set("X-Forwarded-For", existing+", "+clientIP)
		} else {
			r.Header.Set("X-Forwarded-For", clientIP)
		}

		// 设置原始请求信息
		originalHeaders := map[string]string{
			"X-Forwarded-Server": "sslcat",
			"X-Original-URI":      r.RequestURI,
			"X-Original-Method":   r.Method,
		}
		m.setHeadersBatch(r.Header, originalHeaders)

		m.log.Debugf("Added proxy headers (non-CDN, non-cloud mode) for %s", r.Host)
	} else {
		// CDN模式或云服务模式：最小化头部，避免干扰
		if cdnEnabled && isCloudStorage {
			m.log.Infof("云服务 + CDN mode enabled for %s, skipping proxy headers", r.Host)
		} else if isCloudStorage {
			m.log.Infof("云服务模式 enabled for %s, skipping proxy headers", r.Host)
		} else if cdnEnabled {
			m.log.Infof("CDN mode enabled for %s, skipping proxy headers", r.Host)
		}
	}

	// 执行代理
	// 在 ModifyResponse 中做缓存落盘（全局或域名启用）
	// 修复：避免重复设置 ModifyResponse，防止递归调用链
	// 如果 ModifyResponse 已经被设置过，使用 context 传递请求特定信息
	if proxy.ModifyResponse == nil {
		// 只在第一次设置 ModifyResponse
		proxy.ModifyResponse = func(resp *http.Response) error {
			// 从 context 获取请求特定信息
			ctx := resp.Request.Context()
			ruleFromCtx, _ := ctx.Value(proxyRuleKey).(*config.ProxyRule)
			if ruleFromCtx == nil {
				// 这不应该发生，因为我们总是在调用前设置 context
				// 记录警告但不使用不安全的回退
				m.log.Warnf("proxyRule not found in context, this should not happen for request %s %s", resp.Request.Method, resp.Request.URL.Path)
			}
			cdnEnabledFromCtx, _ := ctx.Value(cdnEnabledKey).(bool)
			if !cdnEnabledFromCtx {
				cdnEnabledFromCtx = m.config.CDNCache.Enabled || (ruleFromCtx != nil && ruleFromCtx.CDNEnabled)
			}

			// 记录响应详情
			m.logResponseDetails(resp, ruleFromCtx)
		// 移除可能的安全头，让目标服务器自己设置
		// 性能优化：批量删除
		securityHeaders := []string{
			"Strict-Transport-Security",
			"X-Frame-Options",
			"X-Content-Type-Options",
		}
		m.deleteHeadersBatch(resp.Header, securityHeaders)

		// 添加代理标识
		resp.Header.Set("X-Proxy-By", "SSLcat/"+m.version)

		// 处理自定义响应头部
		if ruleFromCtx != nil && len(ruleFromCtx.ResponseHeaders) > 0 {
			// 使用对象池优化：从对象池获取 map，使用后归还
			responseHeaders := m.getHeaderMap()
			defer m.putHeaderMap(responseHeaders)
			for key, value := range ruleFromCtx.ResponseHeaders {
				trimmedKey := strings.TrimSpace(key)
				if trimmedKey != "" {
					responseHeaders[trimmedKey] = value
				}
			}
			m.setHeadersBatch(resp.Header, responseHeaders)
		}

		// 图片优化处理
		if m.responseProcessor != nil && (resp.Request.Method == "GET" || resp.Request.Method == "HEAD") {
			// 检查是否为图片响应
			contentType := resp.Header.Get("Content-Type")
			if strings.HasPrefix(contentType, "image/") {
				// 读取响应体
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					m.log.Warnf("Failed to read response body for image optimization: %v", err)
				} else {
					// 关闭原始响应体
					resp.Body.Close()

					// 应用图片优化
					optimizedData, newContentType, err := m.responseProcessor.ProcessResponse(body, contentType, resp.Request)
					if err != nil {
						m.log.Warnf("Image optimization failed: %v, using original", err)
						// 如果优化失败，使用原始数据
						optimizedData = body
						newContentType = contentType
					} else {
						// 更新响应头
						if newContentType != contentType {
							resp.Header.Set("Content-Type", newContentType)
						}
						resp.Header.Set("Content-Length", strconv.Itoa(len(optimizedData)))

						// 添加优化标识
						if len(optimizedData) < len(body) {
							resp.Header.Set("X-Image-Optimized", "true")
							compressionRatio := float64(len(body)-len(optimizedData)) / float64(len(body)) * 100
							resp.Header.Set("X-Image-Compression-Ratio", fmt.Sprintf("%.1f%%", compressionRatio))
						}
					}

					// 设置新的响应体
					resp.Body = io.NopCloser(bytes.NewReader(optimizedData))
				}
			}
		}

		// CDN 缓存落盘（全局或域名启用）
		// 使用之前定义的cdnEnabled变量
		if m.cdnCache != nil && cdnEnabledFromCtx {
			if ruleFromCtx != nil && ruleFromCtx.CDNDefaultTTLSeconds > 0 {
				resp.Header.Set("X-SSLcat-CDN-Default-TTL", strconv.Itoa(ruleFromCtx.CDNDefaultTTLSeconds))
			}
			// 临时修改请求Host为后端域名，确保缓存路径一致性
			originalHost := resp.Request.Host
			if ruleFromCtx != nil {
				backendHost := m.extractHostFromTarget(ruleFromCtx.Target, ruleFromCtx.Port)
				resp.Request.Host = backendHost
			}
			m.cdnCache.MaybeStoreWithConfig(resp, cdnEnabledFromCtx)
			// 恢复原始Host
			resp.Request.Host = originalHost
			if ruleFromCtx != nil {
				resp.Header.Del("X-SSLcat-CDN-Default-TTL")
			}
		}
		return nil
	}
	}

	// 将请求特定信息放入 context
	ctx := r.Context()
	ctx = context.WithValue(ctx, proxyRuleKey, rule)
	ctx = context.WithValue(ctx, cdnEnabledKey, cdnEnabled)
	r = r.WithContext(ctx)

	proxy.ServeHTTP(w, r)
}

// getOrCreateProxy 获取或创建反向代理
func (m *Manager) getOrCreateProxy(rule *config.ProxyRule) *httputil.ReverseProxy {
	// 生成缓存key，对于完整URL使用URL本身，对于IP+端口使用传统格式
	var key string
	targetURL := rule.Target
	if strings.HasPrefix(strings.ToLower(targetURL), "http://") || strings.HasPrefix(strings.ToLower(targetURL), "https://") {
		// 完整URL，使用URL本身作为key
		key = targetURL
	} else {
		// IP或域名，使用传统格式
		key = fmt.Sprintf("%s:%d", rule.Target, rule.Port)
	}

	m.cacheMutex.RLock()
	if proxy, exists := m.proxyCache[key]; exists {
		m.cacheMutex.RUnlock()
		return proxy
	}
	m.cacheMutex.RUnlock()

	// 创建新的反向代理
	// 允许在配置中直接写入完整URL（包含协议与端口）或仅写主机名/IP
	if !strings.HasPrefix(strings.ToLower(targetURL), "http://") && !strings.HasPrefix(strings.ToLower(targetURL), "https://") {
		// 只有当target不包含协议时才添加协议和端口
		if rule.Port > 0 {
			targetURL = "http://" + net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port))
		} else {
			targetURL = "http://" + rule.Target
		}
	} else {
		// target已经包含完整URL，完全忽略port字段
		// 解析URL以提取协议、主机和端口
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			m.log.Errorf("Failed to parse target URL: %v", err)
			return nil
		}
		
		// 如果URL中没有端口，根据协议使用默认端口
		if parsedURL.Port() == "" {
			if parsedURL.Scheme == "https" {
				// HTTPS默认端口443
				parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), "443")
			} else if parsedURL.Scheme == "http" {
				// HTTP默认端口80
				parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), "80")
			}
			targetURL = parsedURL.String()
		}
		// 如果URL中已有端口，直接使用，完全忽略rule.Port字段
	}
	
	target, err := url.Parse(targetURL)
	if err != nil {
		m.log.Errorf("Failed to parse target URL: %v", err)
		return nil
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// 自定义 Director 函数以实现智能Host头转发
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// 保存原始Host，因为原始Director会修改它
		originalHost := req.Host

		// 调用原始 Director
		originalDirector(req)

		// 智能Host头转发逻辑
		// 如果后端配置的是IP地址，则转发原始的Host名
		// 如果后端配置的是域名，则使用后端原有的域名作为Host
		if m.isIPAddress(rule.Target) {
			// 后端是IP地址，保持原始的Host头，实现透明代理
			req.Host = originalHost
			req.Header.Set("Host", originalHost)
			m.log.Debugf("Backend is IP (%s), forwarding original Host: %s", rule.Target, originalHost)
		} else {
			// 后端是域名，根据配置决定Host头部处理方式
			if rule.OptimizeHostHeader {
				// 启用Host头部优化：使用后端配置的域名作为Host
				m.log.Infof("开始Host头部优化: target=%s, port=%d", rule.Target, rule.Port)
				backendHost := m.extractHostFromTarget(rule.Target, rule.Port)
				m.log.Infof("extractHostFromTarget返回: %s", backendHost)

				// 如果是云存储服务，根据配置决定Host头部
				if m.isCloudStorageService(rule.Target) {
					m.log.Infof("检测到云存储服务: %s", rule.Target)
					// 对于云存储，优先使用配置的端点，否则使用检测到的端点
					if rule.CloudStorageEndpoint != "" {
						backendHost = rule.CloudStorageEndpoint
						m.log.Infof("使用配置的云存储端点: %s", backendHost)
					} else if cloudInfo := m.detectCloudStorageInfo(rule.Target); cloudInfo != nil {
						backendHost = cloudInfo.Endpoint
						m.log.Infof("使用检测到的云存储端点: %s", backendHost)
					}
					m.log.Infof("云存储模式: 使用端点 %s (配置: %s)", backendHost, rule.CloudStorageEndpoint)
				}

				// 关键修复：同时设置 req.Host 和 Header，覆盖原始Director的设置
				req.Host = backendHost
				req.Header.Set("Host", backendHost)

				m.log.Infof("Host头部优化已启用: 设置Host为 %s (原: %s)", backendHost, originalHost)
			} else {
				// 禁用Host头部优化：保持原始的Host头，实现透明代理
				req.Host = originalHost
				req.Header.Set("Host", originalHost)
				m.log.Infof("Host头部优化已禁用: 保持原始Host %s", originalHost)
			}
		}

		// 移除 Hop-by-hop 头部
		hopHeaders := []string{
			"Connection",
			"Proxy-Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"Te",
			"Trailers",
			"Transfer-Encoding",
			"Upgrade",
		}
		for _, header := range hopHeaders {
			req.Header.Del(header)
		}

		// 检查是否为云存储服务
		isCloudStorage := m.isCloudStorageService(rule.Target)
		cdnEnabled := m.config.CDNCache.Enabled || (rule != nil && rule.CDNEnabled)

		if isCloudStorage || cdnEnabled {
			// 移除所有可能干扰的代理头部
			req.Header.Del("X-Forwarded-Host")
			req.Header.Del("X-Forwarded-Server")
			req.Header.Del("X-Original-Uri")
			req.Header.Del("X-Original-Method")
			req.Header.Del("X-Forwarded-For")
			req.Header.Del("X-Real-IP")
			req.Header.Del("X-Forwarded-Proto")
			req.Header.Del("X-Forwarded-Port")

			// 对于云服务，还需要移除一些额外的头部
			if isCloudStorage {
				req.Header.Del("X-Forwarded")
				req.Header.Del("X-Client-IP")
				req.Header.Del("X-Cluster-Client-IP")
				req.Header.Del("Forwarded-For")
				req.Header.Del("Forwarded")
				req.Header.Del("CF-Connecting-IP")
				// 对于防盗链敏感的服务，可选择性移除或修改Referer
				if referer := req.Header.Get("Referer"); referer != "" && strings.Contains(referer, "local.") {
					// 移除指向本地域名的Referer，避免触发防盗链
					req.Header.Del("Referer")
					m.log.Debugf("Removed local Referer for OSS: %s", referer)
				}
			}

			if isCloudStorage && cdnEnabled {
				m.log.Infof("云服务 + CDN mode: removed all proxy headers for target: %s", rule.Target)
			} else if isCloudStorage {
				m.log.Infof("云服务模式: 已移除防盗链和代理头部 for target: %s", rule.Target)
			} else if cdnEnabled {
				m.log.Infof("CDN mode: removed proxy headers for target: %s", rule.Target)
			}
		}

		// 记录Host字段的最终状态 (Debug级别，避免频繁日志)
		m.log.Debugf("最终发送的Host信息 - req.Host: %s, Header['Host']: %s", req.Host, req.Header.Get("Host"))

		// 记录向上游发送的请求详情
		m.logRequestDetails(req, "OUTGOING_REQUEST", rule)
	}

	// 获取超时配置，如果为0则使用默认值
	connectTimeout := rule.ConnectTimeoutSec
	if connectTimeout <= 0 {
		connectTimeout = 30 // 默认30秒
	}
	keepAliveTimeout := rule.KeepAliveTimeoutSec
	if keepAliveTimeout <= 0 {
		keepAliveTimeout = 30 // 默认30秒
	}
	idleTimeout := rule.IdleTimeoutSec
	if idleTimeout <= 0 {
		idleTimeout = 90 // 默认90秒
	}
	tlsHandshakeTimeout := rule.TLSHandshakeTimeoutSec
	if tlsHandshakeTimeout <= 0 {
		tlsHandshakeTimeout = 10 // 默认10秒
	}
	expectContinueTimeout := rule.ExpectContinueTimeoutSec
	if expectContinueTimeout <= 0 {
		expectContinueTimeout = 1 // 默认1秒
	}

	// 自定义传输配置
	baseTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(connectTimeout) * time.Second,
			KeepAlive: time.Duration(keepAliveTimeout) * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    10,                                      // 每个主机保持 10 个空闲连接，提高连接复用
		IdleConnTimeout:        time.Duration(idleTimeout) * time.Second,
		TLSHandshakeTimeout:    time.Duration(tlsHandshakeTimeout) * time.Second,
		ExpectContinueTimeout:  time.Duration(expectContinueTimeout) * time.Second,
		ResponseHeaderTimeout:  30 * time.Second, // 响应头超时，防止连接泄漏
		MaxResponseHeaderBytes: 1 << 20,          // 限制响应头最大 1MB，防止内存攻击
		ReadBufferSize:         32 * 1024,        // 32KB 读缓冲，减少小缓冲区频繁分配
		WriteBufferSize:        32 * 1024,        // 32KB 写缓冲，减少小缓冲区频繁分配
		// 不验证后端证书，允许自签名证书
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 包装Transport以记录实际发送的请求
	proxy.Transport = &loggingTransport{
		base:   baseTransport,
		log:    m.log,
		config: m.config,
	}

	// 自定义错误处理
	// 注意：这里是在创建新 proxy 时设置，所以 ErrorHandler 应该是 nil
	// 但为了代码健壮性，还是添加检查
	if proxy.ErrorHandler == nil {
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			m.log.Errorf("Proxy error %s -> %s: %v", r.Host, targetURL, err)

			// 返回错误页面
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, `
			<html>
			<head><title>Proxy Error</title></head>
			<body>
				<h1>502 Bad Gateway</h1>
				<p>Unable to connect to upstream: %s</p>
				<p>Error: %v</p>
				<hr>
				<p><small>Powered by sslcat-%s</small></p>
			</body>
			</html>
			`, targetURL, err, m.version)
		}
	}

	// 修改响应
	// 缓存代理
	m.cacheMutex.Lock()
	m.proxyCache[key] = proxy
	m.cacheMutex.Unlock()

	return proxy
}

// getClientIP 获取客户端真实IP
func (m *Manager) getClientIP(r *http.Request) string {
	// 1. 首先检查 CF-Connecting-IP (Cloudflare)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" && m.isValidIP(cfIP) {
		return cfIP
	}

	// 2. 检查 X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" && m.isValidIP(xri) {
		return xri
	}

	// 3. 检查 X-Forwarded-For (取第一个非内网IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if m.isValidIP(ip) && !m.isPrivateIP(ip) {
				return ip
			}
		}
		// 如果没有公网IP，返回第一个有效IP
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if m.isValidIP(ip) {
				return ip
			}
		}
	}

	// 4. 检查其他常见头部
	headers := []string{
		"X-Client-IP",
		"X-Forwarded",
		"X-Cluster-Client-IP",
		"Forwarded-For",
		"Forwarded",
	}

	for _, header := range headers {
		if ip := r.Header.Get(header); ip != "" && m.isValidIP(ip) {
			return ip
		}
	}

	// 5. 最后使用RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// isValidIP 检查是否为有效IP地址
func (m *Manager) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// isPrivateIP 检查是否为内网IP
func (m *Manager) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 检查是否为内网IP段
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // 链路本地地址
		"::1/128",        // IPv6 本地回环
		"fc00::/7",       // IPv6 私有地址
		"fe80::/10",      // IPv6 链路本地地址
	}

	for _, block := range privateBlocks {
		_, network, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// isIPAddress 检查目标是否为IP地址（包括IPv4和IPv6）
func (m *Manager) isIPAddress(target string) bool {
	// 移除可能的协议前缀
	if strings.HasPrefix(strings.ToLower(target), "http://") {
		target = target[7:]
	} else if strings.HasPrefix(strings.ToLower(target), "https://") {
		target = target[8:]
	}

	// 处理IPv6地址格式 [2001:db8::1]:8080
	if strings.HasPrefix(target, "[") && strings.Contains(target, "]:") {
		idx := strings.Index(target, "]:")
		if idx != -1 {
			target = target[1:idx] // 移除方括号
		}
	} else if strings.Contains(target, ":") {
		// 处理普通端口号格式
		idx := strings.LastIndex(target, ":")
		if idx != -1 {
			portPart := target[idx+1:]
			if _, err := strconv.Atoi(portPart); err == nil {
				target = target[:idx]
			}
		}
	}

	// 尝试解析为IP地址
	return net.ParseIP(target) != nil
}

// isHTTPSURL 检查目标是否为HTTPS URL（非IP地址）
func (m *Manager) isHTTPSURL(target string) bool {
	// 检查是否以 https:// 开头
	if !strings.HasPrefix(strings.ToLower(target), "https://") {
		return false
	}
	
	// 解析URL
	parsedURL, err := url.Parse(target)
	if err != nil {
		return false
	}
	
	// 提取主机名（去除端口）
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return false
	}
	
	// 检查主机名是否为IP地址
	return !m.isIPAddress(hostname)
}

// getPort 获取请求端口
func (m *Manager) getPort(r *http.Request) string {
	if r.TLS != nil {
		return "443"
	}
	return "80"
}

// HandleWebSocket 处理WebSocket代理
func (m *Manager) HandleWebSocket(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 建立WebSocket连接
	conn, err := net.Dial("tcp", net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port)))
	if err != nil {
		http.Error(w, "无法连接到目标服务器", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// 获取客户端连接
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "无法劫持连接", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "无法劫持连接", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// 发送HTTP响应
	clientConn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n"))
	clientConn.Write([]byte("Upgrade: websocket\r\n"))
	clientConn.Write([]byte("Connection: Upgrade\r\n"))
	clientConn.Write([]byte("\r\n"))

	// 开始双向数据转发
	// 修复：确保连接正确关闭
	// copyData 只关闭源连接，所以需要确保两个方向都正确关闭
	go func() {
		m.copyData(clientConn, conn)
		// 当从上游读取完成时，关闭客户端连接
		clientConn.Close()
	}()
	// 主 goroutine 处理从客户端到上游的数据
	m.copyData(conn, clientConn)
	// 当从客户端读取完成时，关闭上游连接
	conn.Close()
}

// isWebSocketUpgrade 检查是否为WebSocket升级请求
func (m *Manager) isWebSocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// HandleWebSocketOptimized 优化的WebSocket代理处理
func (m *Manager) HandleWebSocketOptimized(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 检查是否启用WebSocket优化
	if !rule.WebSocketOptimized {
		// 使用原有的简单WebSocket代理
		m.HandleWebSocket(w, r, rule)
		return
	}

	// 获取连接超时配置
	connectTimeout := rule.ConnectTimeoutSec
	if connectTimeout <= 0 {
		connectTimeout = 30 // 默认30秒
	}

	// 建立到上游服务器的连接
	upstreamConn, err := net.DialTimeout("tcp", net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port)), time.Duration(connectTimeout)*time.Second)
	if err != nil {
		m.log.Errorf("Failed to connect to upstream WebSocket server: %v", err)
		http.Error(w, "无法连接到目标服务器", http.StatusBadGateway)
		return
	}

	// 劫持客户端连接
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstreamConn.Close()
		http.Error(w, "无法劫持连接", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		upstreamConn.Close()
		http.Error(w, "无法劫持连接", http.StatusInternalServerError)
		return
	}

	// 转发WebSocket握手请求到上游服务器
	err = r.Write(upstreamConn)
	if err != nil {
		m.log.Errorf("Failed to forward WebSocket handshake: %v", err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	// 读取上游服务器的握手响应
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamReader, r)
	if err != nil {
		m.log.Errorf("Failed to read WebSocket handshake response: %v", err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	// 转发握手响应到客户端
	err = resp.Write(clientConn)
	if err != nil {
		m.log.Errorf("Failed to forward WebSocket handshake response: %v", err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	// 检查握手是否成功
	if resp.StatusCode != 101 {
		m.log.Errorf("WebSocket handshake failed with status: %d", resp.StatusCode)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	m.log.Infof("WebSocket handshake successful for %s", r.Host)

	// 开始优化的双向数据转发
	m.startOptimizedWebSocketProxy(clientConn, upstreamConn, rule)
}

// startOptimizedWebSocketProxy 启动优化的WebSocket代理
func (m *Manager) startOptimizedWebSocketProxy(clientConn, upstreamConn net.Conn, rule *config.ProxyRule) {
	// 设置连接超时
	timeout := time.Duration(rule.WebSocketTimeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Minute // 默认 30 分钟
	}

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 获取缓冲区大小配置
	bufferSize := rule.WebSocketBufferSize
	if bufferSize <= 0 {
		bufferSize = 100 // 默认100
	}

	// 创建带缓冲的通道用于数据传输
	clientToUpstream := make(chan []byte, bufferSize)
	upstreamToClient := make(chan []byte, bufferSize)

	// 错误通道
	errChan := make(chan error, 4)

	// 连接状态
	var clientClosed, upstreamClosed int32

	// 使用 WaitGroup 等待所有 goroutine 退出
	var wg sync.WaitGroup

	// 启动数据读取goroutine
	wg.Add(2)
	go func() {
		defer wg.Done()
		m.readWebSocketData(ctx, clientConn, clientToUpstream, errChan, &clientClosed, "client", rule)
	}()
	go func() {
		defer wg.Done()
		m.readWebSocketData(ctx, upstreamConn, upstreamToClient, errChan, &upstreamClosed, "upstream", rule)
	}()

	// 启动数据写入goroutine
	wg.Add(2)
	go func() {
		defer wg.Done()
		m.writeWebSocketData(ctx, upstreamConn, clientToUpstream, errChan, &upstreamClosed, "upstream", rule)
	}()
	go func() {
		defer wg.Done()
		m.writeWebSocketData(ctx, clientConn, upstreamToClient, errChan, &clientClosed, "client", rule)
	}()

	// 监控连接状态和错误
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.monitorWebSocketConnections(ctx, clientConn, upstreamConn, errChan, &clientClosed, &upstreamClosed, rule)
	}()

	// 等待连接关闭或超时
	select {
	case <-errChan:
		// 连接正常关闭
	case <-ctx.Done():
		// 连接超时
		m.log.Warnf("WebSocket connection timeout for %s", rule.Target)
	}

	// 清理资源：先取消 context，让所有 goroutine 知道应该退出
	cancel() // 取消 context，通知所有 goroutine 退出

	// 设置关闭标志
	atomic.StoreInt32(&clientClosed, 1)
	atomic.StoreInt32(&upstreamClosed, 1)

	// 关闭连接，这会触发 Read/Write 错误，让 goroutine 快速退出
	clientConn.Close()
	upstreamConn.Close()

	// 使用 WaitGroup 等待所有 goroutine 退出，带超时保护
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// 所有 goroutine 已安全退出
		m.log.Debugf("All WebSocket goroutines exited cleanly for %s", rule.Target)
	case <-time.After(1 * time.Second):
		// 超时，但至少我们尝试等待了
		m.log.Warnf("Timeout waiting for WebSocket goroutines to exit for %s (this may indicate a goroutine leak)", rule.Target)
	}

	// 现在可以安全关闭通道，因为所有 goroutine 都已退出
	close(clientToUpstream)
	close(upstreamToClient)
	// errChan 也应该关闭
	close(errChan)

	m.log.Infof("WebSocket proxy connection closed for %s", rule.Target)
}

// readWebSocketData 读取WebSocket数据
func (m *Manager) readWebSocketData(ctx context.Context, conn net.Conn, dataChan chan<- []byte, errChan chan<- error, closed *int32, connType string, rule *config.ProxyRule) {
	defer func() {
		if r := recover(); r != nil {
			m.log.Errorf("Panic in readWebSocketData (%s): %v", connType, r)
		}
	}()

	// 获取读取超时配置
	readTimeout := rule.WebSocketReadTimeout
	if readTimeout <= 0 {
		readTimeout = 30 // 默认30秒
	}

	// 性能优化：从 buffer 池获取缓冲区，减少内存分配
	buffer := m.bufferPool.Get().([]byte)
	defer m.bufferPool.Put(buffer) // 使用完后归还到池中

	for atomic.LoadInt32(closed) == 0 {
		// 检查上下文是否已取消（在循环开始时检查，避免不必要的操作）
		select {
		case <-ctx.Done():
			m.log.Debugf("WebSocket read context cancelled (%s)", connType)
			return
		default:
		}

		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(time.Duration(readTimeout) * time.Second))

		n, err := conn.Read(buffer)
		if err != nil {
			if atomic.LoadInt32(closed) == 0 {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时不是错误，但在继续之前再次检查上下文
					// 这样可以避免在上下文已取消时继续忙等待
					select {
					case <-ctx.Done():
						return
					default:
						// 添加短暂延迟，避免超时后立即重试导致 CPU 占用过高
						// 这可以防止在连接有问题时形成忙等待循环
						time.Sleep(10 * time.Millisecond)
					}
					continue
				}
				m.log.Debugf("WebSocket read error (%s): %v", connType, err)
				errChan <- err
			}
			return
		}

		if n > 0 {
			// 性能优化：只复制实际读取的数据，避免浪费内存
			// 注意：这里必须复制，因为 buffer 会被复用
			data := make([]byte, n)
			copy(data, buffer[:n])

			// 修复：使用 context.WithTimeout 而不是 time.After，避免定时器泄露
			// time.After 在 select 循环中会不断创建新的定时器，导致内存泄露和 CPU 占用高
			sendTimeoutCtx, sendTimeoutCancel := context.WithTimeout(ctx, 5*time.Second)
			select {
			case dataChan <- data:
				sendTimeoutCancel() // 发送成功，取消超时
				// 数据发送成功
			case <-sendTimeoutCtx.Done():
				sendTimeoutCancel()
				// 发送超时，可能对端已关闭
				m.log.Warnf("WebSocket data send timeout (%s)", connType)
				errChan <- fmt.Errorf("data send timeout")
				return
			case <-ctx.Done():
				sendTimeoutCancel()
				return
			}
		}
	}
}

// writeWebSocketData 写入WebSocket数据
func (m *Manager) writeWebSocketData(ctx context.Context, conn net.Conn, dataChan <-chan []byte, errChan chan<- error, closed *int32, connType string, rule *config.ProxyRule) {
	defer func() {
		if r := recover(); r != nil {
			m.log.Errorf("Panic in writeWebSocketData (%s): %v", connType, r)
		}
	}()

	// 获取写入超时配置
	writeTimeout := rule.WebSocketWriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 10 // 默认10秒
	}

	// 修复：使用 ticker 而不是不断创建新的 context，避免内存泄漏
	// 不断创建 context.WithTimeout 会在高并发时产生大量 context 对象，导致内存占用过高
	idleTimeout := 60 * time.Second
	idleTicker := time.NewTicker(idleTimeout)
	defer idleTicker.Stop()
	
	// 记录最后一次写入时间
	lastWriteTime := time.Now()

	for atomic.LoadInt32(closed) == 0 {
		select {
		case data, ok := <-dataChan:
			// 重置空闲超时：更新最后写入时间并重置 ticker
			lastWriteTime = time.Now()
			// 停止旧 ticker 并创建新的
			idleTicker.Stop()
			idleTicker = time.NewTicker(idleTimeout)

			if !ok {
				// 通道已关闭
				return
			}

			// 设置写入超时
			conn.SetWriteDeadline(time.Now().Add(time.Duration(writeTimeout) * time.Second))

			_, err := conn.Write(data)
			if err != nil {
				if atomic.LoadInt32(closed) == 0 {
					m.log.Debugf("WebSocket write error (%s): %v", connType, err)
					errChan <- err
				}
				return
			}
		case <-idleTicker.C:
			// 写入超时检查（60秒无数据）
			if time.Since(lastWriteTime) >= idleTimeout {
				if atomic.LoadInt32(closed) != 0 {
					return
				}
				// 超时，关闭连接
				m.log.Debugf("WebSocket write idle timeout (%s)", connType)
				errChan <- fmt.Errorf("write idle timeout")
				return
			}
			// 如果时间未到（可能是 ticker 重置导致的误触发），继续等待
		case <-ctx.Done():
			return
		}
	}
}

// monitorWebSocketConnections 监控WebSocket连接状态
func (m *Manager) monitorWebSocketConnections(ctx context.Context, clientConn, upstreamConn net.Conn, errChan chan<- error, clientClosed, upstreamClosed *int32, rule *config.ProxyRule) {
	ticker := time.NewTicker(29 * time.Second) // 使用质数间隔避免与其他定时器同时触发
	defer ticker.Stop()

	// 修复：使用 context.WithTimeout 而不是 time.After，避免定时器泄露
	// time.After 在 select 循环中会不断创建新的定时器，导致内存泄露
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer timeoutCancel()

	for {
		select {
		case <-ctx.Done():
			// 上下文已取消
			return
		case <-ticker.C:
			// 定期检查连接状态
			if atomic.LoadInt32(clientClosed) != 0 || atomic.LoadInt32(upstreamClosed) != 0 {
				errChan <- fmt.Errorf("connection closed")
				return
			}

			// 可以在这里添加心跳检测逻辑

		case <-timeoutCtx.Done():
			// 连接超时检查
			m.log.Debugf("WebSocket connection timeout check for %s", rule.Target)
			return
		}
	}
}

// copyData 复制数据（保留原有方法作为备用）
// 注意：这个函数会关闭两个连接，调用者需要确保不会重复关闭
func (m *Manager) copyData(dst, src net.Conn) {
	// 修复：只关闭源连接，目标连接由调用者管理
	// 避免在 HandleWebSocket 中重复关闭连接
	defer src.Close()

	// 性能优化：从 buffer 池获取缓冲区，减少内存分配
	buffer := m.bufferPool.Get().([]byte)
	defer m.bufferPool.Put(buffer) // 使用完后归还到池中

	for {
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				m.log.Debugf("Error reading data: %v", err)
			}
			break
		}

		if n > 0 {
			_, err := dst.Write(buffer[:n])
			if err != nil {
				m.log.Debugf("Error writing data: %v", err)
				break
			}
		}
	}
}

// TestConnection 测试到目标服务器的连接
func (m *Manager) TestConnection(rule *config.ProxyRule) error {
	// 获取健康检查超时配置，如果为0则使用默认值
	healthCheckTimeout := rule.HealthCheckTimeoutSec
	if healthCheckTimeout <= 0 {
		healthCheckTimeout = 5 // 默认5秒
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port)), time.Duration(healthCheckTimeout)*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", rule.Target, rule.Port, err)
	}
	defer conn.Close()

	return nil
}

// GetProxyStats 获取代理统计信息
func (m *Manager) GetProxyStats() map[string]interface{} {
	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()

	stats := map[string]interface{}{
		"cached_proxies": len(m.proxyCache),
		"active_rules":   len(m.config.Proxy.Rules),
	}

	// 添加负载均衡器统计
	m.lbMutex.RLock()
	stats["load_balancers"] = len(m.loadBalancers)
	m.lbMutex.RUnlock()

	// 添加上游缓存统计
	if m.upstreamCache != nil {
		stats["upstream_cache"] = m.upstreamCache.GetStats()
	}

	return stats
}

// 实现 ReloadableComponent 接口

// GetName 获取组件名称
func (m *Manager) GetName() string {
	return "proxy_manager"
}

// Reload 重载代理配置
func (m *Manager) Reload(newConfig *config.Config) error {
	m.log.Info("Reloading proxy manager configuration")

	// 更新配置
	oldConfig := m.config
	m.config = newConfig

	// 重新初始化负载均衡器
	m.lbMutex.Lock()
	// 停止旧的负载均衡器
	for _, lb := range m.loadBalancers {
		lb.StopHealthCheck()
	}
	// 清空负载均衡器
	m.loadBalancers = make(map[string]loadbalancer.BalancerInterface)
	m.lbMutex.Unlock()

	// 初始化新的负载均衡器
	m.initializeLoadBalancers()

	// 清理不再需要的代理缓存
	m.cacheMutex.Lock()
	newDomains := make(map[string]bool)
	for _, rule := range newConfig.Proxy.Rules {
		newDomains[rule.Domain] = true
	}

	// 清理不再使用的代理缓存
	for key := range m.proxyCache {
		found := false
		for _, rule := range newConfig.Proxy.Rules {
			if !rule.LoadBalancerEnabled {
				expectedKey := fmt.Sprintf("%s:%d", rule.Target, rule.Port)
				if key == expectedKey {
					found = true
					break
				}
			}
		}
		if !found {
			delete(m.proxyCache, key)
		}
	}
	m.cacheMutex.Unlock()

	m.log.Infof("Proxy manager reloaded: %d rules -> %d rules, %d load balancers",
		len(oldConfig.Proxy.Rules), len(newConfig.Proxy.Rules), len(m.loadBalancers))

	return nil
}

// Validate 验证代理配置
func (m *Manager) Validate(newConfig *config.Config) error {
	// 验证代理规则
	for i, rule := range newConfig.Proxy.Rules {
		if rule.Domain == "" {
			return fmt.Errorf("proxy rule %d: domain is required", i)
		}

		// 使用统一的后端验证
		effectiveBackends := rule.GetEffectiveBackends()
		if len(effectiveBackends) == 0 {
			return fmt.Errorf("proxy rule %d: at least one backend is required", i)
		}

		enabledBackends := 0
		for j, backend := range effectiveBackends {
			if backend.Host == "" {
				return fmt.Errorf("proxy rule %d, backend %d: host is required", i, j)
			}
			if backend.Port <= 0 {
				return fmt.Errorf("proxy rule %d, backend %d: invalid port: %d", i, j, backend.Port)
			}
			if backend.Enabled {
				enabledBackends++
			}
		}

		if enabledBackends == 0 {
			return fmt.Errorf("proxy rule %d: at least one backend must be enabled", i)
		}
	}

	return nil
}

// logRequestDetails 记录请求详情
func (m *Manager) logRequestDetails(r *http.Request, requestType string, rule *config.ProxyRule) {
	// 只在调试模式下记录详细请求信息
	if !m.config.Server.Debug {
		return
	}

	// 构建目标地址信息
	targetInfo := "unknown"
	if rule != nil {
		targetInfo = m.buildTargetInfo(rule)
	}

	// 获取实际的Host头（可能已经被Director函数修改）
	actualHost := r.Header.Get("Host")
	if actualHost == "" {
		actualHost = r.Host
	}

	m.log.WithFields(logrus.Fields{
		"type":           requestType,
		"method":         r.Method,
		"url":            r.URL.String(),
		"host":           actualHost,
		"target":         targetInfo,
		"user_agent":     r.Header.Get("User-Agent"),
		"client_ip":      m.getClientIP(r),
		"content_type":   r.Header.Get("Content-Type"),
		"content_length": r.ContentLength,
	}).Debug("HTTP请求详情")

	// 记录重要的请求头部
	importantHeaders := []string{
		"Authorization",
		"Cookie",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Forwarded-Proto",
		"X-Forwarded-Host",
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
		"Cache-Control",
		"Referer",
	}

	headers := make(map[string]string)
	for _, header := range importantHeaders {
		if value := r.Header.Get(header); value != "" {
			// 对敏感信息进行脱敏处理
			if header == "Authorization" || header == "Cookie" {
				if len(value) > 20 {
					headers[header] = value[:20] + "..."
				} else {
					headers[header] = "***"
				}
			} else {
				headers[header] = value
			}
		}
	}

	if len(headers) > 0 {
		m.log.WithFields(logrus.Fields{
			"type":    requestType,
			"headers": headers,
		}).Debug("请求头部信息")
	}

	// 记录请求体（仅对POST/PUT等有body的请求，且限制大小）
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		if r.ContentLength > 0 && r.ContentLength < 1024 { // 只记录小于1KB的请求体
			body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
			if err == nil && len(body) > 0 {
				// 重新设置请求体，因为ReadAll会消耗掉原始body
				r.Body = io.NopCloser(strings.NewReader(string(body)))
				m.log.WithFields(logrus.Fields{
					"type": requestType,
					"body": string(body),
				}).Debug("请求体内容")
			}
		}
	}
}

// logResponseDetails 记录响应详情
func (m *Manager) logResponseDetails(resp *http.Response, rule *config.ProxyRule) {
	// 只在调试模式下记录详细响应信息
	if !m.config.Server.Debug {
		return
	}

	// 构建目标地址信息
	targetInfo := "unknown"
	if rule != nil {
		targetInfo = m.buildTargetInfo(rule)
	}

	m.log.WithFields(logrus.Fields{
		"type":           "RESPONSE",
		"status_code":    resp.StatusCode,
		"status":         resp.Status,
		"target":         targetInfo,
		"content_type":   resp.Header.Get("Content-Type"),
		"content_length": resp.ContentLength,
		"server":         resp.Header.Get("Server"),
	}).Debug("HTTP响应详情")

	// 记录重要的响应头部
	importantHeaders := []string{
		"Set-Cookie",
		"Location",
		"Cache-Control",
		"Expires",
		"Last-Modified",
		"ETag",
		"Content-Encoding",
		"Transfer-Encoding",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Strict-Transport-Security",
	}

	headers := make(map[string]string)
	for _, header := range importantHeaders {
		if value := resp.Header.Get(header); value != "" {
			// 对敏感信息进行脱敏处理
			if header == "Set-Cookie" {
				if len(value) > 50 {
					headers[header] = value[:50] + "..."
				} else {
					headers[header] = "***"
				}
			} else {
				headers[header] = value
			}
		}
	}

	if len(headers) > 0 {
		m.log.WithFields(logrus.Fields{
			"type":    "RESPONSE",
			"headers": headers,
		}).Debug("响应头部信息")
	}
}

// buildTargetInfo 构建目标地址信息用于日志记录
func (m *Manager) buildTargetInfo(rule *config.ProxyRule) string {
	if rule == nil {
		return "unknown"
	}

	// 如果target已经包含完整URL，直接使用
	if strings.HasPrefix(strings.ToLower(rule.Target), "http://") || strings.HasPrefix(strings.ToLower(rule.Target), "https://") {
		return rule.Target
	}

	// 如果target不包含协议，构建完整的目标信息
	if rule.Port > 0 {
		return fmt.Sprintf("%s:%d", rule.Target, rule.Port)
	}
	return rule.Target
}

// extractHostFromTarget 从目标配置中提取Host头信息
func (m *Manager) extractHostFromTarget(target string, port int) string {
	m.log.Infof("extractHostFromTarget调用: target=%s, port=%d", target, port)

	// 如果target包含完整URL，解析出域名和端口
	if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
		m.log.Infof("target包含协议，开始解析URL")
		parsedURL, err := url.Parse(target)
		if err == nil {
			// 检查是否为OSS或其他云服务，对于这些服务，Host头部不应包含标准端口号
			hostname := parsedURL.Hostname()
			m.log.Infof("解析URL成功: hostname=%s, port=%s", hostname, parsedURL.Port())
			isCloudService := strings.Contains(strings.ToLower(hostname), "aliyuncs.com") ||
				strings.Contains(strings.ToLower(hostname), "amazonaws.com") ||
				strings.Contains(strings.ToLower(hostname), "qcloud.com") ||
				strings.Contains(strings.ToLower(hostname), "myqcloud.com")
			m.log.Infof("云服务检测结果: %v", isCloudService)

			// 如果URL中已经有端口
			if parsedURL.Port() != "" {
				urlPort, _ := strconv.Atoi(parsedURL.Port())

				// 对于云服务，如果是标准端口（80/443），则不包含端口号
				if isCloudService && (urlPort == 80 || urlPort == 443) {
					m.log.Infof("云服务标准端口，返回hostname: %s", hostname)
					return hostname
				}

				// 对于云服务，即使是非标准端口，也不包含端口号（云服务通常只支持标准端口）
				if isCloudService {
					m.log.Infof("云服务非标准端口，仍返回hostname: %s", hostname)
					return hostname
				}

				// 对于非云服务，保留端口号
				m.log.Infof("非云服务，返回完整Host: %s", parsedURL.Host)
				return parsedURL.Host
			}

			// 如果URL中没有端口，使用配置中的端口
			if port > 0 && port != 80 && port != 443 {
				// 对于云服务，即使配置了非标准端口，也不包含端口号（云服务通常只支持标准端口）
				if isCloudService {
					m.log.Infof("云服务，配置了非标准端口，仍返回hostname: %s", hostname)
					return hostname
				}
				result := net.JoinHostPort(hostname, strconv.Itoa(port))
				m.log.Infof("非云服务，添加配置端口，返回: %s", result)
				return result
			}
			m.log.Infof("无需添加端口，返回hostname: %s", hostname)
			return hostname
		}
	}

	// 如果target不包含协议，直接使用target和port
	// 检查是否为云服务域名
	isCloudService := strings.Contains(strings.ToLower(target), "aliyuncs.com") ||
		strings.Contains(strings.ToLower(target), "amazonaws.com") ||
		strings.Contains(strings.ToLower(target), "qcloud.com") ||
		strings.Contains(strings.ToLower(target), "myqcloud.com")

	if port > 0 && port != 80 && port != 443 {
		// 对于云服务，不包含端口号
		if isCloudService {
			return target
		}
		return net.JoinHostPort(target, strconv.Itoa(port))
	}
	return target
}

// RoundTrip 实现http.RoundTripper接口，记录实际发送的请求
func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 只在调试模式下记录详细的上游请求信息
	if lt.config.Server.Debug {
		// 构造等效的curl命令
		curlCmd := lt.buildCurlCommand(req)

		lt.log.WithFields(logrus.Fields{
			"type":           "ACTUAL_OUTGOING_REQUEST",
			"method":         req.Method,
			"url":            req.URL.String(),
			"host":           req.Header.Get("Host"),
			"user_agent":     req.Header.Get("User-Agent"),
			"content_type":   req.Header.Get("Content-Type"),
			"content_length": req.ContentLength,
			"all_headers":    req.Header,
			"curl_command":   curlCmd,
		}).Debug("实际发送给上游的HTTP请求")

		// 单独记录curl命令，便于复制
		lt.log.Debugf("等效的curl命令: %s", curlCmd)

		// 记录重要的请求头部
		importantHeaders := []string{
			"Authorization",
			"Cookie",
			"X-Forwarded-For",
			"X-Real-IP",
			"X-Forwarded-Proto",
			"X-Forwarded-Host",
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Cache-Control",
			"Referer",
			// 追踪头部
			"traceparent",
			"tracestate",
			"X-Trace-ID",
			"X-Span-ID",
			"X-Request-ID",
			"X-B3-TraceId",
			"X-B3-SpanId",
			"X-B3-ParentSpanId",
			"X-Cloud-Trace-Context",
			"X-Amzn-Trace-Id",
			"baggage",
		}

		headers := make(map[string]string)
		for _, header := range importantHeaders {
			if value := req.Header.Get(header); value != "" {
				// 对敏感信息进行脱敏处理
				if header == "Authorization" || header == "Cookie" {
					if len(value) > 20 {
						headers[header] = value[:20] + "..."
					} else {
						headers[header] = "***"
					}
				} else {
					headers[header] = value
				}
			}
		}

		if len(headers) > 0 {
			lt.log.WithFields(logrus.Fields{
				"type":    "ACTUAL_OUTGOING_REQUEST",
				"headers": headers,
			}).Debug("实际发送的请求头部信息")
		}
	}

	// 执行实际的请求
	resp, err := lt.base.RoundTrip(req)

	// 只在调试模式下记录详细的上游响应信息
	if resp != nil && lt.config.Server.Debug {
		lt.log.WithFields(logrus.Fields{
			"type":           "ACTUAL_RESPONSE",
			"status_code":    resp.StatusCode,
			"status":         resp.Status,
			"content_type":   resp.Header.Get("Content-Type"),
			"content_length": resp.ContentLength,
			"server":         resp.Header.Get("Server"),
		}).Debug("上游服务器实际返回的HTTP响应")
	}

	return resp, err
}

// buildCurlCommand 构造等效的curl命令
func (lt *loggingTransport) buildCurlCommand(req *http.Request) string {
	var parts []string

	// 基础curl命令
	parts = append(parts, "curl")

	// HTTP方法
	if req.Method != "GET" {
		parts = append(parts, "-X", req.Method)
	}

	// 添加所有请求头
	for name, values := range req.Header {
		for _, value := range values {
			// 对特殊字符进行转义
			escapedValue := strings.ReplaceAll(value, "'", "'\\''")
			parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", name, escapedValue))
		}
	}

	// 如果有请求体
	if req.Body != nil && req.ContentLength > 0 {
		// 注意：这里无法读取Body内容，因为Body已经被消费了
		// 只能提示用户手动添加
		if req.ContentLength > 0 {
			parts = append(parts, "-d", "'[REQUEST_BODY]'")
		}
	}

	// 添加URL（使用单引号包围以避免shell解释）
	parts = append(parts, fmt.Sprintf("'%s'", req.URL.String()))

	// 添加一些常用选项
	parts = append(parts, "-v")         // 详细输出
	parts = append(parts, "--insecure") // 忽略SSL证书验证（如果需要）

	return strings.Join(parts, " ")
}

// CloudStorageInfo 云存储服务信息
type CloudStorageInfo struct {
	Type     string `json:"type"`     // aliyun_oss, aws_s3, tencent_cos
	Name     string `json:"name"`     // 服务名称
	Region   string `json:"region"`   // 区域
	Bucket   string `json:"bucket"`   // 存储桶
	Endpoint string `json:"endpoint"` // 端点
}

// isCloudStorageService 检测是否为云存储服务
func (m *Manager) isCloudStorageService(target string) bool {
	targetLower := strings.ToLower(target)
	return strings.Contains(targetLower, "aliyuncs.com") ||
		strings.Contains(targetLower, "amazonaws.com") ||
		strings.Contains(targetLower, "qcloud.com") ||
		strings.Contains(targetLower, "myqcloud.com") ||
		strings.Contains(targetLower, "oss-") ||
		strings.Contains(targetLower, ".s3.") ||
		strings.Contains(targetLower, ".cos.")
}

// detectCloudStorageInfo 检测云存储服务详细信息
func (m *Manager) detectCloudStorageInfo(target string) *CloudStorageInfo {
	targetLower := strings.ToLower(target)

	// 提取hostname（去除协议）
	extractHostname := func(target string) string {
		if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
			if parsedURL, err := url.Parse(target); err == nil {
				return parsedURL.Hostname()
			}
		}
		return target
	}

	// 阿里云OSS检测
	if strings.Contains(targetLower, "aliyuncs.com") || strings.Contains(targetLower, "oss-") {
		hostname := extractHostname(target)
		// 解析bucket.oss-region.aliyuncs.com格式
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{
				Type:     "aliyun_oss",
				Name:     "阿里云OSS",
				Bucket:   parts[0],
				Region:   extractRegionFromOSS(parts),
				Endpoint: hostname,
			}
		}
		return &CloudStorageInfo{
			Type:     "aliyun_oss",
			Name:     "阿里云OSS",
			Endpoint: hostname,
		}
	}

	// AWS S3检测
	if strings.Contains(targetLower, "amazonaws.com") || strings.Contains(targetLower, ".s3.") {
		hostname := extractHostname(target)
		// 解析bucket.s3-region.amazonaws.com格式
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{
				Type:     "aws_s3",
				Name:     "AWS S3",
				Bucket:   parts[0],
				Region:   extractRegionFromS3(parts),
				Endpoint: hostname,
			}
		}
		return &CloudStorageInfo{
			Type:     "aws_s3",
			Name:     "AWS S3",
			Endpoint: hostname,
		}
	}

	// 腾讯云COS检测
	if strings.Contains(targetLower, "qcloud.com") || strings.Contains(targetLower, "myqcloud.com") || strings.Contains(targetLower, ".cos.") {
		hostname := extractHostname(target)
		// 解析bucket.cos-region.myqcloud.com格式
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{
				Type:     "tencent_cos",
				Name:     "腾讯云COS",
				Bucket:   parts[0],
				Region:   extractRegionFromCOS(parts),
				Endpoint: hostname,
			}
		}
		return &CloudStorageInfo{
			Type:     "tencent_cos",
			Name:     "腾讯云COS",
			Endpoint: hostname,
		}
	}

	return nil
}

// extractRegionFromOSS 从阿里云OSS域名中提取区域信息
func extractRegionFromOSS(parts []string) string {
	if len(parts) < 2 {
		return ""
	}
	// 格式: bucket.oss-region.aliyuncs.com
	ossPart := parts[1]
	if strings.HasPrefix(ossPart, "oss-") {
		return strings.TrimPrefix(ossPart, "oss-")
	}
	return ""
}

// extractRegionFromS3 从AWS S3域名中提取区域信息
func extractRegionFromS3(parts []string) string {
	if len(parts) < 2 {
		return ""
	}
	// 格式: bucket.s3-region.amazonaws.com
	s3Part := parts[1]
	if strings.HasPrefix(s3Part, "s3-") {
		return strings.TrimPrefix(s3Part, "s3-")
	}
	return ""
}

// extractRegionFromCOS 从腾讯云COS域名中提取区域信息
func extractRegionFromCOS(parts []string) string {
	if len(parts) < 2 {
		return ""
	}
	// 格式: bucket.cos-region.myqcloud.com
	cosPart := parts[1]
	if strings.HasPrefix(cosPart, "cos-") {
		return strings.TrimPrefix(cosPart, "cos-")
	}
	return ""
}

// ExtractTraceHeaders 提取追踪头部信息
func (m *Manager) ExtractTraceHeaders(r *http.Request) map[string]string {
	traceHeaders := make(map[string]string)

	// 追踪头部列表
	traceHeaderNames := []string{
		"traceparent",           // W3C Trace Context
		"tracestate",            // W3C Trace Context
		"X-Trace-ID",            // 自定义标准
		"X-Span-ID",             // 自定义标准
		"X-Request-ID",          // 请求ID
		"X-B3-TraceId",          // Zipkin B3
		"X-B3-SpanId",           // Zipkin B3
		"X-B3-ParentSpanId",     // Zipkin B3
		"X-B3-Sampled",          // Zipkin B3
		"X-B3-Flags",            // Zipkin B3
		"X-Cloud-Trace-Context", // Google Cloud
		"X-Amzn-Trace-Id",       // AWS X-Ray
		"baggage",               // W3C Baggage
	}

	// 提取追踪头部
	for _, headerName := range traceHeaderNames {
		if value := r.Header.Get(headerName); value != "" {
			traceHeaders[headerName] = value
		}
	}

	// 提取以 "Baggage-" 开头的头部
	for key, values := range r.Header {
		if strings.HasPrefix(key, "Baggage-") {
			traceHeaders[key] = values[0]
		}
	}

	return traceHeaders
}

// InjectTraceHeaders 将追踪头部注入到请求中
func (m *Manager) InjectTraceHeaders(r *http.Request, traceHeaders map[string]string) {
	for headerName, value := range traceHeaders {
		r.Header.Set(headerName, value)
	}

	if len(traceHeaders) > 0 && m.log != nil {
		m.log.Debugf("Injected trace headers for %s: %v", r.Host, traceHeaders)
	}
}
