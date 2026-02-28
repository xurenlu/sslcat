package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/config"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// ServiceMeshType Service Mesh 类型
type ServiceMeshType string

const (
	ServiceMeshNone    ServiceMeshType = "none"     // 无 Service Mesh
	ServiceMeshIstio   ServiceMeshType = "istio"    // Istio
	ServiceMeshLinkerd ServiceMeshType = "linkerd"  // Linkerd
	ServiceMeshConsul  ServiceMeshType = "consul"   // Consul Connect
	ServiceMeshCustom  ServiceMeshType = "custom"   // 自定义
)

// ServiceMeshConfig Service Mesh 配置
type ServiceMeshConfig struct {
	Enabled bool             `json:"enabled"`
	Type    ServiceMeshType  `json:"type"`
	// Istio 配置
	Istio *IstioConfig `json:"istio,omitempty"`
	// Linkerd 配置
	Linkerd *LinkerdConfig `json:"linkerd,omitempty"`
	// Consul 配置
	Consul *ConsulConfig `json:"consul,omitempty"`
	// 通用配置
 ControlPlaneURL string        `json:"control_plane_url"`
	DiscoveryURL    string        `json:"discovery_url"`
	SidecarMode     bool          `json:"sidecar_mode"`
	SidecarPort     int           `json:"sidecar_port"`     // sidecar 代理端口，默认 15001
	EnablemTLS      bool          `json:"enable_mtls"`      // 启用 mesh mTLS
	ConnectTimeout  time.Duration `json:"connect_timeout"`
	RequestTimeout  time.Duration `json:"request_timeout"`
	// 服务发现配置
	ServiceDiscovery *ServiceDiscoveryConfig `json:"service_discovery,omitempty"`
	// 流量管理
	TrafficManagement *TrafficManagementConfig `json:"traffic_management,omitempty"`
}

// IstioConfig Istio 特定配置
type IstioConfig struct {
	PilotAddress    string `json:"pilot_address"`    // istiod.istio-system.svc:15012
	PilotPort       int    `json:"pilot_port"`       // 默认 15012
	EnableMtls      bool   `json:"enable_mtls"`      // 使用 Istio mTLS
	MtlsMode        string `json:"mtls_mode"`        // STRICT, PERMISSIVE
	PolicyEnabled   bool   `json:"policy_enabled"`   // 启用策略检查
	Telemetry       bool   `json:"telemetry"`        // 启用遥测
	TracingEnabled  bool   `json:"tracing_enabled"`  // 启用链路追踪
	TracingProvider string `json:"tracing_provider"` // jaeger, zipkin
}

// LinkerdConfig Linkerd 特定配置
type LinkerdConfig struct {
	ControlPlaneURL string `json:"control_plane_url"` // linkerd.istio-system:8088
	ProxyAPIURL     string `json:"proxy_api_url"`    // linkerd-proxy:4191
	EnableIdentity  bool   `json:"enable_identity"`  // 启用 SPIFFE 身份
}

// ConsulConfig Consul Connect 特定配置
type ConsulConfig struct {
	Address      string `json:"address"`       // consul.default.svc:8500
	Token        string `json:"token"`        // ACL token
	Datacenter   string `json:"datacenter"`   // 数据中心名称
	Namespace    string `json:"namespace"`    // 命名空间
	ConnectCA    string `json:"connect_ca"`   // CA 路径
	EnableTLS    bool   `json:"enable_tls"`
	TLSSkipVerify bool  `json:"tls_skip_verify"`
}

// ServiceDiscoveryConfig 服务发现配置
type ServiceDiscoveryConfig struct {
	Enabled          bool          `json:"enabled"`
	Type             string        `json:"type"`              // dns, consul, kubernetes, etcd
	RefreshInterval  time.Duration `json:"refresh_interval"`  // 刷新间隔
	HealthCheck      bool          `json:"health_check"`      // 启用健康检查
	HealthCheckPath  string        `json:"health_check_path"` // 健康检查路径
	HealthCheckInterval time.Duration `json:"health_check_interval"`
}

// TrafficManagementConfig 流量管理配置
type TrafficManagementConfig struct {
	CircuitBreaking *CircuitBreakingConfig `json:"circuit_breaking,omitempty"`
	Retry          *RetryConfig            `json:"retry,omitempty"`
	Timeout        *TimeoutConfig          `json:"timeout,omitempty"`
	RateLimiting   *RateLimitConfig        `json:"rate_limiting,omitempty"`
}

// CircuitBreakingConfig 熔断配置
type CircuitBreakingConfig struct {
	Enabled                bool          `json:"enabled"`
	MaxConnections         int           `json:"max_connections"`
	MaxPendingRequests     int           `json:"max_pending_requests"`
	MaxRequests            int           `json:"max_requests"`
	MaxRetries             int           `json:"max_retries"`
	ConsecutiveErrors      int           `json:"consecutive_errors"`      // 连续错误阈值
	Interval               time.Duration `json:"interval"`                // 统计间隔
	Timeout                time.Duration `json:"timeout"`                 // 熔断超时
	SleepWindow            time.Duration `json:"sleep_window"`            // 恢复睡眠窗口
}

// RetryConfig 重试配置
type RetryConfig struct {
	Enabled         bool          `json:"enabled"`
	MaxRetries      int           `json:"max_retries"`       // 最大重试次数
	PerTryTimeout   time.Duration `json:"per_try_timeout"`   // 每次尝试超时
	RetryOn         []string      `json:"retry_on"`          // 重试的 HTTP 状态码
	RetryBackoff    time.Duration `json:"retry_backoff"`     // 重试退避时间
}

// TimeoutConfig 超时配置
type TimeoutConfig struct {
	RequestTimeout  time.Duration `json:"request_timeout"`
	IdleTimeout     time.Duration `json:"idle_timeout"`
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	Enabled     bool          `json:"enabled"`
	RequestsPerUnit int       `json:"requests_per_unit"`
	Unit        time.Duration `json:"unit"`        // second, minute, hour
	Burst       int           `json:"burst"`
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Address    string            `json:"address"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`    // http, https, grpc
	Metadata   map[string]string `json:"metadata"`
	Labels     map[string]string `json:"labels"`
	Healthy    bool              `json:"healthy"`
	LastCheck  time.Time         `json:"last_check"`
	Version    string            `json:"version"`
	Cluster    string            `json:"cluster"`
}

// ServiceMeshManager Service Mesh 管理器
type ServiceMeshManager struct {
	config         *ServiceMeshConfig
	log            *logrus.Entry
	proxyManager   *Manager
	configManager  *config.Config

	// 服务发现
	serviceCache    map[string][]*ServiceInfo
	serviceMutex    sync.RWMutex

	// Circuit Breaker 状态
	breakerStates   map[string]*CircuitBreakerState
	breakerMutex    sync.RWMutex

	// 统计信息
	stats           ServiceMeshStats
	statsMutex      sync.RWMutex

	// HTTP 客户端（用于调用 mesh API）
	httpClient      *http.Client
	transport       *http.Transport

	// 健康检查
	stopHealthCheck chan struct{}
}

// CircuitBreakerState 熔断器状态
type CircuitBreakerState struct {
	Name            string        `json:"name"`
	State           string        `json:"state"`           // closed, open, half-open
	ConsecutiveErrors int         `json:"consecutive_errors"`
	LastStateChange  time.Time    `json:"last_state_change"`
	LastErrorTime    time.Time    `json:"last_error_time"`
	LastError        string       `json:"last_error"`
	RequestsTotal    int64        `json:"requests_total"`
	RequestsFailed   int64        `json:"requests_failed"`
}

// ServiceMeshStats Service Mesh 统计
type ServiceMeshStats struct {
	ServicesDiscovered int       `json:"services_discovered"`
	RequestsViaMesh    int64     `json:"requests_via_mesh"`
	RequestsDirect     int64     `json:"requests_direct"`
	RetriesAttempted   int64     `json:"retries_attempted"`
	CircuitBreakerTrips int64    `json:"circuit_breaker_trips"`
	LastDiscoveryTime  time.Time `json:"last_discovery_time"`
	MeshAPICalls       int64     `json:"mesh_api_calls"`
	MeshAPIErrors      int64     `json:"mesh_api_errors"`
}

// NewServiceMeshManager 创建 Service Mesh 管理器
func NewServiceMeshManager(cfg *ServiceMeshConfig, proxyMgr *Manager, configMgr *config.Config) *ServiceMeshManager {
	if !cfg.Enabled || cfg.Type == ServiceMeshNone {
		return nil
	}

	log := logrus.WithFields(logrus.Fields{
		"component": "service_mesh",
		"type":      cfg.Type,
	})

	// 创建 HTTP transport
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// 支持 HTTP/2
		ForceAttemptHTTP2:     true,
	}

	// 配置 HTTP/2
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Warnf("Failed to configure HTTP/2: %v", err)
	}

	mgr := &ServiceMeshManager{
		config:          cfg,
		log:             log,
		proxyManager:    proxyMgr,
		configManager:   configMgr,
		serviceCache:    make(map[string][]*ServiceInfo),
		breakerStates:   make(map[string]*CircuitBreakerState),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.RequestTimeout,
		},
		transport:       transport,
		stopHealthCheck: make(chan struct{}),
	}

	log.Infof("Service Mesh manager initialized: type=%s, sidecar=%v", cfg.Type, cfg.SidecarMode)

	// 启动服务发现
	if cfg.ServiceDiscovery != nil && cfg.ServiceDiscovery.Enabled {
		go mgr.startServiceDiscovery()
	}

	// 启动健康检查
	if cfg.ServiceDiscovery != nil && cfg.ServiceDiscovery.HealthCheck {
		go mgr.startHealthCheck()
	}

	return mgr
}

// startServiceDiscovery 启动服务发现
func (m *ServiceMeshManager) startServiceDiscovery() {
	interval := m.config.ServiceDiscovery.RefreshInterval
	if interval == 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	m.log.Infof("Service discovery started: interval=%v, type=%s", interval, m.config.ServiceDiscovery.Type)

	// 首次发现
	m.discoverServices()

	for {
		select {
		case <-ticker.C:
			m.discoverServices()
		case <-m.stopHealthCheck:
			return
		}
	}
}

// discoverServices 发现服务
func (m *ServiceMeshManager) discoverServices() {
	m.statsMutex.Lock()
	m.stats.MeshAPICalls++
	m.stats.MeshAPIErrors = 0 // 重置错误计数
	m.stats.LastDiscoveryTime = time.Now()
	m.statsMutex.Unlock()

	var services []*ServiceInfo
	var err error

	switch m.config.ServiceDiscovery.Type {
	case "consul":
		services, err = m.discoverConsul()
	case "kubernetes":
		services, err = m.discoverKubernetes()
	case "istio":
		services, err = m.discoverIstio()
	default:
		services, err = m.discoverDNS()
	}

	if err != nil {
		m.log.Errorf("Service discovery failed: %v", err)
		m.statsMutex.Lock()
		m.stats.MeshAPIErrors++
		m.statsMutex.Unlock()
		return
	}

	// 更新缓存
	m.serviceMutex.Lock()
	for _, svc := range services {
		key := svc.Name + ":" + svc.Namespace
		m.serviceCache[key] = append(m.serviceCache[key], svc)
	}
	m.serviceMutex.Unlock()

	m.statsMutex.Lock()
	m.stats.ServicesDiscovered = len(services)
	m.statsMutex.Unlock()

	m.log.Debugf("Discovered %d services", len(services))
}

// discoverConsul 从 Consul 发现服务
func (m *ServiceMeshManager) discoverConsul() ([]*ServiceInfo, error) {
	if m.config.Consul == nil {
		return nil, fmt.Errorf("Consul config not provided")
	}

	// 调用 Consul API
	// GET /v1/catalog/services
	url := fmt.Sprintf("%s/v1/catalog/services", m.config.Consul.Address)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if m.config.Consul.Token != "" {
		req.Header.Set("X-Consul-Token", m.config.Consul.Token)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Consul API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Consul API returned status %d", resp.StatusCode)
	}

	// 解析响应
	var services map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return nil, err
	}

	// 转换为 ServiceInfo
	result := make([]*ServiceInfo, 0)
	for name := range services {
		// 获取服务的详细信息和健康状态
		svcInfo, err := m.getConsulServiceHealth(name)
		if err != nil {
			m.log.Warnf("Failed to get health for service %s: %v", name, err)
			continue
		}
		result = append(result, svcInfo...)
	}

	return result, nil
}

// getConsulServiceHealth 获取 Consul 服务健康状态
func (m *ServiceMeshManager) getConsulServiceHealth(serviceName string) ([]*ServiceInfo, error) {
	url := fmt.Sprintf("%s/v1/health/service/%s", m.config.Consul.Address, serviceName)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if m.config.Consul.Token != "" {
		req.Header.Set("X-Consul-Token", m.config.Consul.Token)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var healthChecks []struct {
		Node    struct {
			Address string `json:"Address"`
		} `json:"Node"`
		Service struct {
			ID      string `json:"ID"`
			Service string `json:"Service"`
			Tags    []string `json:"Tags"`
			Address string `json:"Address"`
			Port    int    `json:"Port"`
		} `json:"Service"`
		Checks []struct {
			Status string `json:"Status"`
		} `json:"Checks"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&healthChecks); err != nil {
		return nil, err
	}

	result := make([]*ServiceInfo, 0)
	for _, check := range healthChecks {
		// 检查健康状态
		healthy := true
		for _, c := range check.Checks {
			if c.Status != "passing" {
				healthy = false
				break
			}
		}

		svc := &ServiceInfo{
			Name:      check.Service.Service,
			Namespace: m.config.Consul.Datacenter,
			Address:   check.Service.Address,
			Port:      check.Service.Port,
			Protocol:  "http",
			Healthy:   healthy,
			LastCheck: time.Now(),
			Version:   "1",
			Cluster:   m.config.Consul.Datacenter,
		}

		result = append(result, svc)
	}

	return result, nil
}

// discoverKubernetes 从 Kubernetes 发现服务
func (m *ServiceMeshManager) discoverKubernetes() ([]*ServiceInfo, error) {
	// TODO: 实现 Kubernetes 服务发现
	// 使用 K8s API 或环境变量 (KUBERNETES_SERVICE_HOST)
	return nil, fmt.Errorf("Kubernetes service discovery not implemented")
}

// discoverIstio 从 Istio 发现服务
func (m *ServiceMeshManager) discoverIstio() ([]*ServiceInfo, error) {
	if m.config.Istio == nil {
		return nil, fmt.Errorf("Istio config not provided")
	}

	// 调用 Istio Pilot API
	// GET /v1/registration
	url := fmt.Sprintf("http://%s:%d/v1/registration",
		strings.Split(m.config.Istio.PilotAddress, ":")[0],
		m.config.Istio.PilotPort)

	resp, err := m.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Istio Pilot API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Istio Pilot API returned status %d", resp.StatusCode)
	}

	// 解析响应
	var services struct {
		Services []struct {
			Host      string `json:"Host"`
			Addresses struct {
				Address []string `json:"Address"`
			} `json:"Addresses"`
			Ports []struct {
				Name     string `json:"name"`
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
			} `json:"Ports"`
		} `json:"Services"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return nil, err
	}

	result := make([]*ServiceInfo, 0)
	for _, svc := range services.Services {
		for _, portInfo := range svc.Ports {
			svcInfo := &ServiceInfo{
				Name:      svc.Host,
				Namespace: "default", // TODO: 从 hostname 解析
				Address:   svc.Addresses.Address[0],
				Port:      portInfo.Port,
				Protocol:  portInfo.Protocol,
				Healthy:   true,
				LastCheck: time.Now(),
				Version:   "1",
			}
			result = append(result, svcInfo)
		}
	}

	return result, nil
}

// discoverDNS 通过 DNS 发现服务
func (m *ServiceMeshManager) discoverDNS() ([]*ServiceInfo, error) {
	// DNS 服务发现 - 解析 SRV 记录
	// 格式: _service-name._proto.service.namespace.svc.cluster.local
	// 这是 Kubernetes 内部 DNS 的标准格式

	// TODO: 实现 DNS 服务发现
	return nil, fmt.Errorf("DNS service discovery not implemented")
}

// startHealthCheck 启动健康检查
func (m *ServiceMeshManager) startHealthCheck() {
	interval := m.config.ServiceDiscovery.HealthCheckInterval
	if interval == 0 {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	m.log.Infof("Health check started: interval=%v", interval)

	for {
		select {
		case <-ticker.C:
			m.checkAllServices()
		case <-m.stopHealthCheck:
			return
		}
	}
}

// checkAllServices 检查所有服务健康
func (m *ServiceMeshManager) checkAllServices() {
	m.serviceMutex.RLock()
	services := make(map[string][]*ServiceInfo)
	for k, v := range m.serviceCache {
		services[k] = v
	}
	m.serviceMutex.RUnlock()

	for key, svcList := range services {
		for _, svc := range svcList {
			healthy := m.checkServiceHealth(svc)
			if !healthy {
				m.log.Warnf("Service %s is unhealthy", key)
			}
		}
	}
}

// checkServiceHealth 检查单个服务健康
func (m *ServiceMeshManager) checkServiceHealth(svc *ServiceInfo) bool {
	if m.config.ServiceDiscovery.HealthCheckPath == "" {
		return true
	}

	scheme := "http"
	if svc.Protocol == "https" || svc.Protocol == "grpcs" {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, svc.Address, svc.Port, m.config.ServiceDiscovery.HealthCheckPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetServiceEndpoint 获取服务端点
func (m *ServiceMeshManager) GetServiceEndpoint(serviceName string) (string, error) {
	if m == nil || !m.config.Enabled {
		return "", fmt.Errorf("service mesh not enabled")
	}

	m.serviceMutex.RLock()
	defer m.serviceMutex.RUnlock()

	// 查找缓存
	for key, svcList := range m.serviceCache {
		if strings.HasPrefix(key, serviceName) {
			for _, svc := range svcList {
				if svc.Healthy {
					// 构造端点 URL
					scheme := "http"
					if svc.Protocol == "https" || svc.Protocol == "grpcs" {
						scheme = "https"
					}
					return fmt.Sprintf("%s://%s:%d", scheme, svc.Address, svc.Port), nil
				}
			}
		}
	}

	return "", fmt.Errorf("service not found: %s", serviceName)
}

// ShouldUseMesh 判断请求是否应该通过 Service Mesh
func (m *ServiceMeshManager) ShouldUseMesh(req *http.Request) bool {
	if m == nil || !m.config.Enabled {
		return false
	}

	// 检查目标服务是否在 mesh 中
	target := req.URL.Hostname()

	// 检查是否是内部服务
	if m.isInternalService(target) {
		return true
	}

	// 检查特定服务的路由
	for key := range m.serviceCache {
		serviceName := strings.Split(key, ":")[0]
		if strings.Contains(target, serviceName) {
			return true
		}
	}

	return false
}

// isInternalService 判断是否是内部服务
func (m *ServiceMeshManager) isInternalService(host string) bool {
	// 检查常见的内部服务后缀
	internalSuffixes := []string{
		".svc.cluster.local",
		".svc",
		".local",
	}

	for _, suffix := range internalSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	return false
}

// ProxyViaMesh 通过 Service Mesh 代理请求
func (m *ServiceMeshManager) ProxyViaMesh(req *http.Request) (*http.Response, error) {
	if m == nil {
		return nil, fmt.Errorf("service mesh not available")
	}

	m.statsMutex.Lock()
	m.stats.RequestsViaMesh++
	m.statsMutex.Unlock()

	// 检查熔断器
	if err := m.checkCircuitBreaker(req.URL.Hostname()); err != nil {
		return nil, err
	}

	// 根据 mesh 类型处理
	switch m.config.Type {
	case ServiceMeshIstio:
		return m.proxyViaIstio(req)
	case ServiceMeshLinkerd:
		return m.proxyViaLinkerd(req)
	default:
		// 通用处理
		return m.proxyViaSidecar(req)
	}
}

// checkCircuitBreaker 检查熔断器
func (m *ServiceMeshManager) checkCircuitBreaker(service string) error {
	if m.config.TrafficManagement == nil ||
	   m.config.TrafficManagement.CircuitBreaking == nil ||
	   !m.config.TrafficManagement.CircuitBreaking.Enabled {
		return nil
	}

	m.breakerMutex.Lock()
	defer m.breakerMutex.Unlock()

	state, exists := m.breakerStates[service]
	if !exists {
		state = &CircuitBreakerState{
			Name:             service,
			State:            "closed",
			LastStateChange:  time.Now(),
		}
		m.breakerStates[service] = state
	}

	// 检查熔断器状态
	if state.State == "open" {
		// 检查是否可以尝试恢复
		if time.Since(state.LastStateChange) > m.config.TrafficManagement.CircuitBreaking.SleepWindow {
			state.State = "half-open"
			m.log.Infof("Circuit breaker for %s transitioned to half-open", service)
		} else {
			m.statsMutex.Lock()
			m.stats.CircuitBreakerTrips++
			m.statsMutex.Unlock()
			return fmt.Errorf("circuit breaker open for service %s", service)
		}
	}

	return nil
}

// recordRequestResult 记录请求结果（用于熔断器）
func (m *ServiceMeshManager) recordRequestResult(service string, success bool) {
	if m.config.TrafficManagement == nil ||
	   m.config.TrafficManagement.CircuitBreaking == nil ||
	   !m.config.TrafficManagement.CircuitBreaking.Enabled {
		return
	}

	m.breakerMutex.Lock()
	defer m.breakerMutex.Unlock()

	state, exists := m.breakerStates[service]
	if !exists {
		return
	}

	state.RequestsTotal++
	if !success {
		state.RequestsFailed++
		state.ConsecutiveErrors++
		state.LastErrorTime = time.Now()

		// 检查是否需要熔断
		if state.ConsecutiveErrors >= m.config.TrafficManagement.CircuitBreaking.ConsecutiveErrors {
			state.State = "open"
			state.LastStateChange = time.Now()
			m.log.Warnf("Circuit breaker opened for service %s after %d consecutive errors",
				service, state.ConsecutiveErrors)

			m.statsMutex.Lock()
			m.stats.CircuitBreakerTrips++
			m.statsMutex.Unlock()
		}
	} else {
		// 成功请求，重置错误计数
		if state.State == "half-open" {
			state.State = "closed"
			state.LastStateChange = time.Now()
			m.log.Infof("Circuit breaker for %s closed after successful request", service)
		}
		state.ConsecutiveErrors = 0
	}
}

// proxyViaIstio 通过 Istio 代理请求
func (m *ServiceMeshManager) proxyViaIstio(req *http.Request) (*http.Response, error) {
	// 添加 Istio 特定的 headers
	m.addIstioHeaders(req)

	// Istio sidecar 通常在 localhost:15001
	sidecarURL := fmt.Sprintf("http://127.0.0.1:%d%s", m.config.SidecarPort, req.URL.Path)

	proxyReq, err := http.NewRequest(req.Method, sidecarURL, req.Body)
	if err != nil {
		return nil, err
	}

	// 复制原始 headers
	for k, v := range req.Header {
		proxyReq.Header[k] = v
	}

	// 添加 Istio headers
	m.addIstioHeaders(proxyReq)

	resp, err := m.httpClient.Do(proxyReq)
	if err != nil {
		m.recordRequestResult(req.URL.Hostname(), false)
		return nil, err
	}

	// 处理重试
	if m.shouldRetry(resp) && m.config.TrafficManagement.Retry != nil && m.config.TrafficManagement.Retry.Enabled {
		m.statsMutex.Lock()
		m.stats.RetriesAttempted++
		m.statsMutex.Unlock()

		// 关闭原始响应
		resp.Body.Close()

		// 等待退避时间
		time.Sleep(m.config.TrafficManagement.Retry.RetryBackoff)

		// 重试
		return m.proxyViaIstio(req)
	}

	m.recordRequestResult(req.URL.Hostname(), true)
	return resp, nil
}

// addIstioHeaders 添加 Istio 特定的 headers
func (m *ServiceMeshManager) addIstioHeaders(req *http.Request) {
	// 添加 mesh 相关的 headers
	req.Header.Set("x-envoy-upstream-service-time", strconv.FormatInt(time.Now().UnixMilli(), 10))

	// 添加服务信息
	if m.config.Istio != nil && m.config.Istio.Telemetry {
		req.Header.Set("x-b3-traceid", generateTraceID())
		req.Header.Set("x-b3-spanid", generateSpanID())
	}
}

// proxyViaLinkerd 通过 Linkerd 代理请求
func (m *ServiceMeshManager) proxyViaLinkerd(req *http.Request) (*http.Response, error) {
	// Linkerd 使用类似的 sidecar 模式
	// 默认端口 4143 (proxy outbound)
	sidecarPort := 4143
	if m.config.SidecarPort > 0 {
		sidecarPort = m.config.SidecarPort
	}

	sidecarURL := fmt.Sprintf("http://127.0.0.1:%d%s", sidecarPort, req.URL.Path)

	proxyReq, err := http.NewRequest(req.Method, sidecarURL, req.Body)
	if err != nil {
		return nil, err
	}

	// 复制原始 headers
	for k, v := range req.Header {
		proxyReq.Header[k] = v
	}

	// 添加 Linkerd 特定的 headers
	proxyReq.Header.Set("l5d-dst-canonical", req.URL.Host)

	resp, err := m.httpClient.Do(proxyReq)
	if err != nil {
		m.recordRequestResult(req.URL.Hostname(), false)
		return nil, err
	}

	m.recordRequestResult(req.URL.Hostname(), true)
	return resp, nil
}

// proxyViaSidecar 通过通用 sidecar 代理请求
func (m *ServiceMeshManager) proxyViaSidecar(req *http.Request) (*http.Response, error) {
	if !m.config.SidecarMode {
		return nil, fmt.Errorf("sidecar mode not enabled")
	}

	sidecarURL := fmt.Sprintf("http://127.0.0.1:%d%s", m.config.SidecarPort, req.URL.RequestURI())

	proxyReq, err := http.NewRequest(req.Method, sidecarURL, req.Body)
	if err != nil {
		return nil, err
	}

	// 复制原始 headers
	for k, v := range req.Header {
		proxyReq.Header[k] = v
	}

	resp, err := m.httpClient.Do(proxyReq)
	if err != nil {
		m.recordRequestResult(req.URL.Hostname(), false)
		return nil, err
	}

	m.recordRequestResult(req.URL.Hostname(), true)
	return resp, nil
}

// shouldRetry 判断是否应该重试
func (m *ServiceMeshManager) shouldRetry(resp *http.Response) bool {
	if m.config.TrafficManagement == nil ||
	   m.config.TrafficManagement.Retry == nil ||
	   !m.config.TrafficManagement.Retry.Enabled {
		return false
	}

	for _, code := range m.config.TrafficManagement.Retry.RetryOn {
		if strconv.Itoa(resp.StatusCode) == code {
			return true
		}
	}

	return false
}

// GetStats 获取统计信息
func (m *ServiceMeshManager) GetStats() ServiceMeshStats {
	if m == nil {
		return ServiceMeshStats{}
	}

	m.statsMutex.RLock()
	defer m.statsMutex.RUnlock()

	return m.stats
}

// GetServices 获取所有服务
func (m *ServiceMeshManager) GetServices() []*ServiceInfo {
	if m == nil {
		return nil
	}

	m.serviceMutex.RLock()
	defer m.serviceMutex.RUnlock()

	result := make([]*ServiceInfo, 0)
	for _, svcList := range m.serviceCache {
		result = append(result, svcList...)
	}

	return result
}

// GetCircuitBreakerStates 获取熔断器状态
func (m *ServiceMeshManager) GetCircuitBreakerStates() map[string]*CircuitBreakerState {
	if m == nil {
		return nil
	}

	m.breakerMutex.RLock()
	defer m.breakerMutex.RUnlock()

	result := make(map[string]*CircuitBreakerState, len(m.breakerStates))
	for k, v := range m.breakerStates {
		result[k] = v
	}

	return result
}

// ResetCircuitBreaker 重置熔断器
func (m *ServiceMeshManager) ResetCircuitBreaker(service string) {
	if m == nil {
		return
	}

	m.breakerMutex.Lock()
	defer m.breakerMutex.Unlock()

	if state, exists := m.breakerStates[service]; exists {
		state.State = "closed"
		state.ConsecutiveErrors = 0
		state.LastStateChange = time.Now()
		m.log.Infof("Circuit breaker for %s manually reset", service)
	}
}

// UpdateConfig 更新配置
func (m *ServiceMeshManager) UpdateConfig(cfg *ServiceMeshConfig) {
	if m == nil {
		return
	}

	m.log.Info("Updating Service Mesh configuration")
	m.config = cfg

	// 重新启动服务发现
	if cfg.ServiceDiscovery != nil && cfg.ServiceDiscovery.Enabled {
		go m.startServiceDiscovery()
	}

	if cfg.ServiceDiscovery != nil && cfg.ServiceDiscovery.HealthCheck {
		go m.startHealthCheck()
	}
}

// Stop 停止管理器
func (m *ServiceMeshManager) Stop() {
	if m == nil {
		return
	}

	close(m.stopHealthCheck)
	m.log.Info("Service Mesh manager stopped")
}

// GetConfig 获取配置
func (m *ServiceMeshManager) GetConfig() *ServiceMeshConfig {
	if m == nil {
		return nil
	}
	return m.config
}

// generateTraceID 生成 trace ID
func generateTraceID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// generateSpanID 生成 span ID
func generateSpanID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano()%1000000)
}
