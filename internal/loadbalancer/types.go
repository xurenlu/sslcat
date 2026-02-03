package loadbalancer

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Algorithm 负载均衡算法类型
type Algorithm string

const (
	// RoundRobin 轮询算法
	RoundRobin Algorithm = "round_robin"
	// LeastConnections 最少连接算法
	LeastConnections Algorithm = "least_conn"
	// IPHash IP哈希算法
	IPHash Algorithm = "ip_hash"
	// Random 随机算法
	Random Algorithm = "random"
	// WeightedRoundRobin 加权轮询算法
	WeightedRoundRobin Algorithm = "weighted_round_robin"
	// ConsistentHash 一致性哈希算法
	ConsistentHash Algorithm = "consistent_hash"
)

// Backend 后端服务器定义
type Backend struct {
	// 基本配置
	ID       string `json:"id"`       // 后端唯一标识
	Host     string `json:"host"`     // 主机地址
	Port     int    `json:"port"`     // 端口
	Weight   int    `json:"weight"`   // 权重，默认为1
	Priority int    `json:"priority"` // 优先级，数字越小优先级越高

	// 健康检查配置
	HealthCheckEnabled  bool          `json:"health_check_enabled"`  // 是否启用健康检查
	HealthCheckPath     string        `json:"health_check_path"`     // 健康检查路径，默认"/"
	HealthCheckInterval time.Duration `json:"health_check_interval"` // 检查间隔，默认30秒
	HealthCheckTimeout  time.Duration `json:"health_check_timeout"`  // 检查超时，默认5秒
	HealthCheckMethod   string        `json:"health_check_method"`   // 检查方法，默认GET
	ExpectedStatusCode  int           `json:"expected_status_code"`  // 期望的状态码，默认200

	// 故障转移配置
	MaxRetries         int           `json:"max_retries"`          // 最大重试次数
	RetryInterval      time.Duration `json:"retry_interval"`       // 重试间隔
	FailureThreshold   int           `json:"failure_threshold"`    // 故障阈值
	RecoveryThreshold  int           `json:"recovery_threshold"`   // 恢复阈值
	CircuitBreakerOpen bool          `json:"circuit_breaker_open"` // 熔断器状态

	// 运行时状态
	healthy           int64     `json:"is_healthy"`         // 是否健康，使用atomic操作
	ActiveConnections int64     `json:"active_connections"` // 活跃连接数
	TotalRequests     int64     `json:"total_requests"`     // 总请求数
	FailedRequests    int64     `json:"failed_requests"`    // 失败请求数
	LastHealthCheck   time.Time `json:"last_health_check"`  // 最后健康检查时间
	LastFailure       time.Time `json:"last_failure"`       // 最后失败时间
	ResponseTime      int64     `json:"response_time"`      // 平均响应时间（毫秒）

	// 连接配置
	MaxConnections      int           `json:"max_connections"`       // 最大连接数，0表示无限制
	ConnectTimeout      time.Duration `json:"connect_timeout"`       // 连接超时
	ReadTimeout         time.Duration `json:"read_timeout"`          // 读取超时
	WriteTimeout        time.Duration `json:"write_timeout"`         // 写入超时
	KeepAliveTimeout    time.Duration `json:"keep_alive_timeout"`    // 长连接超时
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout"`     // 空闲连接超时
	TLSHandshakeTimeout time.Duration `json:"tls_handshake_timeout"` // TLS握手超时

	// SSL/TLS配置
	TLSEnabled        bool   `json:"tls_enabled"`          // 是否启用TLS
	TLSInsecure       bool   `json:"tls_insecure"`         // 是否跳过TLS验证
	TLSServerName     string `json:"tls_server_name"`      // TLS服务器名称
	TLSClientCertFile string `json:"tls_client_cert_file"` // 客户端证书文件
	TLSClientKeyFile  string `json:"tls_client_key_file"`  // 客户端私钥文件
	TLSCACertFile     string `json:"tls_ca_cert_file"`     // CA证书文件

	// 高级配置
	Metadata map[string]string `json:"metadata"` // 元数据，用于存储自定义信息
}

// LoadBalancerConfig 负载均衡器配置
type LoadBalancerConfig struct {
	// 基本配置
	Algorithm Algorithm `json:"algorithm"` // 负载均衡算法
	Backends  []Backend `json:"backends"`  // 后端服务器列表

	// 健康检查配置
	HealthCheckEnabled  bool          `json:"health_check_enabled"`  // 全局健康检查开关
	HealthCheckInterval time.Duration `json:"health_check_interval"` // 全局健康检查间隔
	HealthCheckTimeout  time.Duration `json:"health_check_timeout"`  // 全局健康检查超时

	// 会话保持配置
	SessionAffinityEnabled bool   `json:"session_affinity_enabled"` // 是否启用会话保持
	SessionAffinityMethod  string `json:"session_affinity_method"`  // 会话保持方法：cookie, header, ip
	SessionAffinityCookie  string `json:"session_affinity_cookie"`  // Cookie名称
	SessionAffinityHeader  string `json:"session_affinity_header"`  // Header名称
	SessionAffinityTTL     int    `json:"session_affinity_ttl"`     // 会话保持时间（秒）

	// 故障转移配置
	FailoverEnabled    bool          `json:"failover_enabled"`     // 是否启用故障转移
	FailoverTimeout    time.Duration `json:"failover_timeout"`     // 故障转移超时
	MaxRetries         int           `json:"max_retries"`          // 最大重试次数
	RetryInterval      time.Duration `json:"retry_interval"`       // 重试间隔
	CircuitBreakerOpen bool          `json:"circuit_breaker_open"` // 全局熔断器状态

	// 高级配置
	ConsistentHashReplicas int               `json:"consistent_hash_replicas"` // 一致性哈希虚拟节点数
	Metadata               map[string]string `json:"metadata"`                 // 元数据
}

// BackendStats 后端统计信息
type BackendStats struct {
	ID                  string        `json:"id"`
	Host                string        `json:"host"`
	Port                int           `json:"port"`
	IsHealthy           bool          `json:"is_healthy"`
	ActiveConnections   int64         `json:"active_connections"`
	TotalRequests       int64         `json:"total_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	SuccessRate         float64       `json:"success_rate"`
	AverageResponseTime int64         `json:"average_response_time"`
	LastHealthCheck     time.Time     `json:"last_health_check"`
	LastFailure         time.Time     `json:"last_failure"`
	Uptime              time.Duration `json:"uptime"`
}

// LoadBalancerStats 负载均衡器统计信息
type LoadBalancerStats struct {
	Algorithm           Algorithm      `json:"algorithm"`
	TotalBackends       int            `json:"total_backends"`
	HealthyBackends     int            `json:"healthy_backends"`
	UnhealthyBackends   int            `json:"unhealthy_backends"`
	TotalRequests       int64          `json:"total_requests"`
	TotalFailures       int64          `json:"total_failures"`
	AverageResponseTime int64          `json:"average_response_time"`
	BackendStats        []BackendStats `json:"backend_stats"`
}

// BalancerInterface 负载均衡器接口
type BalancerInterface interface {
	// 选择后端服务器
	SelectBackend(req *http.Request) (*Backend, error)

	// 健康检查
	StartHealthCheck()
	StopHealthCheck()

	// 统计信息
	GetStats() LoadBalancerStats

	// 后端管理
	AddBackend(backend Backend) error
	RemoveBackend(backendID string) error
	UpdateBackend(backend Backend) error
	GetBackend(backendID string) (*Backend, error)
	GetAllBackends() []Backend

	// 会话保持
	GetSessionBackend(req *http.Request) (*Backend, error)
	SetSessionBackend(req *http.Request, backend *Backend) error

	// 事件回调
	OnBackendHealthChange(callback func(backend *Backend, isHealthy bool))
	OnBackendAdded(callback func(backend *Backend))
	OnBackendRemoved(callback func(backend *Backend))
}

// SelectionInfo 后端选择信息（用于调试 header 输出）
type SelectionInfo struct {
	FromSession bool   // 是否从已有会话中选择（会话保持命中）
	SessionID   string // 会话标识（用于调试）
}

// RequestContext 请求上下文信息
type RequestContext struct {
	Request      *http.Request
	ClientIP     string
	SessionID    string
	Headers      map[string]string
	Cookies      map[string]string
	Metadata     map[string]interface{}
	StartTime    time.Time
	Backend      *Backend
	AttemptCount int
	LastError    error
}

// IsHealthy 检查后端是否健康（线程安全）
func (b *Backend) IsHealthy() bool {
	return atomic.LoadInt64(&b.healthy) == 1
}

// SetHealthy 设置后端健康状态（线程安全）
func (b *Backend) SetHealthy(healthy bool) {
	if healthy {
		atomic.StoreInt64(&b.healthy, 1)
	} else {
		atomic.StoreInt64(&b.healthy, 0)
	}
}

// IncrementConnections 增加活跃连接数（线程安全）
func (b *Backend) IncrementConnections() {
	atomic.AddInt64(&b.ActiveConnections, 1)
}

// DecrementConnections 减少活跃连接数（线程安全）
func (b *Backend) DecrementConnections() {
	atomic.AddInt64(&b.ActiveConnections, -1)
}

// IncrementRequests 增加总请求数（线程安全）
func (b *Backend) IncrementRequests() {
	atomic.AddInt64(&b.TotalRequests, 1)
}

// IncrementFailures 增加失败请求数（线程安全）
func (b *Backend) IncrementFailures() {
	atomic.AddInt64(&b.FailedRequests, 1)
}

// GetActiveConnections 获取活跃连接数（线程安全）
func (b *Backend) GetActiveConnections() int64 {
	return atomic.LoadInt64(&b.ActiveConnections)
}

// GetTotalRequests 获取总请求数（线程安全）
func (b *Backend) GetTotalRequests() int64 {
	return atomic.LoadInt64(&b.TotalRequests)
}

// GetFailedRequests 获取失败请求数（线程安全）
func (b *Backend) GetFailedRequests() int64 {
	return atomic.LoadInt64(&b.FailedRequests)
}

// GetSuccessRate 获取成功率
func (b *Backend) GetSuccessRate() float64 {
	total := b.GetTotalRequests()
	if total == 0 {
		return 0.0
	}
	failed := b.GetFailedRequests()
	return float64(total-failed) / float64(total) * 100.0
}

// UpdateResponseTime 更新平均响应时间（线程安全）
func (b *Backend) UpdateResponseTime(responseTime time.Duration) {
	atomic.StoreInt64(&b.ResponseTime, responseTime.Milliseconds())
}

// GetResponseTime 获取平均响应时间（线程安全）
func (b *Backend) GetResponseTime() time.Duration {
	return time.Duration(atomic.LoadInt64(&b.ResponseTime)) * time.Millisecond
}

// GetAddress 获取后端地址
func (b *Backend) GetAddress() string {
	if b.Port > 0 {
		return fmt.Sprintf("%s:%d", b.Host, b.Port)
	}
	return b.Host
}

// GetURL 获取后端URL
func (b *Backend) GetURL(path string) string {
	scheme := "http"
	if b.TLSEnabled {
		scheme = "https"
	}

	if path == "" {
		path = "/"
	}

	if b.Port > 0 {
		return fmt.Sprintf("%s://%s:%d%s", scheme, b.Host, b.Port, path)
	}
	return fmt.Sprintf("%s://%s%s", scheme, b.Host, path)
}
