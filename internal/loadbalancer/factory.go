package loadbalancer

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// BalancerFactory 负载均衡器工厂
type BalancerFactory struct{}

// NewBalancerFactory 创建负载均衡器工厂
func NewBalancerFactory() *BalancerFactory {
	return &BalancerFactory{}
}

// CreateBalancer 创建负载均衡器
func (f *BalancerFactory) CreateBalancer(config LoadBalancerConfig) (BalancerInterface, error) {
	// 验证配置
	if err := f.validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// 设置默认值
	config = f.setDefaults(config)

	// 创建负载均衡器
	balancer := NewLoadBalancer(config)

	// 如果启用了健康检查，启动健康检查
	if config.HealthCheckEnabled {
		balancer.StartHealthCheck()
	}

	return balancer, nil
}

// CreateSimpleRoundRobinBalancer 创建简单的轮询负载均衡器
func (f *BalancerFactory) CreateSimpleRoundRobinBalancer(backends []Backend) (BalancerInterface, error) {
	config := LoadBalancerConfig{
		Algorithm:           RoundRobin,
		Backends:            backends,
		HealthCheckEnabled:  true,
		HealthCheckInterval: 30 * time.Second,
		HealthCheckTimeout:  5 * time.Second,
	}

	return f.CreateBalancer(config)
}

// CreateWeightedBalancer 创建加权负载均衡器
func (f *BalancerFactory) CreateWeightedBalancer(backends []Backend) (BalancerInterface, error) {
	config := LoadBalancerConfig{
		Algorithm:           WeightedRoundRobin,
		Backends:            backends,
		HealthCheckEnabled:  true,
		HealthCheckInterval: 30 * time.Second,
		HealthCheckTimeout:  5 * time.Second,
	}

	return f.CreateBalancer(config)
}

// CreateLeastConnectionsBalancer 创建最少连接负载均衡器
func (f *BalancerFactory) CreateLeastConnectionsBalancer(backends []Backend) (BalancerInterface, error) {
	config := LoadBalancerConfig{
		Algorithm:           LeastConnections,
		Backends:            backends,
		HealthCheckEnabled:  true,
		HealthCheckInterval: 30 * time.Second,
		HealthCheckTimeout:  5 * time.Second,
	}

	return f.CreateBalancer(config)
}

// CreateIPHashBalancer 创建IP哈希负载均衡器
func (f *BalancerFactory) CreateIPHashBalancer(backends []Backend) (BalancerInterface, error) {
	config := LoadBalancerConfig{
		Algorithm:              IPHash,
		Backends:               backends,
		HealthCheckEnabled:     true,
		HealthCheckInterval:    30 * time.Second,
		HealthCheckTimeout:     5 * time.Second,
		SessionAffinityEnabled: true,
		SessionAffinityMethod:  "ip",
	}

	return f.CreateBalancer(config)
}

// CreateSessionAffinityBalancer 创建会话保持负载均衡器
func (f *BalancerFactory) CreateSessionAffinityBalancer(backends []Backend, method, cookieName string) (BalancerInterface, error) {
	config := LoadBalancerConfig{
		Algorithm:              RoundRobin,
		Backends:               backends,
		HealthCheckEnabled:     true,
		HealthCheckInterval:    30 * time.Second,
		HealthCheckTimeout:     5 * time.Second,
		SessionAffinityEnabled: true,
		SessionAffinityMethod:  method,
		SessionAffinityCookie:  cookieName,
		SessionAffinityTTL:     3600, // 1小时
	}

	return f.CreateBalancer(config)
}

// validateConfig 验证配置
func (f *BalancerFactory) validateConfig(config LoadBalancerConfig) error {
	// 检查是否有后端服务器
	if len(config.Backends) == 0 {
		return fmt.Errorf("no backends specified")
	}

	// 验证算法
	switch config.Algorithm {
	case RoundRobin, LeastConnections, IPHash, Random, WeightedRoundRobin, ConsistentHash:
		// 有效算法
	case "":
		// 空算法，将使用默认值
	default:
		return fmt.Errorf("unsupported algorithm: %s", config.Algorithm)
	}

	// 验证后端配置
	for i, backend := range config.Backends {
		if backend.Host == "" {
			return fmt.Errorf("backend %d: host is required", i)
		}
		if backend.Port <= 0 {
			return fmt.Errorf("backend %d: invalid port: %d", i, backend.Port)
		}
		if backend.Weight < 0 {
			return fmt.Errorf("backend %d: invalid weight: %d", i, backend.Weight)
		}
	}

	// 验证会话保持配置
	if config.SessionAffinityEnabled {
		switch config.SessionAffinityMethod {
		case "cookie":
			if config.SessionAffinityCookie == "" {
				return fmt.Errorf("session affinity cookie name is required when using cookie method")
			}
		case "header":
			if config.SessionAffinityHeader == "" {
				return fmt.Errorf("session affinity header name is required when using header method")
			}
		case "ip":
			// IP方法不需要额外配置
		case "":
			// 空方法，将使用默认值
		default:
			return fmt.Errorf("unsupported session affinity method: %s", config.SessionAffinityMethod)
		}
	}

	return nil
}

// setDefaults 设置默认值
func (f *BalancerFactory) setDefaults(config LoadBalancerConfig) LoadBalancerConfig {
	// 设置默认算法
	if config.Algorithm == "" {
		config.Algorithm = RoundRobin
	}

	// 设置默认健康检查配置
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.HealthCheckTimeout == 0 {
		config.HealthCheckTimeout = 5 * time.Second
	}

	// 设置默认会话保持配置
	if config.SessionAffinityEnabled && config.SessionAffinityMethod == "" {
		config.SessionAffinityMethod = "ip"
	}
	if config.SessionAffinityEnabled && config.SessionAffinityTTL == 0 {
		config.SessionAffinityTTL = 3600 // 1小时
	}

	// 设置默认故障转移配置
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = 1 * time.Second
	}

	// 设置一致性哈希默认值
	if config.ConsistentHashReplicas == 0 {
		config.ConsistentHashReplicas = 100
	}

	// 为每个后端设置默认值
	for i := range config.Backends {
		backend := &config.Backends[i]

		// 设置默认ID
		if backend.ID == "" {
			backend.ID = fmt.Sprintf("backend_%d", i)
		}

		// 设置默认权重
		if backend.Weight == 0 {
			backend.Weight = 1
		}

		// 设置默认健康检查配置
		if backend.HealthCheckPath == "" {
			backend.HealthCheckPath = "/"
		}
		if backend.HealthCheckInterval == 0 {
			backend.HealthCheckInterval = config.HealthCheckInterval
		}
		if backend.HealthCheckTimeout == 0 {
			backend.HealthCheckTimeout = config.HealthCheckTimeout
		}
		if backend.HealthCheckMethod == "" {
			backend.HealthCheckMethod = "GET"
		}
		if backend.ExpectedStatusCode == 0 {
			backend.ExpectedStatusCode = 200
		}

		// 设置默认连接配置
		if backend.ConnectTimeout == 0 {
			backend.ConnectTimeout = 30 * time.Second
		}
		if backend.ReadTimeout == 0 {
			backend.ReadTimeout = 30 * time.Second
		}
		if backend.WriteTimeout == 0 {
			backend.WriteTimeout = 30 * time.Second
		}
		if backend.KeepAliveTimeout == 0 {
			backend.KeepAliveTimeout = 30 * time.Second
		}
		if backend.IdleConnTimeout == 0 {
			backend.IdleConnTimeout = 90 * time.Second
		}
		if backend.TLSHandshakeTimeout == 0 {
			backend.TLSHandshakeTimeout = 10 * time.Second
		}

		// 设置默认故障转移配置
		if backend.MaxRetries == 0 {
			backend.MaxRetries = config.MaxRetries
		}
		if backend.RetryInterval == 0 {
			backend.RetryInterval = config.RetryInterval
		}
		if backend.FailureThreshold == 0 {
			backend.FailureThreshold = 3
		}
		if backend.RecoveryThreshold == 0 {
			backend.RecoveryThreshold = 2
		}

		// 初始化元数据
		if backend.Metadata == nil {
			backend.Metadata = make(map[string]string)
		}
	}

	// 初始化全局元数据
	if config.Metadata == nil {
		config.Metadata = make(map[string]string)
	}

	return config
}

// CreateFromBackendAddresses 从地址列表创建简单的负载均衡器
func (f *BalancerFactory) CreateFromBackendAddresses(addresses []string, algorithm Algorithm) (BalancerInterface, error) {
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no backend addresses specified")
	}

	var backends []Backend
	for i, addr := range addresses {
		// 解析地址
		host, port, err := f.parseAddress(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %s: %w", addr, err)
		}

		backend := Backend{
			ID:                 fmt.Sprintf("backend_%d", i),
			Host:               host,
			Port:               port,
			Weight:             1,
			HealthCheckEnabled: true,
		}

		backends = append(backends, backend)
	}

	config := LoadBalancerConfig{
		Algorithm:           algorithm,
		Backends:            backends,
		HealthCheckEnabled:  true,
		HealthCheckInterval: 30 * time.Second,
		HealthCheckTimeout:  5 * time.Second,
	}

	return f.CreateBalancer(config)
}

// parseAddress 解析地址字符串
func (f *BalancerFactory) parseAddress(addr string) (host string, port int, err error) {
	// 简单的地址解析，支持 "host:port" 格式
	// 在实际实现中，可以使用 net.SplitHostPort 等更完善的解析方法

	// 这里简化处理，假设地址格式为 "host:port"
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("address must be in format host:port")
	}

	host = parts[0]
	if host == "" {
		return "", 0, fmt.Errorf("host cannot be empty")
	}

	port, err = strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %w", err)
	}

	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("port must be between 1 and 65535")
	}

	return host, port, nil
}
