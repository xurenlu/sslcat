package loadbalancer

import (
	"crypto/md5"
	"fmt"
	"hash/crc32"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// LoadBalancer 负载均衡器实现
type LoadBalancer struct {
	config   LoadBalancerConfig
	backends []Backend
	mutex    sync.RWMutex
	log      *logrus.Entry

	// 算法相关状态
	roundRobinIndex int64
	sessionStore    map[string]string // sessionID -> backendID
	sessionMutex    sync.RWMutex

	// 健康检查
	healthCheckTicker *time.Ticker
	healthCheckDone   chan bool

	// 统计信息
	totalRequests int64
	totalFailures int64

	// 事件回调
	onHealthChangeCb   func(backend *Backend, isHealthy bool)
	onBackendAddedCb   func(backend *Backend)
	onBackendRemovedCb func(backend *Backend)
}

// NewLoadBalancer 创建新的负载均衡器
func NewLoadBalancer(config LoadBalancerConfig) *LoadBalancer {
	lb := &LoadBalancer{
		config:       config,
		backends:     make([]Backend, len(config.Backends)),
		sessionStore: make(map[string]string),
		log: logrus.WithFields(logrus.Fields{
			"component": "loadbalancer",
			"algorithm": string(config.Algorithm),
		}),
	}

	// 复制后端配置并初始化状态
	copy(lb.backends, config.Backends)
	for i := range lb.backends {
		lb.backends[i].SetHealthy(true) // 初始状态为健康
		if lb.backends[i].Weight <= 0 {
			lb.backends[i].Weight = 1 // 默认权重为1
		}
		if lb.backends[i].ID == "" {
			lb.backends[i].ID = fmt.Sprintf("backend_%d", i)
		}
	}

	lb.log.Infof("Created load balancer with %d backends", len(lb.backends))
	return lb
}

// SelectBackend 选择后端服务器
func (lb *LoadBalancer) SelectBackend(req *http.Request) (*Backend, error) {
	backend, _, err := lb.SelectBackendWithInfo(req)
	return backend, err
}

// SelectBackendWithInfo 选择后端服务器并返回选择信息（用于调试 header）
func (lb *LoadBalancer) SelectBackendWithInfo(req *http.Request) (*Backend, *SelectionInfo, error) {
	atomic.AddInt64(&lb.totalRequests, 1)
	info := &SelectionInfo{}

	// 检查会话保持
	if lb.config.SessionAffinityEnabled {
		if backend, err := lb.GetSessionBackend(req); err == nil && backend != nil {
			if backend.IsHealthy() {
				info.FromSession = true
				info.SessionID = lb.getSessionID(req)
				backend.IncrementRequests()
				backend.IncrementConnections()
				return backend, info, nil
			}
		}
	}

	// 获取健康的后端列表
	healthyBackends := lb.getHealthyBackends()
	if len(healthyBackends) == 0 {
		atomic.AddInt64(&lb.totalFailures, 1)
		return nil, nil, fmt.Errorf("no healthy backends available")
	}

	var selectedBackend *Backend
	var err error

	switch lb.config.Algorithm {
	case RoundRobin:
		selectedBackend = lb.selectRoundRobin(healthyBackends)
	case LeastConnections:
		selectedBackend = lb.selectLeastConnections(healthyBackends)
	case IPHash:
		selectedBackend = lb.selectIPHash(req, healthyBackends)
	case Random:
		selectedBackend = lb.selectRandom(healthyBackends)
	case WeightedRoundRobin:
		selectedBackend = lb.selectWeightedRoundRobin(healthyBackends)
	case ConsistentHash:
		selectedBackend = lb.selectConsistentHash(req, healthyBackends)
	default:
		selectedBackend = lb.selectRoundRobin(healthyBackends)
	}

	if selectedBackend == nil {
		atomic.AddInt64(&lb.totalFailures, 1)
		return nil, nil, fmt.Errorf("failed to select backend")
	}

	// 设置会话保持
	if lb.config.SessionAffinityEnabled {
		_ = lb.SetSessionBackend(req, selectedBackend)
		info.SessionID = lb.getSessionID(req)
	}

	selectedBackend.IncrementRequests()
	selectedBackend.IncrementConnections()

	return selectedBackend, info, err
}

// getHealthyBackends 获取健康的后端列表
func (lb *LoadBalancer) getHealthyBackends() []Backend {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()

	var healthy []Backend
	for _, backend := range lb.backends {
		if backend.IsHealthy() {
			healthy = append(healthy, backend)
		}
	}
	return healthy
}

// selectRoundRobin 轮询算法
func (lb *LoadBalancer) selectRoundRobin(backends []Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	index := atomic.AddInt64(&lb.roundRobinIndex, 1) - 1
	return &backends[index%int64(len(backends))]
}

// selectLeastConnections 最少连接算法
func (lb *LoadBalancer) selectLeastConnections(backends []Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	minConnections := backends[0].GetActiveConnections()
	selectedIndex := 0

	for i, backend := range backends {
		connections := backend.GetActiveConnections()
		if connections < minConnections {
			minConnections = connections
			selectedIndex = i
		}
	}

	return &backends[selectedIndex]
}

// selectIPHash IP哈希算法
func (lb *LoadBalancer) selectIPHash(req *http.Request, backends []Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	clientIP := lb.getClientIP(req)
	hash := crc32.ChecksumIEEE([]byte(clientIP))
	index := int(hash) % len(backends)

	return &backends[index]
}

// selectRandom 随机算法
func (lb *LoadBalancer) selectRandom(backends []Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	index := rand.Intn(len(backends))
	return &backends[index]
}

// selectWeightedRoundRobin 加权轮询算法
func (lb *LoadBalancer) selectWeightedRoundRobin(backends []Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	// 计算总权重
	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}

	if totalWeight == 0 {
		return lb.selectRoundRobin(backends)
	}

	// 使用轮询计数器选择
	counter := atomic.AddInt64(&lb.roundRobinIndex, 1) - 1
	target := int(counter) % totalWeight

	currentWeight := 0
	for i, backend := range backends {
		currentWeight += backend.Weight
		if target < currentWeight {
			return &backends[i]
		}
	}

	return &backends[0]
}

// selectConsistentHash 一致性哈希算法
func (lb *LoadBalancer) selectConsistentHash(req *http.Request, backends []Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}

	key := lb.getHashKey(req)
	hash := lb.hash(key)

	// 简化的一致性哈希实现
	// 在生产环境中，应该使用更完整的一致性哈希环
	index := int(hash) % len(backends)
	return &backends[index]
}

// getClientIP 获取客户端IP
func (lb *LoadBalancer) getClientIP(req *http.Request) string {
	// 检查 X-Forwarded-For 头
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 检查 X-Real-IP 头
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// 使用 RemoteAddr
	parts := strings.Split(req.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}

	return req.RemoteAddr
}

// getHashKey 获取哈希键
func (lb *LoadBalancer) getHashKey(req *http.Request) string {
	switch lb.config.SessionAffinityMethod {
	case "header":
		if lb.config.SessionAffinityHeader != "" {
			return req.Header.Get(lb.config.SessionAffinityHeader)
		}
	case "cookie":
		if lb.config.SessionAffinityCookie != "" {
			if cookie, err := req.Cookie(lb.config.SessionAffinityCookie); err == nil {
				return cookie.Value
			}
		}
	case "ip":
		return lb.getClientIP(req)
	}

	// 默认使用客户端IP
	return lb.getClientIP(req)
}

// hash 计算哈希值
func (lb *LoadBalancer) hash(key string) uint32 {
	h := md5.New()
	h.Write([]byte(key))
	sum := h.Sum(nil)
	return uint32(sum[0])<<24 + uint32(sum[1])<<16 + uint32(sum[2])<<8 + uint32(sum[3])
}

// GetSessionBackend 获取会话对应的后端
func (lb *LoadBalancer) GetSessionBackend(req *http.Request) (*Backend, error) {
	if !lb.config.SessionAffinityEnabled {
		return nil, fmt.Errorf("session affinity not enabled")
	}

	sessionID := lb.getSessionID(req)
	if sessionID == "" {
		return nil, fmt.Errorf("no session ID found")
	}

	lb.sessionMutex.RLock()
	backendID, exists := lb.sessionStore[sessionID]
	lb.sessionMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no backend found for session")
	}

	// 查找对应的后端
	backend, err := lb.GetBackend(backendID)
	if err != nil {
		// 清理无效的会话
		lb.sessionMutex.Lock()
		delete(lb.sessionStore, sessionID)
		lb.sessionMutex.Unlock()
		return nil, err
	}

	return backend, nil
}

// SetSessionBackend 设置会话对应的后端
func (lb *LoadBalancer) SetSessionBackend(req *http.Request, backend *Backend) error {
	if !lb.config.SessionAffinityEnabled {
		return fmt.Errorf("session affinity not enabled")
	}

	sessionID := lb.getSessionID(req)
	if sessionID == "" {
		sessionID = lb.generateSessionID(req)
	}

	lb.sessionMutex.Lock()
	lb.sessionStore[sessionID] = backend.ID
	lb.sessionMutex.Unlock()

	return nil
}

// getSessionID 获取会话ID
func (lb *LoadBalancer) getSessionID(req *http.Request) string {
	switch lb.config.SessionAffinityMethod {
	case "cookie":
		if lb.config.SessionAffinityCookie != "" {
			if cookie, err := req.Cookie(lb.config.SessionAffinityCookie); err == nil {
				return cookie.Value
			}
		}
	case "header":
		if lb.config.SessionAffinityHeader != "" {
			return req.Header.Get(lb.config.SessionAffinityHeader)
		}
	case "ip":
		return lb.getClientIP(req)
	}

	// 默认使用客户端IP作为会话ID
	return lb.getClientIP(req)
}

// generateSessionID 生成会话ID
func (lb *LoadBalancer) generateSessionID(req *http.Request) string {
	// 使用时间戳和客户端IP生成唯一ID
	clientIP := lb.getClientIP(req)
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%s_%d", clientIP, timestamp)
}

// AddBackend 添加后端服务器
func (lb *LoadBalancer) AddBackend(backend Backend) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	// 检查是否已存在相同ID的后端
	for _, existing := range lb.backends {
		if existing.ID == backend.ID {
			return fmt.Errorf("backend with ID %s already exists", backend.ID)
		}
	}

	// 设置默认值
	if backend.Weight <= 0 {
		backend.Weight = 1
	}
	backend.SetHealthy(true)

	lb.backends = append(lb.backends, backend)
	lb.log.Infof("Added backend: %s", backend.ID)

	// 触发事件回调
	if lb.onBackendAddedCb != nil {
		go lb.onBackendAddedCb(&backend)
	}

	return nil
}

// RemoveBackend 移除后端服务器
func (lb *LoadBalancer) RemoveBackend(backendID string) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	for i, backend := range lb.backends {
		if backend.ID == backendID {
			// 移除后端
			lb.backends = append(lb.backends[:i], lb.backends[i+1:]...)

			// 清理会话存储中的引用
			lb.sessionMutex.Lock()
			for sessionID, storedBackendID := range lb.sessionStore {
				if storedBackendID == backendID {
					delete(lb.sessionStore, sessionID)
				}
			}
			lb.sessionMutex.Unlock()

			lb.log.Infof("Removed backend: %s", backendID)

			// 触发事件回调
			if lb.onBackendRemovedCb != nil {
				go lb.onBackendRemovedCb(&backend)
			}

			return nil
		}
	}

	return fmt.Errorf("backend with ID %s not found", backendID)
}

// UpdateBackend 更新后端服务器
func (lb *LoadBalancer) UpdateBackend(updatedBackend Backend) error {
	lb.mutex.Lock()
	defer lb.mutex.Unlock()

	for i, backend := range lb.backends {
		if backend.ID == updatedBackend.ID {
			// 保留运行时状态
			updatedBackend.ActiveConnections = backend.ActiveConnections
			updatedBackend.TotalRequests = backend.TotalRequests
			updatedBackend.FailedRequests = backend.FailedRequests
			updatedBackend.LastHealthCheck = backend.LastHealthCheck
			updatedBackend.LastFailure = backend.LastFailure
			updatedBackend.ResponseTime = backend.ResponseTime

			// 如果权重没有设置，使用默认值
			if updatedBackend.Weight <= 0 {
				updatedBackend.Weight = 1
			}

			lb.backends[i] = updatedBackend
			lb.log.Infof("Updated backend: %s", updatedBackend.ID)
			return nil
		}
	}

	return fmt.Errorf("backend with ID %s not found", updatedBackend.ID)
}

// GetBackend 获取后端服务器
func (lb *LoadBalancer) GetBackend(backendID string) (*Backend, error) {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()

	for _, backend := range lb.backends {
		if backend.ID == backendID {
			return &backend, nil
		}
	}

	return nil, fmt.Errorf("backend with ID %s not found", backendID)
}

// GetAllBackends 获取所有后端服务器
func (lb *LoadBalancer) GetAllBackends() []Backend {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()

	backends := make([]Backend, len(lb.backends))
	copy(backends, lb.backends)
	return backends
}

// GetStats 获取统计信息
func (lb *LoadBalancer) GetStats() LoadBalancerStats {
	lb.mutex.RLock()
	defer lb.mutex.RUnlock()

	var healthyCount, unhealthyCount int
	var totalResponseTime int64
	var backendStats []BackendStats

	for _, backend := range lb.backends {
		if backend.IsHealthy() {
			healthyCount++
		} else {
			unhealthyCount++
		}

		totalResponseTime += backend.GetResponseTime().Milliseconds()

		backendStats = append(backendStats, BackendStats{
			ID:                  backend.ID,
			Host:                backend.Host,
			Port:                backend.Port,
			IsHealthy:           backend.IsHealthy(),
			ActiveConnections:   backend.GetActiveConnections(),
			TotalRequests:       backend.GetTotalRequests(),
			FailedRequests:      backend.GetFailedRequests(),
			SuccessRate:         backend.GetSuccessRate(),
			AverageResponseTime: backend.GetResponseTime().Milliseconds(),
			LastHealthCheck:     backend.LastHealthCheck,
			LastFailure:         backend.LastFailure,
		})
	}

	averageResponseTime := int64(0)
	if len(lb.backends) > 0 {
		averageResponseTime = totalResponseTime / int64(len(lb.backends))
	}

	return LoadBalancerStats{
		Algorithm:           lb.config.Algorithm,
		TotalBackends:       len(lb.backends),
		HealthyBackends:     healthyCount,
		UnhealthyBackends:   unhealthyCount,
		TotalRequests:       atomic.LoadInt64(&lb.totalRequests),
		TotalFailures:       atomic.LoadInt64(&lb.totalFailures),
		AverageResponseTime: averageResponseTime,
		BackendStats:        backendStats,
	}
}

// OnBackendHealthChange 设置健康状态变化回调
func (lb *LoadBalancer) OnBackendHealthChange(callback func(backend *Backend, isHealthy bool)) {
	lb.onHealthChangeCb = callback
}

// OnBackendAdded 设置后端添加回调
func (lb *LoadBalancer) OnBackendAdded(callback func(backend *Backend)) {
	lb.onBackendAddedCb = callback
}

// OnBackendRemoved 设置后端移除回调
func (lb *LoadBalancer) OnBackendRemoved(callback func(backend *Backend)) {
	lb.onBackendRemovedCb = callback
}

// 确保LoadBalancer实现了BalancerInterface接口
var _ BalancerInterface = (*LoadBalancer)(nil)
