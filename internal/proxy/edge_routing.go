package proxy

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// EdgeLocation 边缘节点位置
type EdgeLocation struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Region      string  `json:"region"`       // us-east, us-west, eu-central, ap-southeast, etc.
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Priority    int     `json:"priority"`     // 路由优先级，数字越小优先级越高
	Enabled     bool    `json:"enabled"`
	HealthCheck string  `json:"health_check"` // 健康检查URL
	Healthy     bool    `json:"healthy"`      // 当前健康状态
	LastCheck   time.Time `json:"last_check"`
}

// EdgeCluster 边缘集群
type EdgeCluster struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Locations   []*EdgeLocation `json:"locations"`
	LoadBalance string          `json:"load_balance"` // round_robin, latency_based, geo_proximity, weighted
	CreatedAt   time.Time       `json:"created_at"`
}

// EdgeRoutingConfig 边缘路由配置
type EdgeRoutingConfig struct {
	Enabled           bool          `json:"enabled"`
	DefaultClusterID  string        `json:"default_cluster_id"`
	FallbackStrategy  string        `json:"fallback_strategy"`  // local, any, closest
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	HealthCheckTimeout  time.Duration `json:"health_check_timeout"`
	MaxRetries        int           `json:"max_retries"`
	RetryDelay        time.Duration `json:"retry_delay"`
	LatencyThreshold  time.Duration `json:"latency_threshold"` // 延迟阈值，超过则认为节点不健康
}

// EdgeRoutingMetrics 边缘路由指标
type EdgeRoutingMetrics struct {
	TotalRequests     int64         `json:"total_requests"`
	RequestsByRegion  map[string]int64 `json:"requests_by_region"`
	RequestsByCluster map[string]int64 `json:"requests_by_cluster"`
	AvgLatency        map[string]time.Duration `json:"avg_latency"`
	FailedRequests    int64         `json:"failed_requests"`
	HealthCheckFailures int64       `json:"health_check_failures"`
}

// ClientLocation 客户端位置信息
type ClientLocation struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ASN       int     `json:"asn"` // 自治系统号
	ISP       string  `json:"isp"`
}

// EdgeRoutingManager 边缘路由管理器
type EdgeRoutingManager struct {
	config      *EdgeRoutingConfig
	clusters    map[string]*EdgeCluster
	locations   map[string]*EdgeLocation
	metrics     *EdgeRoutingMetrics
	geoIPCache  map[string]*ClientLocation
	client      *http.Client
	log         *logrus.Entry
	mutex       sync.RWMutex
	stopChan    chan struct{}
	manager     *Manager // 代理管理器引用
}

// NewEdgeRoutingManager 创建边缘路由管理器
func NewEdgeRoutingManager(config *EdgeRoutingConfig, manager *Manager) *EdgeRoutingManager {
	if config == nil {
		config = &EdgeRoutingConfig{
			Enabled:            true,
			FallbackStrategy:   "closest",
			HealthCheckInterval: 30 * time.Second,
			HealthCheckTimeout:  5 * time.Second,
			MaxRetries:         3,
			RetryDelay:         100 * time.Millisecond,
			LatencyThreshold:   500 * time.Millisecond,
		}
	}

	return &EdgeRoutingManager{
		config:     config,
		clusters:   make(map[string]*EdgeCluster),
		locations:  make(map[string]*EdgeLocation),
		geoIPCache: make(map[string]*ClientLocation),
		metrics: &EdgeRoutingMetrics{
			RequestsByRegion:  make(map[string]int64),
			RequestsByCluster: make(map[string]int64),
			AvgLatency:        make(map[string]time.Duration),
		},
		client: &http.Client{
			Timeout: config.HealthCheckTimeout,
		},
		log: logrus.WithFields(logrus.Fields{
			"component": "edge_routing",
		}),
		stopChan: make(chan struct{}),
		manager:  manager,
	}
}

// Start 启动边缘路由管理器
func (m *EdgeRoutingManager) Start() error {
	if !m.config.Enabled {
		m.log.Info("Edge routing is disabled")
		return nil
	}

	m.log.Info("Starting edge routing manager")

	// 不再初始化默认边缘节点，由用户手动添加
	// m.initDefaultEdges()

	// 启动健康检查
	go m.healthCheckLoop()

	// 启动指标清理
	go m.metricsCleanupLoop()

	return nil
}

// Stop 停止边缘路由管理器
func (m *EdgeRoutingManager) Stop() {
	m.log.Info("Stopping edge routing manager")
	close(m.stopChan)
}

// initDefaultEdges 初始化默认边缘节点
func (m *EdgeRoutingManager) initDefaultEdges() {
	// 创建默认集群
	defaultCluster := &EdgeCluster{
		ID:        "default",
		Name:      "Default Edge Cluster",
		Locations: []*EdgeLocation{},
		LoadBalance: "geo_proximity",
		CreatedAt: time.Now(),
	}

	// 添加默认边缘位置
	defaultLocations := []*EdgeLocation{
		{
			ID:        "us-east-1",
			Name:      "US East (N. Virginia)",
			Region:    "us-east",
			Country:   "US",
			City:      "Ashburn",
			Latitude:  39.0437,
			Longitude: -77.4875,
			Priority:  1,
			Enabled:   true,
			Healthy:   true,
			LastCheck: time.Now(),
		},
		{
			ID:        "us-west-2",
			Name:      "US West (Oregon)",
			Region:    "us-west",
			Country:   "US",
			City:      "Portland",
			Latitude:  45.5152,
			Longitude: -122.6784,
			Priority:  2,
			Enabled:   true,
			Healthy:   true,
			LastCheck: time.Now(),
		},
		{
			ID:        "eu-central-1",
			Name:      "EU (Frankfurt)",
			Region:    "eu-central",
			Country:   "DE",
			City:      "Frankfurt",
			Latitude:  50.1109,
			Longitude:  8.6821,
			Priority:  3,
			Enabled:   true,
			Healthy:   true,
			LastCheck: time.Now(),
		},
		{
			ID:        "ap-southeast-1",
			Name:      "Asia Pacific (Singapore)",
			Region:    "ap-southeast",
			Country:   "SG",
			City:      "Singapore",
			Latitude:  1.3521,
			Longitude:  103.8198,
			Priority:  4,
			Enabled:   true,
			Healthy:   true,
			LastCheck: time.Now(),
		},
		{
			ID:        "ap-northeast-1",
			Name:      "Asia Pacific (Tokyo)",
			Region:    "ap-northeast",
			Country:   "JP",
			City:      "Tokyo",
			Latitude:  35.6762,
			Longitude:  139.6503,
			Priority:  5,
			Enabled:   true,
			Healthy:   true,
			LastCheck: time.Now(),
		},
	}

	for _, loc := range defaultLocations {
		defaultCluster.Locations = append(defaultCluster.Locations, loc)
		m.locations[loc.ID] = loc
	}

	m.clusters[defaultCluster.ID] = defaultCluster
	m.config.DefaultClusterID = defaultCluster.ID

	m.log.Infof("Initialized %d edge locations in cluster %s", len(defaultLocations), defaultCluster.ID)
}

// SelectBestEdge 选择最佳边缘节点
func (m *EdgeRoutingManager) SelectBestEdge(req *http.Request, clientIP string) (*EdgeLocation, error) {
	if !m.config.Enabled {
		return nil, fmt.Errorf("edge routing is disabled")
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 获取客户端位置
	clientLoc := m.getClientLocation(clientIP, req)

	// 获取默认集群
	cluster, exists := m.clusters[m.config.DefaultClusterID]
	if !exists {
		return nil, fmt.Errorf("default cluster not found")
	}

	// 根据负载均衡策略选择边缘节点
	var bestLocation *EdgeLocation

	switch cluster.LoadBalance {
	case "geo_proximity":
		bestLocation = m.selectByGeoProximity(cluster, clientLoc)
	case "latency_based":
		bestLocation = m.selectByLatency(cluster, clientLoc)
	case "round_robin":
		bestLocation = m.selectRoundRobin(cluster)
	case "weighted":
		bestLocation = m.selectWeighted(cluster)
	default:
		bestLocation = m.selectByGeoProximity(cluster, clientLoc)
	}

	if bestLocation == nil {
		// 如果没有找到合适的边缘节点，使用第一个健康节点
		for _, loc := range cluster.Locations {
			if loc.Enabled && loc.Healthy {
				bestLocation = loc
				break
			}
		}
	}

	if bestLocation == nil {
		return nil, fmt.Errorf("no healthy edge location available")
	}

	// 更新指标
	m.updateMetrics(bestLocation, clientLoc)

	return bestLocation, nil
}

// selectByGeoProximity 基于地理位置选择最近的边缘节点
func (m *EdgeRoutingManager) selectByGeoProximity(cluster *EdgeCluster, clientLoc *ClientLocation) *EdgeLocation {
	if clientLoc == nil {
		// 如果无法获取客户端位置，选择优先级最高的节点
		return m.selectByPriority(cluster)
	}

	var bestLocation *EdgeLocation
	minDistance := float64(1e9) // 初始化为一个大值

	for _, loc := range cluster.Locations {
		if !loc.Enabled || !loc.Healthy {
			continue
		}

		distance := m.calculateDistance(clientLoc.Latitude, clientLoc.Longitude, loc.Latitude, loc.Longitude)
		if distance < minDistance {
			minDistance = distance
			bestLocation = loc
		}
	}

	return bestLocation
}

// selectByLatency 基于延迟选择边缘节点
func (m *EdgeRoutingManager) selectByLatency(cluster *EdgeCluster, clientLoc *ClientLocation) *EdgeLocation {
	var bestLocation *EdgeLocation
	minLatency := time.Duration(1e9) // 初始化为大值

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, loc := range cluster.Locations {
		if !loc.Enabled || !loc.Healthy {
			continue
		}

		if avgLatency, exists := m.metrics.AvgLatency[loc.ID]; exists {
			if avgLatency < minLatency {
				minLatency = avgLatency
				bestLocation = loc
			}
		}
	}

	// 如果没有延迟数据，回退到地理位置选择
	if bestLocation == nil {
		return m.selectByGeoProximity(cluster, clientLoc)
	}

	return bestLocation
}

// selectRoundRobin 轮询选择边缘节点
func (m *EdgeRoutingManager) selectRoundRobin(cluster *EdgeCluster) *EdgeLocation {
	healthyLocations := make([]*EdgeLocation, 0)
	for _, loc := range cluster.Locations {
		if loc.Enabled && loc.Healthy {
			healthyLocations = append(healthyLocations, loc)
		}
	}

	if len(healthyLocations) == 0 {
		return nil
	}

	// 简单的轮询：使用请求计数取模
	index := int(m.metrics.TotalRequests) % len(healthyLocations)
	return healthyLocations[index]
}

// selectWeighted 基于权重选择边缘节点
func (m *EdgeRoutingManager) selectWeighted(cluster *EdgeCluster) *EdgeLocation {
	// 这里使用优先级作为权重，优先级越高权重越大
	var totalWeight int
	weightedLocations := make([]*EdgeLocation, 0)

	for _, loc := range cluster.Locations {
		if loc.Enabled && loc.Healthy {
			weight := 100 - loc.Priority // 优先级转换为权重
			totalWeight += weight
			for i := 0; i < weight; i++ {
				weightedLocations = append(weightedLocations, loc)
			}
		}
	}

	if len(weightedLocations) == 0 {
		return nil
	}

	// 随机选择
	index := int(m.metrics.TotalRequests) % len(weightedLocations)
	return weightedLocations[index]
}

// selectByPriority 按优先级选择边缘节点
func (m *EdgeRoutingManager) selectByPriority(cluster *EdgeCluster) *EdgeLocation {
	var bestLocation *EdgeLocation
	minPriority := int(1e9)

	for _, loc := range cluster.Locations {
		if !loc.Enabled || !loc.Healthy {
			continue
		}

		if loc.Priority < minPriority {
			minPriority = loc.Priority
			bestLocation = loc
		}
	}

	return bestLocation
}

// getClientLocation 获取客户端位置
func (m *EdgeRoutingManager) getClientLocation(clientIP string, req *http.Request) *ClientLocation {
	// 检查缓存
	if loc, exists := m.geoIPCache[clientIP]; exists {
		return loc
	}

	// 简化实现：从请求头获取位置信息
	// 实际生产环境中应该使用GeoIP数据库
	loc := &ClientLocation{
		IP: clientIP,
	}

	// 尝试从请求头获取地理位置信息
	if country := req.Header.Get("CF-IPCountry"); country != "" {
		loc.Country = country
	}
	if region := req.Header.Get("CF-Region"); region != "" {
		loc.Region = region
	}
	if city := req.Header.Get("CF-City"); city != "" {
		loc.City = city
	}

	// 如果没有Cloudflare头，使用简单的IP推断
	if loc.Country == "" {
		loc = m.inferLocationFromIP(clientIP)
	}

	// 缓存结果
	m.geoIPCache[clientIP] = loc

	return loc
}

// inferLocationFromIP 从IP推断位置（简化实现）
func (m *EdgeRoutingManager) inferLocationFromIP(ip string) *ClientLocation {
	loc := &ClientLocation{
		IP: ip,
	}

	// 简单的内网IP判断
	if isPrivateIP(ip) {
		loc.Country = "CN" // 默认为中国
		loc.Region = "local"
		return loc
	}

	// 基于IP段的大致推断
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return loc
	}

	// 简化的IP地理位置推断
	// 实际生产环境应使用MaxMind GeoIP2数据库
	if strings.Contains(ip, "192.168.") || strings.Contains(ip, "10.") {
		loc.Country = "CN"
		loc.Region = "local"
	} else {
		// 默认假设为美国
		loc.Country = "US"
		loc.Region = "us-east"
	}

	return loc
}

// isPrivateIP 判断是否为内网IP
func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// calculateDistance 计算两个经纬度之间的距离（Haversine公式）
func (m *EdgeRoutingManager) calculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371 // 地球半径，单位km

	// 转换为弧度
	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	deltaLat := (lat2 - lat1) * math.Pi / 180
	deltaLon := (lon2 - lon1) * math.Pi / 180

	// Haversine公式
	a := math.Pow(math.Sin(deltaLat/2), 2) + math.Cos(lat1Rad)*math.Cos(lat2Rad)*math.Pow(math.Sin(deltaLon/2), 2)
	c := 2 * math.Asin(math.Sqrt(a))

	return earthRadius * c
}

// updateMetrics 更新路由指标
func (m *EdgeRoutingManager) updateMetrics(location *EdgeLocation, clientLoc *ClientLocation) {
	m.metrics.TotalRequests++

	if location != nil {
		m.metrics.RequestsByCluster[m.config.DefaultClusterID]++
		m.metrics.RequestsByRegion[location.Region]++
	}

	if clientLoc != nil && clientLoc.Region != "" {
		m.metrics.RequestsByRegion[clientLoc.Region]++
	}
}

// healthCheckLoop 健康检查循环
func (m *EdgeRoutingManager) healthCheckLoop() {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performHealthChecks()
		case <-m.stopChan:
			return
		}
	}
}

// performHealthChecks 执行健康检查
func (m *EdgeRoutingManager) performHealthChecks() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, loc := range m.locations {
		if !loc.Enabled {
			continue
		}

		healthy := m.checkLocationHealth(loc)
		loc.Healthy = healthy
		loc.LastCheck = time.Now()

		if !healthy {
			m.metrics.HealthCheckFailures++
			m.log.Warnf("Health check failed for location %s", loc.ID)
		}
	}
}

// checkLocationHealth 检查单个位置的健康状态
func (m *EdgeRoutingManager) checkLocationHealth(loc *EdgeLocation) bool {
	if loc.HealthCheck == "" {
		// 如果没有配置健康检查URL，默认为健康
		return true
	}

	start := time.Now()
	resp, err := m.client.Get(loc.HealthCheck)
	if err != nil {
		m.log.Debugf("Health check error for %s: %v", loc.ID, err)
		return false
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	// 更新延迟指标
	m.metrics.AvgLatency[loc.ID] = latency

	// 检查HTTP状态码和延迟
	if resp.StatusCode != http.StatusOK {
		return false
	}

	if latency > m.config.LatencyThreshold {
		m.log.Debugf("Location %s latency exceeds threshold: %v", loc.ID, latency)
		return false
	}

	return true
}

// metricsCleanupLoop 指标清理循环
func (m *EdgeRoutingManager) metricsCleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupOldMetrics()
		case <-m.stopChan:
			return
		}
	}
}

// cleanupOldMetrics 清理旧指标
func (m *EdgeRoutingManager) cleanupOldMetrics() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 重置计数器
	m.metrics.FailedRequests = 0
	m.metrics.HealthCheckFailures = 0
}

// AddCluster 添加边缘集群
func (m *EdgeRoutingManager) AddCluster(cluster *EdgeCluster) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.clusters[cluster.ID]; exists {
		return fmt.Errorf("cluster %s already exists", cluster.ID)
	}

	m.clusters[cluster.ID] = cluster
	m.log.Infof("Added edge cluster: %s", cluster.ID)

	return nil
}

// RemoveCluster 移除边缘集群
func (m *EdgeRoutingManager) RemoveCluster(clusterID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.clusters[clusterID]; !exists {
		return fmt.Errorf("cluster %s not found", clusterID)
	}

	if clusterID == m.config.DefaultClusterID {
		return fmt.Errorf("cannot remove default cluster")
	}

	delete(m.clusters, clusterID)
	m.log.Infof("Removed edge cluster: %s", clusterID)

	return nil
}

// AddLocation 添加边缘位置
func (m *EdgeRoutingManager) AddLocation(clusterID string, location *EdgeLocation) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	cluster, exists := m.clusters[clusterID]
	if !exists {
		return fmt.Errorf("cluster %s not found", clusterID)
	}

	// 检查是否已存在
	for _, loc := range cluster.Locations {
		if loc.ID == location.ID {
			return fmt.Errorf("location %s already exists", location.ID)
		}
	}

	cluster.Locations = append(cluster.Locations, location)
	m.locations[location.ID] = location

	// 初始健康检查
	location.Healthy = m.checkLocationHealth(location)
	location.LastCheck = time.Now()

	m.log.Infof("Added edge location %s to cluster %s", location.ID, clusterID)

	return nil
}

// RemoveLocation 移除边缘位置
func (m *EdgeRoutingManager) RemoveLocation(locationID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.locations[locationID]; !exists {
		return fmt.Errorf("location %s not found", locationID)
	}

	// 从集群中移除
	for _, cluster := range m.clusters {
		for i, loc := range cluster.Locations {
			if loc.ID == locationID {
				cluster.Locations = append(cluster.Locations[:i], cluster.Locations[i+1:]...)
				break
			}
		}
	}

	delete(m.locations, locationID)
	m.log.Infof("Removed edge location: %s", locationID)

	return nil
}

// GetConfig 获取配置
func (m *EdgeRoutingManager) GetConfig() *EdgeRoutingConfig {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.config
}

// UpdateConfig 更新配置
func (m *EdgeRoutingManager) UpdateConfig(config *EdgeRoutingConfig) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.config = config
	m.log.Info("Edge routing configuration updated")
}

// GetClusters 获取所有集群
func (m *EdgeRoutingManager) GetClusters() map[string]*EdgeCluster {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]*EdgeCluster)
	for k, v := range m.clusters {
		result[k] = v
	}
	return result
}

// GetLocations 获取所有位置
func (m *EdgeRoutingManager) GetLocations() map[string]*EdgeLocation {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]*EdgeLocation)
	for k, v := range m.locations {
		result[k] = v
	}
	return result
}

// GetMetrics 获取指标
func (m *EdgeRoutingManager) GetMetrics() *EdgeRoutingMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 返回副本
	metricsCopy := *m.metrics
	metricsCopy.RequestsByRegion = make(map[string]int64)
	metricsCopy.RequestsByCluster = make(map[string]int64)
	metricsCopy.AvgLatency = make(map[string]time.Duration)

	for k, v := range m.metrics.RequestsByRegion {
		metricsCopy.RequestsByRegion[k] = v
	}
	for k, v := range m.metrics.RequestsByCluster {
		metricsCopy.RequestsByCluster[k] = v
	}
	for k, v := range m.metrics.AvgLatency {
		metricsCopy.AvgLatency[k] = v
	}

	return &metricsCopy
}

// EnableLocation 启用位置
func (m *EdgeRoutingManager) EnableLocation(locationID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	loc, exists := m.locations[locationID]
	if !exists {
		return fmt.Errorf("location %s not found", locationID)
	}

	loc.Enabled = true
	m.log.Infof("Enabled edge location: %s", locationID)

	return nil
}

// DisableLocation 禁用位置
func (m *EdgeRoutingManager) DisableLocation(locationID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	loc, exists := m.locations[locationID]
	if !exists {
		return fmt.Errorf("location %s not found", locationID)
	}

	loc.Enabled = false
	m.log.Infof("Disabled edge location: %s", locationID)

	return nil
}

// ExportConfiguration 导出配置为JSON
func (m *EdgeRoutingManager) ExportConfiguration() (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	config := map[string]interface{}{
		"config":    m.config,
		"clusters":  m.clusters,
		"locations": m.locations,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// ImportConfiguration 从JSON导入配置
func (m *EdgeRoutingManager) ImportConfiguration(configJSON string) error {
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return err
	}

	// 导入配置
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 这里应该有更复杂的导入逻辑
	// 简化实现：只更新配置部分
	if cfgData, ok := config["config"]; ok {
		cfgJSON, _ := json.Marshal(cfgData)
		var cfg EdgeRoutingConfig
		if err := json.Unmarshal(cfgJSON, &cfg); err == nil {
			m.config = &cfg
		}
	}

	m.log.Info("Edge routing configuration imported")

	return nil
}
