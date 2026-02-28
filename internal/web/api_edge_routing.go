package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/proxy"
)

// EdgeRoutingConfigRequest 边缘路由配置请求
type EdgeRoutingConfigRequest struct {
	Enabled                  bool   `json:"enabled"`
	DefaultClusterID         string `json:"default_cluster_id"`
	FallbackStrategy         string `json:"fallback_strategy"`
	HealthCheckInterval      int    `json:"health_check_interval"` // 毫秒
	HealthCheckIntervalMs    int    `json:"health_check_interval_ms"`
	HealthCheckTimeout       int    `json:"health_check_timeout"` // 毫秒
	HealthCheckTimeoutMs     int    `json:"health_check_timeout_ms"`
	MaxRetries               int    `json:"max_retries"`
	RetryDelay               int    `json:"retry_delay"` // 毫秒
	RetryDelayMs             int    `json:"retry_delay_ms"`
	LatencyThreshold         int    `json:"latency_threshold"` // 毫秒
	LatencyThresholdMs       int    `json:"latency_threshold_ms"`
}

// EdgeLocationRequest 边缘位置请求
type EdgeLocationRequest struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Region      string  `json:"region"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Priority    int     `json:"priority"`
	HealthCheck string  `json:"health_check"`
}

// EdgeClusterRequest 边缘集群请求
type EdgeClusterRequest struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Locations   []EdgeLocationRequest   `json:"locations"`
	LoadBalance string                  `json:"load_balance"`
}

// handleEdgeRoutingConfig 处理边缘路由配置的 GET 和 POST 请求
func (s *Server) handleEdgeRoutingConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleEdgeRoutingGetConfig(w, r)
	case http.MethodPost:
		s.handleEdgeRoutingUpdateConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEdgeRoutingGetConfig 获取边缘路由配置
func (s *Server) handleEdgeRoutingGetConfig(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		s.sendJSON(w, map[string]interface{}{
			"enabled": false,
			"error":   "Edge routing not enabled",
		})
		return
	}

	cfg := s.proxyManager.GetEdgeRoutingManager().GetConfig()

	response := map[string]interface{}{
		"enabled":                  cfg.Enabled,
		"default_cluster_id":       cfg.DefaultClusterID,
		"fallback_strategy":        cfg.FallbackStrategy,
		"health_check_interval_ms": cfg.HealthCheckInterval.Milliseconds(),
		"health_check_timeout_ms":  cfg.HealthCheckTimeout.Milliseconds(),
		"max_retries":              cfg.MaxRetries,
		"retry_delay_ms":           cfg.RetryDelay.Milliseconds(),
		"latency_threshold_ms":     cfg.LatencyThreshold.Milliseconds(),
	}

	s.sendJSON(w, response)
}

// handleEdgeRoutingUpdateConfig 更新边缘路由配置
func (s *Server) handleEdgeRoutingUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EdgeRoutingConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil {
		http.Error(w, "Proxy manager not initialized", http.StatusInternalServerError)
		return
	}

	// 兼容两种字段命名格式：优先使用 _ms 后缀的值
	healthCheckInterval := req.HealthCheckIntervalMs
	if healthCheckInterval == 0 && req.HealthCheckInterval > 0 {
		healthCheckInterval = req.HealthCheckInterval
	}
	// 设置默认值：30秒
	if healthCheckInterval <= 0 {
		healthCheckInterval = 30000
	}

	healthCheckTimeout := req.HealthCheckTimeoutMs
	if healthCheckTimeout == 0 && req.HealthCheckTimeout > 0 {
		healthCheckTimeout = req.HealthCheckTimeout
	}
	// 设置默认值：5秒
	if healthCheckTimeout <= 0 {
		healthCheckTimeout = 5000
	}

	retryDelay := req.RetryDelayMs
	if retryDelay == 0 && req.RetryDelay > 0 {
		retryDelay = req.RetryDelay
	}
	// 设置默认值：1秒
	if retryDelay <= 0 {
		retryDelay = 1000
	}

	latencyThreshold := req.LatencyThresholdMs
	if latencyThreshold == 0 && req.LatencyThreshold > 0 {
		latencyThreshold = req.LatencyThreshold
	}
	// 设置默认值：500ms
	if latencyThreshold <= 0 {
		latencyThreshold = 500
	}

	// 转换请求为配置
	config := &proxy.EdgeRoutingConfig{
		Enabled:            req.Enabled,
		DefaultClusterID:   req.DefaultClusterID,
		FallbackStrategy:   req.FallbackStrategy,
		HealthCheckInterval: time.Duration(healthCheckInterval) * time.Millisecond,
		HealthCheckTimeout:  time.Duration(healthCheckTimeout) * time.Millisecond,
		MaxRetries:         req.MaxRetries,
		RetryDelay:         time.Duration(retryDelay) * time.Millisecond,
		LatencyThreshold:   time.Duration(latencyThreshold) * time.Millisecond,
	}

	// 更新配置或创建新的 Edge Routing Manager
	if s.proxyManager.GetEdgeRoutingManager() == nil && req.Enabled {
		// 首次启用 - 创建新的 Edge Routing Manager
		manager := proxy.NewEdgeRoutingManager(config, s.proxyManager)
		s.proxyManager.SetEdgeRoutingManager(manager)
		// 启动管理器
		if err := manager.Start(); err != nil {
			s.sendJSON(w, map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
	} else if s.proxyManager.GetEdgeRoutingManager() != nil && !req.Enabled {
		// 禁用 Edge Routing
		s.proxyManager.GetEdgeRoutingManager().Stop()
		s.proxyManager.SetEdgeRoutingManager(nil)
	} else if s.proxyManager.GetEdgeRoutingManager() != nil {
		// 更新现有配置
		s.proxyManager.GetEdgeRoutingManager().UpdateConfig(config)
	}

	// 返回更新后的配置 - 使用 _ms 后缀格式
	response := map[string]interface{}{
		"enabled":                   req.Enabled,
		"default_cluster_id":        req.DefaultClusterID,
		"fallback_strategy":         req.FallbackStrategy,
		"health_check_interval_ms":  healthCheckInterval,
		"health_check_timeout_ms":   healthCheckTimeout,
		"max_retries":               req.MaxRetries,
		"retry_delay_ms":            retryDelay,
		"latency_threshold_ms":      latencyThreshold,
	}

	s.sendJSON(w, response)
}

// handleEdgeRoutingGetClusters 获取边缘集群列表
func (s *Server) handleEdgeRoutingGetClusters(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	clusters := s.proxyManager.GetEdgeRoutingManager().GetClusters()

	s.sendJSON(w, map[string]interface{}{
		"clusters": clusters,
		"count":    len(clusters),
	})
}

// handleEdgeRoutingGetLocations 获取边缘位置列表
func (s *Server) handleEdgeRoutingGetLocations(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	locations := s.proxyManager.GetEdgeRoutingManager().GetLocations()

	s.sendJSON(w, map[string]interface{}{
		"locations": locations,
		"count":     len(locations),
	})
}

// handleEdgeRoutingAddCluster 添加边缘集群
func (s *Server) handleEdgeRoutingAddCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EdgeClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	// 转换请求为集群对象
	cluster := &proxy.EdgeCluster{
		ID:          req.ID,
		Name:        req.Name,
		Locations:   make([]*proxy.EdgeLocation, 0),
		LoadBalance: req.LoadBalance,
		CreatedAt:   time.Now(),
	}

	// 转换位置
	for _, locReq := range req.Locations {
		loc := &proxy.EdgeLocation{
			ID:          locReq.ID,
			Name:        locReq.Name,
			Region:      locReq.Region,
			Country:     locReq.Country,
			City:        locReq.City,
			Latitude:    locReq.Latitude,
			Longitude:   locReq.Longitude,
			Priority:    locReq.Priority,
			Enabled:     true,
			HealthCheck: locReq.HealthCheck,
		}
		cluster.Locations = append(cluster.Locations, loc)
	}

	// 添加集群
	if err := s.proxyManager.GetEdgeRoutingManager().AddCluster(cluster); err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Edge cluster added",
		"cluster": cluster,
	})
}

// handleEdgeRoutingRemoveCluster 移除边缘集群
func (s *Server) handleEdgeRoutingRemoveCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClusterID string `json:"cluster_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	if err := s.proxyManager.GetEdgeRoutingManager().RemoveCluster(req.ClusterID); err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Edge cluster removed",
	})
}

// handleEdgeRoutingAddLocation 添加边缘位置
func (s *Server) handleEdgeRoutingAddLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClusterID string              `json:"cluster_id"`
		Location  EdgeLocationRequest `json:"location"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	// 转换请求为位置对象
	location := &proxy.EdgeLocation{
		ID:          req.Location.ID,
		Name:        req.Location.Name,
		Region:      req.Location.Region,
		Country:     req.Location.Country,
		City:        req.Location.City,
		Latitude:    req.Location.Latitude,
		Longitude:   req.Location.Longitude,
		Priority:    req.Location.Priority,
		Enabled:     true,
		HealthCheck: req.Location.HealthCheck,
	}

	// 添加位置
	if err := s.proxyManager.GetEdgeRoutingManager().AddLocation(req.ClusterID, location); err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Edge location added",
		"location": location,
	})
}

// handleEdgeRoutingRemoveLocation 移除边缘位置
func (s *Server) handleEdgeRoutingRemoveLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LocationID string `json:"location_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	if err := s.proxyManager.GetEdgeRoutingManager().RemoveLocation(req.LocationID); err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Edge location removed",
	})
}

// handleEdgeRoutingEnableLocation 启用/禁用边缘位置（统一接口）
func (s *Server) handleEdgeRoutingEnableLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LocationID string `json:"location_id"`
		Enabled    bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	var err error
	if req.Enabled {
		err = s.proxyManager.GetEdgeRoutingManager().EnableLocation(req.LocationID)
	} else {
		err = s.proxyManager.GetEdgeRoutingManager().DisableLocation(req.LocationID)
	}

	if err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Edge location %s", map[bool]string{true: "enabled", false: "disabled"}[req.Enabled]),
	})
}

// handleEdgeRoutingDisableLocation 禁用边缘位置
func (s *Server) handleEdgeRoutingDisableLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		LocationID string `json:"location_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	if err := s.proxyManager.GetEdgeRoutingManager().DisableLocation(req.LocationID); err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Edge location disabled",
	})
}

// handleEdgeRoutingGetMetrics 获取边缘路由指标
func (s *Server) handleEdgeRoutingGetMetrics(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	metrics := s.proxyManager.GetEdgeRoutingManager().GetMetrics()

	s.sendJSON(w, metrics)
}

// handleEdgeRoutingExportConfig 导出边缘路由配置
func (s *Server) handleEdgeRoutingExportConfig(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	configJSON, err := s.proxyManager.GetEdgeRoutingManager().ExportConfiguration()
	if err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=edge-routing-config.json")
	w.Write([]byte(configJSON))
}

// handleEdgeRoutingImportConfig 导入边缘路由配置
func (s *Server) handleEdgeRoutingImportConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Config string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	if err := s.proxyManager.GetEdgeRoutingManager().ImportConfiguration(req.Config); err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Edge routing configuration imported",
	})
}

// handleEdgeRoutingSelectBest 测试选择最佳边缘节点
func (s *Server) handleEdgeRoutingSelectBest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientIP string `json:"client_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetEdgeRoutingManager() == nil {
		http.Error(w, "Edge routing not enabled", http.StatusBadRequest)
		return
	}

	// 创建一个测试请求
	testReq := &http.Request{}
	location, err := s.proxyManager.GetEdgeRoutingManager().SelectBestEdge(testReq, req.ClientIP)
	if err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success":  true,
		"location": location,
	})
}
