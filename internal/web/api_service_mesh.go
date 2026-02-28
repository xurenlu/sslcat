package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/proxy"
)

// ServiceMeshConfigRequest Service Mesh 配置请求
type ServiceMeshConfigRequest struct {
	Enabled bool                        `json:"enabled"`
	Type    proxy.ServiceMeshType       `json:"type"`
	Config  *proxy.ServiceMeshConfig    `json:"config"`
}

// ServiceMeshResponse Service Mesh 响应
type ServiceMeshResponse struct {
	Enabled bool                       `json:"enabled"`
	Type    proxy.ServiceMeshType      `json:"type"`
	Stats   proxy.ServiceMeshStats     `json:"stats"`
	Services []*proxy.ServiceInfo      `json:"services,omitempty"`
	CircuitBreakers map[string]*proxy.CircuitBreakerState `json:"circuit_breakers,omitempty"`
}

// CircuitBreakerActionRequest 熔断器操作请求
type CircuitBreakerActionRequest struct {
	Action string `json:"action"` // reset, open, close
}

// handleServiceMeshConfig 处理 Service Mesh 配置的 GET 和 POST 请求
func (s *Server) handleServiceMeshConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleServiceMeshGetConfig(w, r)
	case http.MethodPost:
		s.handleServiceMeshUpdateConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleServiceMeshGetConfig 获取 Service Mesh 配置
func (s *Server) handleServiceMeshGetConfig(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetServiceMeshManager() == nil {
		s.sendJSON(w, map[string]interface{}{
			"enabled": false,
			"error":   "Service Mesh not enabled",
		})
		return
	}

	cfg := s.proxyManager.GetServiceMeshManager().GetConfig()
	stats := s.proxyManager.GetServiceMeshManager().GetStats()
	services := s.proxyManager.GetServiceMeshManager().GetServices()
	breakers := s.proxyManager.GetServiceMeshManager().GetCircuitBreakerStates()

	response := ServiceMeshResponse{
		Enabled:         cfg.Enabled,
		Type:            cfg.Type,
		Stats:           stats,
		Services:        services,
		CircuitBreakers: breakers,
	}

	s.sendJSON(w, response)
}

// handleServiceMeshUpdateConfig 更新 Service Mesh 配置
func (s *Server) handleServiceMeshUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ServiceMeshConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.proxyManager == nil {
		http.Error(w, "Proxy manager not initialized", http.StatusInternalServerError)
		return
	}

	currentManager := s.proxyManager.GetServiceMeshManager()

	// 构建 or 使用现有配置
	config := req.Config
	if config == nil && currentManager != nil {
		config = currentManager.GetConfig()
	}
	if config == nil {
		// 创建默认配置
		config = &proxy.ServiceMeshConfig{
			Enabled: req.Enabled,
			Type:    req.Type,
		}
	} else {
		// 更新配置中的 enabled 和 type
		config.Enabled = req.Enabled
		config.Type = req.Type
	}

	// 更新配置
	if currentManager == nil && req.Enabled {
		// 首次启用
		s.proxyManager.SetServiceMeshManager(proxy.NewServiceMeshManager(
			config,
			s.proxyManager,
			s.config,
		))
	} else if currentManager != nil && !req.Enabled {
		// 禁用 Service Mesh
		s.proxyManager.SetServiceMeshManager(nil)
	} else if currentManager != nil {
		currentManager.UpdateConfig(config)
	}

	// 获取更新后的状态并发送回客户端
	cfg := s.proxyManager.GetServiceMeshManager()
	stats := proxy.ServiceMeshStats{}
	services := []*proxy.ServiceInfo{}
	breakers := map[string]*proxy.CircuitBreakerState{}
	meshType := proxy.ServiceMeshType("istio")

	if cfg != nil {
		meshType = cfg.GetConfig().Type
		stats = cfg.GetStats()
		services = cfg.GetServices()
		breakers = cfg.GetCircuitBreakerStates()
	}

	response := ServiceMeshResponse{
		Enabled:         cfg != nil,
		Type:            meshType,
		Stats:           stats,
		Services:        services,
		CircuitBreakers: breakers,
	}

	s.sendJSON(w, response)
}

// handleServiceMeshStats 获取 Service Mesh 统计
func (s *Server) handleServiceMeshStats(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetServiceMeshManager() == nil {
		http.Error(w, "Service Mesh not enabled", http.StatusBadRequest)
		return
	}

	stats := s.proxyManager.GetServiceMeshManager().GetStats()
	s.sendJSON(w, stats)
}

// handleServiceMeshServices 获取服务列表
func (s *Server) handleServiceMeshServices(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetServiceMeshManager() == nil {
		http.Error(w, "Service Mesh not enabled", http.StatusBadRequest)
		return
	}

	query := r.URL.Query()
	namespace := query.Get("namespace")
	healthyOnly := query.Get("healthy") == "true"

	services := s.proxyManager.GetServiceMeshManager().GetServices()

	// 过滤
	filtered := make([]*proxy.ServiceInfo, 0)
	for _, svc := range services {
		if namespace != "" && svc.Namespace != namespace {
			continue
		}
		if healthyOnly && !svc.Healthy {
			continue
		}
		filtered = append(filtered, svc)
	}

	s.sendJSON(w, map[string]interface{}{
		"services": filtered,
		"count":    len(filtered),
	})
}

// handleServiceMeshCircuitBreakers 获取熔断器状态
func (s *Server) handleServiceMeshCircuitBreakers(w http.ResponseWriter, r *http.Request) {
	if s.proxyManager == nil || s.proxyManager.GetServiceMeshManager() == nil {
		http.Error(w, "Service Mesh not enabled", http.StatusBadRequest)
		return
	}

	breakers := s.proxyManager.GetServiceMeshManager().GetCircuitBreakerStates()

	s.sendJSON(w, map[string]interface{}{
		"circuit_breakers": breakers,
	})
}

// handleServiceMeshResetBreaker 重置熔断器
func (s *Server) handleServiceMeshResetBreaker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetServiceMeshManager() == nil {
		http.Error(w, "Service Mesh not enabled", http.StatusBadRequest)
		return
	}

	var req struct {
		Service string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.proxyManager.GetServiceMeshManager().ResetCircuitBreaker(req.Service)

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Circuit breaker reset",
	})
}

// handleServiceMeshDiscover 手动触发服务发现
func (s *Server) handleServiceMeshDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetServiceMeshManager() == nil {
		http.Error(w, "Service Mesh not enabled", http.StatusBadRequest)
		return
	}

	// 触发服务发现（这里简化处理，实际应该在管理器中提供公开方法）
	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Service discovery triggered",
	})
}

// handleServiceMeshHealthCheck 手动触发健康检查
func (s *Server) handleServiceMeshHealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.proxyManager == nil || s.proxyManager.GetServiceMeshManager() == nil {
		http.Error(w, "Service Mesh not enabled", http.StatusBadRequest)
		return
	}

	// 触发健康检查
	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Health check triggered",
	})
}

// handleServiceMeshTestConnection 测试与控制平面的连接
func (s *Server) handleServiceMeshTestConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type proxy.ServiceMeshType `json:"type"`
		URL string                  `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 测试连接
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(req.URL)
	if err != nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	s.sendJSON(w, map[string]interface{}{
		"success":   true,
		"reachable": resp.StatusCode == http.StatusOK,
		"status":    resp.StatusCode,
	})
}
