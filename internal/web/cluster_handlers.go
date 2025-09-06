package web

import (
	"encoding/json"
	"net/http"
)

// handleClusterSettings 处理集群设置页面
func (s *Server) handleClusterSettings(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	data := map[string]interface{}{
		"Title":            "集群设置",
		"Config":           s.config,
		"ClusterMode":      s.config.Cluster.Mode,
		"NodeID":           s.config.Cluster.NodeID,
		"NodeName":         s.config.Cluster.NodeName,
		"IsSlaveMode":      s.config.Cluster.Mode == "slave",
		"IsMasterMode":     s.config.Cluster.Mode == "master",
		"IsStandaloneMode": s.config.Cluster.Mode == "standalone" || s.config.Cluster.Mode == "",
	}

	if s.clusterManager != nil {
		data["Nodes"] = s.clusterManager.GetNodes()
	}

	s.templateRenderer.Render(w, "cluster_settings.html", data)
}

// handleClusterSetSlave 设置为Slave模式
func (s *Server) handleClusterSetSlave(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		s.sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		MasterHost string `json:"master_host"`
		MasterPort int    `json:"master_port"`
		AuthKey    string `json:"auth_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.sendJSONError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 验证参数
	if request.MasterHost == "" {
		s.sendJSONError(w, "Master host is required", http.StatusBadRequest)
		return
	}

	if request.MasterPort <= 0 || request.MasterPort > 65535 {
		s.sendJSONError(w, "Invalid master port", http.StatusBadRequest)
		return
	}

	if request.AuthKey == "" {
		s.sendJSONError(w, "Auth key is required", http.StatusBadRequest)
		return
	}

	// 更新配置
	s.config.Cluster.Mode = "slave"
	s.config.Cluster.Master.Host = request.MasterHost
	s.config.Cluster.Master.Port = request.MasterPort
	s.config.Cluster.Master.AuthKey = request.AuthKey

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Error("Failed to save config: ", err)
		s.sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	// 启动集群管理器
	if s.clusterManager != nil {
		s.clusterManager.Stop()
	}

	if err := s.clusterManager.SetSlaveMode(request.MasterHost, request.MasterPort, request.AuthKey); err != nil {
		s.log.Error("Failed to set slave mode: ", err)
		s.sendJSONError(w, "Failed to set slave mode", http.StatusInternalServerError)
		return
	}

	s.sendJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "Successfully set to slave mode",
	})
}

// handleClusterSetStandalone 设置为独立模式
func (s *Server) handleClusterSetStandalone(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 在Slave模式下，允许设置为独立模式
	if r.Method != http.MethodPost {
		s.sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 更新配置
	s.config.Cluster.Mode = "standalone"
	s.config.Cluster.Master.Host = ""
	s.config.Cluster.Master.Port = 0
	s.config.Cluster.Master.AuthKey = ""

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Error("Failed to save config: ", err)
		s.sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	// 停止集群管理器
	if s.clusterManager != nil {
		if err := s.clusterManager.SetStandaloneMode(); err != nil {
			s.log.Error("Failed to set standalone mode: ", err)
			s.sendJSONError(w, "Failed to set standalone mode", http.StatusInternalServerError)
			return
		}
	}

	s.sendJSONResponse(w, map[string]interface{}{
		"success": true,
		"message": "Successfully set to standalone mode",
	})
}

// handleClusterNodes 获取集群节点信息
func (s *Server) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if s.clusterManager == nil {
		s.sendJSONResponse(w, map[string]interface{}{
			"nodes": []interface{}{},
		})
		return
	}

	nodes := s.clusterManager.GetNodes()
	s.sendJSONResponse(w, map[string]interface{}{
		"nodes": nodes,
	})
}

// handleClusterSync 处理集群同步请求（Master模式下）
func (s *Server) handleClusterSync(w http.ResponseWriter, r *http.Request) {
	if s.clusterManager == nil {
		http.Error(w, "Cluster not enabled", http.StatusServiceUnavailable)
		return
	}

	s.clusterManager.HandleSyncRequest(w, r)
}

// isSlaveAllowedAction 检查在Slave模式下是否允许该操作
func (s *Server) isSlaveAllowedAction(action string) bool {
	if !s.config.IsSlaveMode() {
		return true // 非Slave模式，允许所有操作
	}

	// Slave模式下允许的操作列表
	allowedActions := []string{
		"change_password",     // 修改密码
		"change_admin_prefix", // 修改面板路径
		"set_standalone",      // 解除Slave模式
		"view_cluster",        // 查看集群状态
	}

	for _, allowed := range allowedActions {
		if action == allowed {
			return true
		}
	}

	return false
}

// requireNonSlaveMode 中间件：要求非Slave模式才能访问
func (s *Server) requireNonSlaveMode(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.config.IsSlaveMode() {
			s.sendJSONError(w, "Operation not allowed in slave mode", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// requireNonSlaveModeHTML 中间件：要求非Slave模式才能访问（HTML页面）
func (s *Server) requireNonSlaveModeHTML(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.config.IsSlaveMode() {
			data := map[string]interface{}{
				"Title":   "禁止访问",
				"Message": "在Slave模式下不允许此操作",
				"Config":  s.config,
			}
			s.templateRenderer.Render(w, "error.html", data)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// sendJSONError 发送JSON错误响应
func (s *Server) sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// sendJSONResponse 发送JSON响应
func (s *Server) sendJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
