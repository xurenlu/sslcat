package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// ConfigReloadAPI 配置重载API
type ConfigReloadAPI struct {
	server        *Server
	configWatcher *config.ConfigWatcher
	reloadManager *config.ReloadManager
}

// NewConfigReloadAPI 创建配置重载API
func NewConfigReloadAPI(server *Server, configWatcher *config.ConfigWatcher, reloadManager *config.ReloadManager) *ConfigReloadAPI {
	return &ConfigReloadAPI{
		server:        server,
		configWatcher: configWatcher,
		reloadManager: reloadManager,
	}
}

// SetupRoutes 设置API路由
func (api *ConfigReloadAPI) SetupRoutes() {
	prefix := api.server.config.AdminPrefix + "/api/config"

	// 重载配置
	api.server.mux.HandleFunc(prefix+"/reload", api.withAuth(api.handleReload))

	// 验证配置
	api.server.mux.HandleFunc(prefix+"/validate", api.withAuth(api.handleValidate))

	// 获取重载状态
	api.server.mux.HandleFunc(prefix+"/reload/status", api.withAuth(api.handleReloadStatus))

	// 获取配置文件信息
	api.server.mux.HandleFunc(prefix+"/info", api.withAuth(api.handleConfigInfo))
}

// withAuth 认证中间件
func (api *ConfigReloadAPI) withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !api.server.checkAuth(w, r) {
			return
		}
		handler(w, r)
	}
}

// handleReload 处理配置重载请求
func (api *ConfigReloadAPI) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	startTime := time.Now()

	// 强制重载配置
	err := api.configWatcher.ForceReload()

	duration := time.Since(startTime)

	response := map[string]interface{}{
		"success":   err == nil,
		"duration":  duration.String(),
		"timestamp": time.Now().Unix(),
	}

	if err != nil {
		response["error"] = err.Error()
		api.server.log.Errorf("Config reload failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		api.server.log.Infof("Config reload succeeded in %v", duration)
		response["message"] = "Configuration reloaded successfully"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleValidate 处理配置验证请求
func (api *ConfigReloadAPI) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取配置文件信息
	configInfo, err := api.configWatcher.GetConfigFileInfo()
	if err != nil {
		response := map[string]interface{}{
			"valid": false,
			"error": fmt.Sprintf("failed to get config file info: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	configFile, ok := configInfo["file_path"].(string)
	if !ok {
		response := map[string]interface{}{
			"valid": false,
			"error": "failed to get config file path",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// 加载配置进行验证
	newConfig, err := config.Load(configFile)
	if err != nil {
		response := map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// 验证所有组件
	err = api.reloadManager.ValidateAllComponents(newConfig)

	response := map[string]interface{}{
		"valid":     err == nil,
		"timestamp": time.Now().Unix(),
	}

	if err != nil {
		response["error"] = err.Error()
		w.WriteHeader(http.StatusBadRequest)
	} else {
		response["message"] = "Configuration is valid"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleReloadStatus 处理重载状态请求
func (api *ConfigReloadAPI) handleReloadStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取重载管理器统计信息
	reloadStats := api.reloadManager.GetStats()

	// 获取配置文件信息
	configInfo, err := api.configWatcher.GetConfigFileInfo()
	if err != nil {
		api.server.log.Errorf("Failed to get config file info: %v", err)
		configInfo = map[string]interface{}{
			"error": err.Error(),
		}
	}

	response := map[string]interface{}{
		"reload_stats":   reloadStats,
		"config_info":    configInfo,
		"watcher_active": true,
		"timestamp":      time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleConfigInfo 处理配置信息请求
func (api *ConfigReloadAPI) handleConfigInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configInfo, err := api.configWatcher.GetConfigFileInfo()
	if err != nil {
		response := map[string]interface{}{
			"error": err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configInfo)
}

// ReloadRequest 重载请求结构
type ReloadRequest struct {
	Force bool `json:"force"` // 是否强制重载
}

// ValidateRequest 验证请求结构
type ValidateRequest struct {
	ConfigPath string `json:"config_path"` // 可选的配置文件路径
}
