package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/runner"
)

// DeploymentAPI 发布管理 API
type DeploymentAPI struct {
	logger *logrus.Entry
	db     *runner.DeploymentDatabase
}

// NewDeploymentAPI 创建发布管理 API
func NewDeploymentAPI(db *runner.DeploymentDatabase) *DeploymentAPI {
	return &DeploymentAPI{
		logger: logrus.WithField("component", "deployment_api"),
		db:     db,
	}
}

// RegisterRoutes 注册路由
func (api *DeploymentAPI) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/api/git-server/deployments", api.GetDeployments).Methods("GET")
	router.HandleFunc("/api/git-server/deployments/{uuid}", api.GetDeployment).Methods("GET")
	router.HandleFunc("/api/git-server/deployments/{uuid}/logs", api.GetDeploymentLogs).Methods("GET")
	router.HandleFunc("/api/git-server/deployments/{uuid}/status", api.GetDeploymentStatus).Methods("GET")
}

// GetDeployments 获取发布列表
func (api *DeploymentAPI) GetDeployments(w http.ResponseWriter, r *http.Request) {
	appName := r.URL.Query().Get("app")
	
	// 解析分页参数
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	
	limit := 20
	offset := 0
	
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	
	api.logger.Infof("获取发布列表: app=%s, limit=%d, offset=%d", appName, limit, offset)
	
	// 查询发布列表
	deployments, err := api.db.GetDeployments(appName, limit, offset)
	if err != nil {
		api.logger.Errorf("查询发布列表失败: %v", err)
		api.writeError(w, "查询发布列表失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// 构建响应
	response := map[string]interface{}{
		"success": true,
		"data":    deployments,
		"count":   len(deployments),
		"limit":   limit,
		"offset":  offset,
		"app":     appName,
	}
	
	api.writeJSON(w, response)
}

// GetDeployment 获取单个发布记录
func (api *DeploymentAPI) GetDeployment(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uuid := vars["uuid"]
	
	if uuid == "" {
		api.writeError(w, "发布 UUID 不能为空", http.StatusBadRequest)
		return
	}
	
	api.logger.Infof("获取发布记录: %s", uuid)
	
	// 查询发布记录
	deployment, err := api.db.GetDeploymentByUUID(uuid)
	if err != nil {
		api.logger.Errorf("查询发布记录失败: %v", err)
		api.writeError(w, "查询发布记录失败: "+err.Error(), http.StatusNotFound)
		return
	}
	
	// 构建响应
	response := map[string]interface{}{
		"success": true,
		"data":    deployment,
	}
	
	api.writeJSON(w, response)
}

// GetDeploymentLogs 获取发布日志
func (api *DeploymentAPI) GetDeploymentLogs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uuid := vars["uuid"]
	
	if uuid == "" {
		api.writeError(w, "发布 UUID 不能为空", http.StatusBadRequest)
		return
	}
	
	// 解析分页参数
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	
	limit := 100
	offset := 0
	
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}
	
	api.logger.Infof("获取发布日志: %s, limit=%d, offset=%d", uuid, limit, offset)
	
	// 查询发布日志
	logs, err := api.db.GetDeploymentLogs(uuid, limit, offset)
	if err != nil {
		api.logger.Errorf("查询发布日志失败: %v", err)
		api.writeError(w, "查询发布日志失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// 构建响应
	response := map[string]interface{}{
		"success": true,
		"data":    logs,
		"count":   len(logs),
		"limit":   limit,
		"offset":  offset,
		"uuid":    uuid,
	}
	
	api.writeJSON(w, response)
}

// GetDeploymentStatus 获取发布状态历史
func (api *DeploymentAPI) GetDeploymentStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	uuid := vars["uuid"]
	
	if uuid == "" {
		api.writeError(w, "发布 UUID 不能为空", http.StatusBadRequest)
		return
	}
	
	api.logger.Infof("获取发布状态: %s", uuid)
	
	// 查询发布状态
	statuses, err := api.db.GetDeploymentStatus(uuid)
	if err != nil {
		api.logger.Errorf("查询发布状态失败: %v", err)
		api.writeError(w, "查询发布状态失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// 构建响应
	response := map[string]interface{}{
		"success": true,
		"data":    statuses,
		"count":   len(statuses),
		"uuid":    uuid,
	}
	
	api.writeJSON(w, response)
}

// writeJSON 写入 JSON 响应
func (api *DeploymentAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(data); err != nil {
		api.logger.Errorf("编码 JSON 响应失败: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// writeError 写入错误响应
func (api *DeploymentAPI) writeError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	response := map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    statusCode,
	}
	
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	
	if err := encoder.Encode(response); err != nil {
		api.logger.Errorf("编码错误响应失败: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// DeploymentListResponse 发布列表响应
type DeploymentListResponse struct {
	Success bool                   `json:"success"`
	Data    []*runner.Deployment   `json:"data"`
	Count   int                    `json:"count"`
	Limit   int                    `json:"limit"`
	Offset  int                    `json:"offset"`
	App     string                 `json:"app"`
}

// DeploymentResponse 发布记录响应
type DeploymentResponse struct {
	Success bool                 `json:"success"`
	Data    *runner.Deployment   `json:"data"`
}

// DeploymentLogsResponse 发布日志响应
type DeploymentLogsResponse struct {
	Success bool                   `json:"success"`
	Data    []*runner.DeploymentLog `json:"data"`
	Count   int                     `json:"count"`
	Limit   int                     `json:"limit"`
	Offset  int                     `json:"offset"`
	UUID    string                  `json:"uuid"`
}

// DeploymentStatusResponse 发布状态响应
type DeploymentStatusResponse struct {
	Success bool                      `json:"success"`
	Data    []*runner.DeploymentStatus `json:"data"`
	Count   int                        `json:"count"`
	UUID    string                     `json:"uuid"`
}
