package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/runner"
)

// ServiceAPI 服务管理 API
type ServiceAPI struct {
	gitServer *runner.GitServer
	logger    *logrus.Entry
}

// NewServiceAPI 创建服务管理 API
func NewServiceAPI(gs *runner.GitServer, logger *logrus.Logger) *ServiceAPI {
	return &ServiceAPI{
		gitServer: gs,
		logger:    logger.WithField("component", "service_api"),
	}
}

// GetServiceStatusRequest 获取服务状态请求
type GetServiceStatusRequest struct {
	AppName string `json:"app_name"`
}

// RestartServiceRequest 重启服务请求
type RestartServiceRequest struct {
	AppName  string `json:"app_name"`
	Service  string `json:"service,omitempty"` // 如果为空，重启所有服务
}

// StopServiceRequest 停止服务请求
type StopServiceRequest struct {
	AppName string `json:"app_name"`
	Service string `json:"service,omitempty"` // 如果为空，停止所有服务
}

// GetServiceStatus 获取服务状态
func (api *ServiceAPI) GetServiceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	appName := r.URL.Query().Get("app_name")
	if appName == "" {
		writeErrorJSON(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	app, err := api.gitServer.GetApp(appName)
	if err != nil || app == nil {
		writeErrorJSON(w, fmt.Sprintf("应用 %s 不存在", appName), http.StatusNotFound)
		return
	}

	// 如果是模板部署的应用，检查 Docker Compose 服务状态
	if app.TemplateID != "" && app.ComposeFile != "" {
		services, err := api.getComposeServicesStatus(app)
		if err != nil {
			api.logger.WithError(err).Warnf("获取服务状态失败: %v", err)
			writeErrorJSON(w, fmt.Sprintf("获取服务状态失败: %v", err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]interface{}{
			"success":  true,
			"app_name": appName,
			"services": services,
		})
		return
	}

	// 普通应用，返回基本信息
	writeJSON(w, map[string]interface{}{
		"success":  true,
		"app_name": appName,
		"status":   "running",
		"port":     app.Port,
		"domain":   app.Domain,
	})
}

// RestartService 重启服务
func (api *ServiceAPI) RestartService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req RestartServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, fmt.Sprintf("解析请求失败: %v", err), http.StatusBadRequest)
		return
	}

	if req.AppName == "" {
		writeErrorJSON(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	app, err := api.gitServer.GetApp(req.AppName)
	if err != nil || app == nil {
		writeErrorJSON(w, fmt.Sprintf("应用 %s 不存在", req.AppName), http.StatusNotFound)
		return
	}

	// 如果是模板部署的应用，使用 Docker Compose 重启
	if app.TemplateID != "" && app.ComposeFile != "" {
		if err := api.restartComposeService(app, req.Service); err != nil {
			writeErrorJSON(w, fmt.Sprintf("重启服务失败: %v", err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("服务 %s 重启成功", req.Service),
		})
		return
	}

	// 普通应用重启逻辑
	writeErrorJSON(w, "普通应用重启功能待实现", http.StatusNotImplemented)
}

// StopService 停止服务
func (api *ServiceAPI) StopService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req StopServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, fmt.Sprintf("解析请求失败: %v", err), http.StatusBadRequest)
		return
	}

	if req.AppName == "" {
		writeErrorJSON(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	app, err := api.gitServer.GetApp(req.AppName)
	if err != nil || app == nil {
		writeErrorJSON(w, fmt.Sprintf("应用 %s 不存在", req.AppName), http.StatusNotFound)
		return
	}

	// 如果是模板部署的应用，使用 Docker Compose 停止
	if app.TemplateID != "" && app.ComposeFile != "" {
		if err := api.stopComposeService(app, req.Service); err != nil {
			writeErrorJSON(w, fmt.Sprintf("停止服务失败: %v", err), http.StatusInternalServerError)
			return
		}

		writeJSON(w, map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("服务 %s 停止成功", req.Service),
		})
		return
	}

	// 普通应用停止逻辑
	writeErrorJSON(w, "普通应用停止功能待实现", http.StatusNotImplemented)
}

func (api *ServiceAPI) getComposeServicesStatus(app *runner.GitApp) ([]map[string]interface{}, error) {
	projectName := fmt.Sprintf("sslcat-%s", sanitizeProjectName(app.Name))
	composeFile := app.ComposeFile

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker-compose", "-f", composeFile, "-p", projectName, "ps", "--format", "json")
	cmd.Dir = filepath.Dir(composeFile)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行 docker-compose ps 失败: %w", err)
	}

	// 解析 JSON 输出
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	services := make([]map[string]interface{}, 0)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var service map[string]interface{}
		if err := json.Unmarshal([]byte(line), &service); err != nil {
			api.logger.WithError(err).Warnf("解析服务状态失败: %v", err)
			continue
		}
		services = append(services, service)
	}

	return services, nil
}

func (api *ServiceAPI) restartComposeService(app *runner.GitApp, serviceName string) error {
	projectName := fmt.Sprintf("sslcat-%s", sanitizeProjectName(app.Name))
	composeFile := app.ComposeFile

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	args := []string{"-f", composeFile, "-p", projectName, "restart"}
	if serviceName != "" {
		args = append(args, serviceName)
	}

	cmd := exec.CommandContext(ctx, "docker-compose", args...)
	cmd.Dir = filepath.Dir(composeFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("重启服务失败: %s", string(output))
	}

	return nil
}

func (api *ServiceAPI) stopComposeService(app *runner.GitApp, serviceName string) error {
	projectName := fmt.Sprintf("sslcat-%s", sanitizeProjectName(app.Name))
	composeFile := app.ComposeFile

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	args := []string{"-f", composeFile, "-p", projectName, "stop"}
	if serviceName != "" {
		args = append(args, serviceName)
	}

	cmd := exec.CommandContext(ctx, "docker-compose", args...)
	cmd.Dir = filepath.Dir(composeFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("停止服务失败: %s", string(output))
	}

	return nil
}

func sanitizeProjectName(name string) string {
	result := strings.ToLower(name)
	result = strings.ReplaceAll(result, " ", "-")
	result = strings.ReplaceAll(result, "_", "-")
	var builder strings.Builder
	for _, r := range result {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			builder.WriteRune(r)
		}
	}
	result = builder.String()
	if result == "" {
		result = "app"
	}
	return result
}

