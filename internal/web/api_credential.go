package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/runner"
)

// CredentialAPI 凭证管理 API
type CredentialAPI struct {
	gitServer *runner.GitServer
	logger    *logrus.Entry
}

// NewCredentialAPI 创建凭证管理 API
func NewCredentialAPI(gs *runner.GitServer, logger *logrus.Logger) *CredentialAPI {
	return &CredentialAPI{
		gitServer: gs,
		logger:    logger.WithField("component", "credential_api"),
	}
}

// GetCredentialsRequest 获取凭证请求
type GetCredentialsRequest struct {
	AppName string `json:"app_name"`
	Service string `json:"service,omitempty"` // 如果为空，返回所有服务的凭证
}

// RegenerateCredentialRequest 重新生成凭证请求
type RegenerateCredentialRequest struct {
	AppName string `json:"app_name"`
	Service string `json:"service"` // 服务名称
	Field   string `json:"field,omitempty"` // 字段名（如 password, token），如果为空，重新生成所有字段
}

// GetCredentials 获取应用凭证（默认脱敏，可通过 show_full=true 参数获取完整密码）
func (api *CredentialAPI) GetCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	appName := r.URL.Query().Get("app_name")
	if appName == "" {
		writeErrorJSON(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}

	showFull := r.URL.Query().Get("show_full") == "true"

	app, err := api.gitServer.GetApp(appName)
	if err != nil || app == nil {
		writeErrorJSON(w, fmt.Sprintf("应用 %s 不存在", appName), http.StatusNotFound)
		return
	}

	serviceName := r.URL.Query().Get("service")

	// 如果是模板部署的应用，返回服务凭证
	if app.TemplateID != "" && len(app.ServiceCredentials) > 0 {
		// ServiceCredentials 中存储的是完整凭证
		credentials := app.ServiceCredentials
		
		// 如果需要脱敏，创建脱敏副本
		if !showFull {
			credentials = api.maskCredentials(credentials)
		}

		if serviceName != "" {
			// 返回特定服务的凭证
			if cred, ok := credentials[serviceName]; ok {
				writeJSON(w, map[string]interface{}{
					"success":   true,
					"service":   serviceName,
					"credential": cred,
				})
				return
			}
			writeErrorJSON(w, fmt.Sprintf("服务 %s 的凭证不存在", serviceName), http.StatusNotFound)
			return
		}

		// 返回所有服务的凭证
		writeJSON(w, map[string]interface{}{
			"success":    true,
			"app_name":  appName,
			"credentials": credentials,
		})
		return
	}

	writeErrorJSON(w, "应用没有凭证信息", http.StatusNotFound)
}

// maskCredentials 对凭证进行脱敏处理
func (api *CredentialAPI) maskCredentials(creds map[string]runner.AppServiceCredential) map[string]runner.AppServiceCredential {
	masked := make(map[string]runner.AppServiceCredential)
	for svc, cred := range creds {
		maskedCred := cred
		if cred.Password != "" {
			maskedCred.Password = maskPassword(cred.Password)
		}
		if cred.Token != "" {
			maskedCred.Token = maskPassword(cred.Token)
		}
		if cred.Secret != "" {
			maskedCred.Secret = maskPassword(cred.Secret)
		}
		masked[svc] = maskedCred
	}
	return masked
}

func maskPassword(pwd string) string {
	if pwd == "" {
		return ""
	}
	if len(pwd) <= 4 {
		return "****"
	}
	return pwd[:2] + "****" + pwd[len(pwd)-2:]
}

// RegenerateCredential 重新生成凭证
func (api *CredentialAPI) RegenerateCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req RegenerateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, fmt.Sprintf("解析请求失败: %v", err), http.StatusBadRequest)
		return
	}

	if req.AppName == "" {
		writeErrorJSON(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}
	if req.Service == "" {
		writeErrorJSON(w, "服务名称不能为空", http.StatusBadRequest)
		return
	}

	app, err := api.gitServer.GetApp(req.AppName)
	if err != nil || app == nil {
		writeErrorJSON(w, fmt.Sprintf("应用 %s 不存在", req.AppName), http.StatusNotFound)
		return
	}

	if app.TemplateID == "" {
		writeErrorJSON(w, "只有模板部署的应用支持重新生成凭证", http.StatusBadRequest)
		return
	}

	tm := api.gitServer.GetTemplateManager()
	if tm == nil {
		writeErrorJSON(w, "模板管理器未初始化", http.StatusInternalServerError)
		return
	}

	tpl, ok := tm.Get(app.TemplateID)
	if !ok {
		writeErrorJSON(w, fmt.Sprintf("模板 %s 不存在", app.TemplateID), http.StatusNotFound)
		return
	}

	credManager := api.gitServer.GetCredentialManager()
	if credManager == nil {
		writeErrorJSON(w, "凭证管理器未初始化", http.StatusInternalServerError)
		return
	}

	// 重新生成凭证
	credentials, err := credManager.Generate(tpl.Meta, req.AppName)
	if err != nil {
		writeErrorJSON(w, fmt.Sprintf("重新生成凭证失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 更新应用凭证
	if app.ServiceCredentials == nil {
		app.ServiceCredentials = make(map[string]runner.AppServiceCredential)
	}

	orchestrator := api.gitServer.GetDeployOrchestrator()
	if orchestrator == nil {
		writeErrorJSON(w, "部署编排器未初始化", http.StatusInternalServerError)
		return
	}

	// 构建凭证信息（脱敏）
	appCreds := orchestrator.BuildAppCredentials(credentials, tpl.Meta)

	// 更新特定服务的凭证
	if req.Service != "" {
		if cred, ok := appCreds[req.Service]; ok {
			app.ServiceCredentials[req.Service] = cred
		} else {
			writeErrorJSON(w, fmt.Sprintf("服务 %s 的凭证不存在", req.Service), http.StatusNotFound)
			return
		}
	} else {
		// 更新所有服务的凭证
		app.ServiceCredentials = appCreds
	}

	// 保存应用
	if err := api.gitServer.SaveApps(); err != nil {
		api.logger.WithError(err).Warnf("保存应用失败: %v", err)
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "凭证重新生成成功",
		"credentials": app.ServiceCredentials,
	})
}

