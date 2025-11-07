package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/runner"
)

// DomainAPI 域名管理 API
type DomainAPI struct {
	gitServer *runner.GitServer
	logger    *logrus.Entry
}

// NewDomainAPI 创建域名管理 API
func NewDomainAPI(gs *runner.GitServer, logger *logrus.Logger) *DomainAPI {
	return &DomainAPI{
		gitServer: gs,
		logger:    logger.WithField("component", "domain_api"),
	}
}

// AddDomainRequest 添加域名请求
type AddDomainRequest struct {
	AppName string `json:"app_name"`
	Domain  string `json:"domain"`
	Primary bool   `json:"primary,omitempty"` // 是否设为主域名
}

// RemoveDomainRequest 移除域名请求
type RemoveDomainRequest struct {
	AppName string `json:"app_name"`
	Domain  string `json:"domain"`
}

// GetDomainsRequest 获取域名请求
type GetDomainsRequest struct {
	AppName string `json:"app_name"`
}

// AddDomain 添加域名
func (api *DomainAPI) AddDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req AddDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, fmt.Sprintf("解析请求失败: %v", err), http.StatusBadRequest)
		return
	}

	if req.AppName == "" {
		writeErrorJSON(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		writeErrorJSON(w, "域名不能为空", http.StatusBadRequest)
		return
	}

	app, err := api.gitServer.GetApp(req.AppName)
	if err != nil || app == nil {
		writeErrorJSON(w, fmt.Sprintf("应用 %s 不存在", req.AppName), http.StatusNotFound)
		return
	}

	domainMgr := api.gitServer.GetDomainManager()
	if domainMgr == nil {
		writeErrorJSON(w, "域名管理器未初始化", http.StatusInternalServerError)
		return
	}

	if req.Primary {
		domainMgr.SetPrimaryDomain(app, req.Domain)
	} else {
		if !domainMgr.AddDomainAlias(app, req.Domain) {
			writeErrorJSON(w, fmt.Sprintf("域名 %s 已存在", req.Domain), http.StatusConflict)
			return
		}
	}

	// 更新代理规则
	if err := api.gitServer.UpdateProxyRulesForApp(app); err != nil {
		api.logger.WithError(err).Warnf("更新代理规则失败: %v", err)
		// 不返回错误，域名已添加成功
	}

	// 保存应用
	if err := api.gitServer.SaveApps(); err != nil {
		api.logger.WithError(err).Warnf("保存应用失败: %v", err)
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "域名添加成功",
		"domains": app.Domains,
		"primary": app.Domain,
	})
}

// RemoveDomain 移除域名
func (api *DomainAPI) RemoveDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req RemoveDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, fmt.Sprintf("解析请求失败: %v", err), http.StatusBadRequest)
		return
	}

	if req.AppName == "" {
		writeErrorJSON(w, "应用名称不能为空", http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		writeErrorJSON(w, "域名不能为空", http.StatusBadRequest)
		return
	}

	app, err := api.gitServer.GetApp(req.AppName)
	if err != nil || app == nil {
		writeErrorJSON(w, fmt.Sprintf("应用 %s 不存在", req.AppName), http.StatusNotFound)
		return
	}

	domainMgr := api.gitServer.GetDomainManager()
	if domainMgr == nil {
		writeErrorJSON(w, "域名管理器未初始化", http.StatusInternalServerError)
		return
	}

	if !domainMgr.RemoveDomainAlias(app, req.Domain) {
		writeErrorJSON(w, fmt.Sprintf("域名 %s 不存在或为主域名", req.Domain), http.StatusNotFound)
		return
	}

	// 更新代理规则
	if err := api.gitServer.UpdateProxyRulesForApp(app); err != nil {
		api.logger.WithError(err).Warnf("更新代理规则失败: %v", err)
	}

	// 保存应用
	if err := api.gitServer.SaveApps(); err != nil {
		api.logger.WithError(err).Warnf("保存应用失败: %v", err)
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "域名移除成功",
		"domains": app.Domains,
		"primary": app.Domain,
	})
}

// GetDomains 获取应用域名列表
func (api *DomainAPI) GetDomains(w http.ResponseWriter, r *http.Request) {
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

	writeJSON(w, map[string]interface{}{
		"success": true,
		"domains": app.Domains,
		"primary": app.Domain,
		"aliases": getAliases(app.Domains, app.Domain),
	})
}

// VerifyDNS 验证 DNS 配置
func (api *DomainAPI) VerifyDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, fmt.Sprintf("解析请求失败: %v", err), http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		writeErrorJSON(w, "域名不能为空", http.StatusBadRequest)
		return
	}

	// 创建 DNS 验证器
	verifier := runner.NewDNSVerifier(api.logger.Logger)

	// 执行 DNS 验证（5秒超时）
	result, err := verifier.VerifyDomainWithTimeout(req.Domain, 5*time.Second)
	if err != nil {
		writeErrorJSON(w, fmt.Sprintf("DNS 验证失败: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]interface{}{
		"success": result.Resolved,
		"result":  result,
	})
}

func getAliases(domains []string, primary string) []string {
	aliases := make([]string, 0)
	for _, d := range domains {
		if !strings.EqualFold(d, primary) {
			aliases = append(aliases, d)
		}
	}
	return aliases
}

