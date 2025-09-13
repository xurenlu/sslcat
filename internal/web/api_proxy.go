package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// handleAPIProxyRulesPost 添加或更新代理规则
func (s *Server) handleAPIProxyRulesPost(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain               string `json:"domain"`
		Target               string `json:"target"`
		Enabled              bool   `json:"enabled"`
		SSLOnly              bool   `json:"ssl_only"`
		CDNEnabled           bool   `json:"cdn_enabled"`
		CDNPreset            string `json:"cdn_preset"`
		CDNDefaultTTLSeconds int    `json:"cdn_ttl_seconds"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Domain == "" || req.Target == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain and target are required"})
		return
	}

	// 检查是否已存在该域名
	existingIndex := -1
	for i, rule := range s.config.Proxy.Rules {
		if rule.Domain == req.Domain {
			existingIndex = i
			break
		}
	}

	newRule := config.ProxyRule{
		Domain:               req.Domain,
		Target:               req.Target,
		Enabled:              req.Enabled,
		SSLOnly:              req.SSLOnly,
		CDNEnabled:           req.CDNEnabled,
		CDNPreset:            req.CDNPreset,
		CDNDefaultTTLSeconds: req.CDNDefaultTTLSeconds,
	}

	if existingIndex >= 0 {
		// 更新现有规则
		s.config.Proxy.Rules[existingIndex] = newRule
	} else {
		// 添加新规则
		s.config.Proxy.Rules = append(s.config.Proxy.Rules, newRule)
	}

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	// 尝试预取证书
	if s.sslManager != nil {
		if err := s.sslManager.EnsureDomainCert(req.Domain); err != nil {
			s.log.Warnf("Failed to prefetch certificate %s: %v", req.Domain, err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"rule":    newRule,
		"action":  map[bool]string{true: "updated", false: "created"}[existingIndex >= 0],
	})
}

// handleAPIProxyRulesDelete 删除代理规则
func (s *Server) handleAPIProxyRulesDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	indexStr := strings.TrimSpace(r.URL.Query().Get("index"))

	var targetIndex = -1

	// 支持按域名或索引删除
	if domain != "" {
		for i, rule := range s.config.Proxy.Rules {
			if rule.Domain == domain {
				targetIndex = i
				break
			}
		}
	} else if indexStr != "" {
		if index, err := strconv.Atoi(indexStr); err == nil && index >= 0 && index < len(s.config.Proxy.Rules) {
			targetIndex = index
		}
	}

	if targetIndex < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule not found"})
		return
	}

	// 删除规则
	deletedRule := s.config.Proxy.Rules[targetIndex]
	s.config.Proxy.Rules = append(s.config.Proxy.Rules[:targetIndex], s.config.Proxy.Rules[targetIndex+1:]...)

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"deleted_rule": deletedRule,
	})
}
