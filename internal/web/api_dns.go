package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// handleAPIDNSProviders 获取DNS服务商列表
func (s *Server) handleAPIDNSProviders(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取可用的DNS服务商
	availableProviders := []string{"cloudflare", "aliyun", "tencent", "aws", "godaddy", "custom"}

	// 获取已配置的服务商
	configuredProviders := make([]map[string]interface{}, 0, len(s.config.SSL.DNSProviders))
	for _, provider := range s.config.SSL.DNSProviders {
		configuredProviders = append(configuredProviders, map[string]interface{}{
			"name":       provider.Name,
			"type":       provider.Type,
			"enabled":    provider.Enabled,
			"priority":   provider.Priority,
			"has_key":    provider.APIKey != "",
			"has_secret": provider.APISecret != "",
			"zone_id":    provider.ZoneID,
			"endpoint":   provider.Endpoint,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"available":  availableProviders,
		"configured": configuredProviders,
		"default":    s.config.SSL.DefaultDNSProvider,
		"methods":    s.config.SSL.ChallengeMethods,
	})
}

// handleAPIDNSProvidersPost 添加或更新DNS服务商
func (s *Server) handleAPIDNSProvidersPost(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "POST" && r.Method != "PUT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Enabled   bool   `json:"enabled"`
		APIKey    string `json:"api_key"`
		APISecret string `json:"api_secret"`
		ZoneID    string `json:"zone_id"`
		Endpoint  string `json:"endpoint"`
		Priority  int    `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Name == "" || req.Type == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "name and type are required"})
		return
	}

	// 验证服务商类型
	validTypes := []string{"cloudflare", "aliyun", "tencent", "aws", "godaddy", "custom"}
	validType := false
	for _, t := range validTypes {
		if req.Type == t {
			validType = true
			break
		}
	}
	if !validType {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid provider type"})
		return
	}

	// 检查是否已存在
	existingIndex := -1
	for i, provider := range s.config.SSL.DNSProviders {
		if provider.Name == req.Name {
			existingIndex = i
			break
		}
	}

	newProvider := config.DNSProvider{
		Name:      req.Name,
		Type:      req.Type,
		Enabled:   req.Enabled,
		APIKey:    req.APIKey,
		APISecret: req.APISecret,
		ZoneID:    req.ZoneID,
		Endpoint:  req.Endpoint,
		Priority:  req.Priority,
	}

	if existingIndex >= 0 {
		// 更新现有服务商
		s.config.SSL.DNSProviders[existingIndex] = newProvider
	} else {
		// 添加新服务商
		s.config.SSL.DNSProviders = append(s.config.SSL.DNSProviders, newProvider)
	}

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"provider": newProvider,
		"action":   map[bool]string{true: "updated", false: "created"}[existingIndex >= 0],
	})
}

// handleAPIDNSProvidersDelete 删除DNS服务商
func (s *Server) handleAPIDNSProvidersDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	indexStr := strings.TrimSpace(r.URL.Query().Get("index"))

	var targetIndex = -1

	// 支持按名称或索引删除
	if name != "" {
		for i, provider := range s.config.SSL.DNSProviders {
			if provider.Name == name {
				targetIndex = i
				break
			}
		}
	} else if indexStr != "" {
		if index, err := strconv.Atoi(indexStr); err == nil && index >= 0 && index < len(s.config.SSL.DNSProviders) {
			targetIndex = index
		}
	}

	if targetIndex < 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "provider not found"})
		return
	}

	// 删除服务商
	deletedProvider := s.config.SSL.DNSProviders[targetIndex]
	s.config.SSL.DNSProviders = append(s.config.SSL.DNSProviders[:targetIndex], s.config.SSL.DNSProviders[targetIndex+1:]...)

	// 如果删除的是默认服务商，清空默认设置
	if s.config.SSL.DefaultDNSProvider == deletedProvider.Name {
		s.config.SSL.DefaultDNSProvider = ""
	}

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"deleted_provider": deletedProvider,
	})
}

// handleAPIDNSValidate 验证DNS服务商配置
func (s *Server) handleAPIDNSValidate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "provider name is required"})
		return
	}

	// 验证DNS服务商
	err := s.sslManager.ValidateDNSProvider(req.Name)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "DNS provider configuration is valid",
		})
	}
}

// handleAPIDNSRequestCert 使用DNS验证申请证书
func (s *Server) handleAPIDNSRequestCert(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain   string `json:"domain"`
		Provider string `json:"provider"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Domain == "" || req.Provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain and provider are required"})
		return
	}

	// 使用DNS验证申请证书
	err := s.sslManager.RequestCertificateWithDNS(req.Domain, req.Provider)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"message":  "Certificate requested successfully",
			"domain":   req.Domain,
			"provider": req.Provider,
		})
	}
}

// handleAPIDNSConfig 更新DNS配置
func (s *Server) handleAPIDNSConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		DefaultProvider  string   `json:"default_provider"`
		ChallengeMethods []string `json:"challenge_methods"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	// 验证挑战方法
	validMethods := []string{"http-01", "dns-01"}
	for _, method := range req.ChallengeMethods {
		valid := false
		for _, validMethod := range validMethods {
			if method == validMethod {
				valid = true
				break
			}
		}
		if !valid {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid challenge method: " + method})
			return
		}
	}

	// 更新配置
	s.config.SSL.DefaultDNSProvider = req.DefaultProvider
	s.config.SSL.ChallengeMethods = req.ChallengeMethods

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "DNS configuration updated successfully",
	})
}

// handleAPIDNSHealth 获取DNS提供程序健康状态
func (s *Server) handleAPIDNSHealth(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取提供程序健康状态
	health := s.sslManager.GetDNSProviderHealth()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"health":  health,
	})
}

// handleAPIDNSTest 测试DNS提供程序连接
func (s *Server) handleAPIDNSTest(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Provider string `json:"provider"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "provider name is required"})
		return
	}

	// 测试提供程序连接
	err := s.sslManager.TestDNSProvider(req.Provider)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "DNS provider test successful",
		})
	}
}

// handleAPIDNSChallenge 创建DNS挑战记录
func (s *Server) handleAPIDNSChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain      string `json:"domain"`
		RecordName  string `json:"record_name"`
		RecordValue string `json:"record_value"`
		Provider    string `json:"provider,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Domain == "" || req.RecordName == "" || req.RecordValue == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain, record_name, and record_value are required"})
		return
	}

	// 创建DNS挑战
	var challenge interface{}
	var err error

	if req.Provider != "" {
		// 使用指定的提供程序
		challenge, err = s.sslManager.CreateDNSChallenge(req.Domain, req.RecordName, req.RecordValue, req.Provider)
	} else {
		// 使用故障转移机制
		challenge, err = s.sslManager.CreateDNSChallengeWithFailover(req.Domain, req.RecordName, req.RecordValue)
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"challenge": challenge,
		})
	}
}
