package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ssl"
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
	availableProviders := []string{"cloudflare", "aliyun", "tencent", "godaddy", "namecheap", "aws", "custom"}

	// 获取已配置的服务商
	configuredProviders := make([]map[string]interface{}, 0, len(s.config.SSL.DNSProviders))
	for _, provider := range s.config.SSL.DNSProviders {
		// 从缓存获取域名数量和状态
		domainCount := 0
		lastUpdate := ""
		errorMsg := ""
		updating := false
		if provider.Enabled {
			cache := s.dnsCache.GetProviderCache(provider.Name)
			domainCount = cache.DomainCount
			if !cache.LastUpdate.IsZero() {
				lastUpdate = cache.LastUpdate.Format("2006-01-02 15:04:05")
			}
			errorMsg = cache.Error
			updating = cache.Updating
		}

		configuredProviders = append(configuredProviders, map[string]interface{}{
			"name":        provider.Name,
			"type":        provider.Type,
			"enabled":     provider.Enabled,
			"priority":    provider.Priority,
			"has_key":     provider.APIKey != "",
			"has_secret":  provider.APISecret != "",
			"zone_id":     provider.ZoneID,
			"endpoint":    provider.Endpoint,
			"domains":     domainCount,
			"last_update": lastUpdate,
			"error":       errorMsg,
			"updating":    updating,
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

// handleAPIDNSProviderDomains 获取DNS提供商的域名列表
func (s *Server) handleAPIDNSProviderDomains(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "provider parameter is required"})
		return
	}

	// 从缓存获取域名列表
	cache := s.dnsCache.GetProviderCache(providerName)
	
	// 只返回 type 为 "domain" 的域名
	domains := make([]map[string]interface{}, 0)
	for _, d := range cache.Domains {
		if d.Type == "domain" {
			domains = append(domains, map[string]interface{}{
				"name":       d.Name,
				"type":       d.Type,
				"status":     d.Status,
				"created_at": d.CreatedAt.Format("2006-01-02 15:04:05"),
				"updated_at": d.UpdatedAt.Format("2006-01-02 15:04:05"),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"domains": domains,
		"count":   len(domains),
		"error":   cache.Error,
	})
}

// handleAPIDNSProvider 统一处理 DNS provider 的 POST、PUT 和 DELETE 请求
func (s *Server) handleAPIDNSProvider(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	// 如果是 DELETE 请求，转发到删除处理函数
	if r.Method == "DELETE" {
		s.handleAPIDNSProvidersDelete(w, r)
		return
	}

	// 其他请求转发到 POST 处理函数
	s.handleAPIDNSProvidersPost(w, r)
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
	validTypes := []string{"cloudflare", "aliyun", "tencent", "godaddy", "namecheap", "aws", "custom"}
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

	var finalProvider config.DNSProvider

	if existingIndex >= 0 {
		// 更新现有服务商
		existingProvider := s.config.SSL.DNSProviders[existingIndex]
		updatedProvider := config.DNSProvider{
			Name:      req.Name,
			Type:      req.Type,
			Enabled:   req.Enabled,
			APIKey:    req.APIKey,    // 如果为空，保留原有值
			APISecret: req.APISecret, // 如果为空，保留原有值
			ZoneID:    req.ZoneID,
			Endpoint:  req.Endpoint,
			Priority:  req.Priority,
		}
		
		// 如果新的 APIKey 或 APISecret 为空，保留原有值
		if updatedProvider.APIKey == "" {
			updatedProvider.APIKey = existingProvider.APIKey
		}
		if updatedProvider.APISecret == "" {
			updatedProvider.APISecret = existingProvider.APISecret
		}
		// ZoneID 和 Endpoint 也保留原有值（如果新值为空）
		if updatedProvider.ZoneID == "" {
			updatedProvider.ZoneID = existingProvider.ZoneID
		}
		if updatedProvider.Endpoint == "" {
			updatedProvider.Endpoint = existingProvider.Endpoint
		}
		
		s.config.SSL.DNSProviders[existingIndex] = updatedProvider
		finalProvider = updatedProvider
	} else {
		// 添加新服务商
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
		s.config.SSL.DNSProviders = append(s.config.SSL.DNSProviders, newProvider)
		finalProvider = newProvider
	}

	// 保存配置
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save config"})
		return
	}

	// 如果提供商已启用，注册到SSL Manager并触发缓存更新
	if finalProvider.Enabled {
		// 注册provider到SSL Manager的dnsManager
		if err := s.registerDNSProvider(finalProvider); err != nil {
			s.log.Warnf("Failed to register DNS provider %s: %v", finalProvider.Name, err)
			// 不返回错误，因为配置已保存，只是注册失败
		}
		// 触发缓存更新
		s.dnsCache.UpdateProviderCache(finalProvider.Name)
	} else {
		// 如果provider被禁用，从SSL Manager中移除
		s.unregisterDNSProvider(finalProvider.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"provider": finalProvider,
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

	// 从SSL Manager中注销provider
	s.unregisterDNSProvider(deletedProvider.Name)

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

// handleAPIDNSTestConfig 测试DNS提供程序配置（在保存之前）
func (s *Server) handleAPIDNSTestConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type      string `json:"type"`
		APIKey    string `json:"api_key"`
		APISecret string `json:"api_secret"`
		ZoneID    string `json:"zone_id"`
		Endpoint  string `json:"endpoint"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Type == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "provider type is required"})
		return
	}

	// 创建临时的 provider 实例进行测试
	var dnsProvider ssl.DNSProviderInterface
	switch strings.ToLower(req.Type) {
	case "cloudflare":
		dnsProvider = ssl.NewCloudflareProvider(req.APIKey, req.ZoneID, s.log)
	case "aliyun":
		if req.APIKey == "" || req.APISecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "API Key and API Secret are required for Aliyun"})
			return
		}
		dnsProvider = ssl.NewAliyunProvider(req.APIKey, req.APISecret, s.log)
	case "tencent":
		if req.APIKey == "" || req.APISecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "API Key and API Secret are required for Tencent"})
			return
		}
		dnsProvider = ssl.NewTencentProvider(req.APIKey, req.APISecret, s.log)
	case "godaddy":
		if req.APIKey == "" || req.APISecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "API Key and API Secret are required for GoDaddy"})
			return
		}
		dnsProvider = ssl.NewGoDaddyProvider(req.APIKey, req.APISecret, s.log)
	case "namecheap":
		if req.APIKey == "" || req.APISecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "API Key and API Secret are required for Namecheap"})
			return
		}
		dnsProvider = ssl.NewNamecheapProvider(req.APIKey, req.APISecret, req.ZoneID, s.log)
	case "aws":
		if req.APIKey == "" || req.APISecret == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "API Key and API Secret are required for AWS"})
			return
		}
		dnsProvider = ssl.NewAWSRoute53Provider(req.APIKey, req.APISecret, "us-east-1", s.log)
	case "custom":
		if req.Endpoint == "" || req.APIKey == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Endpoint and API Key are required for Custom provider"})
			return
		}
		dnsProvider = ssl.NewCustomProvider(req.Endpoint, req.APIKey, s.log)
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unsupported provider type: " + req.Type})
		return
	}

	// 验证配置
	if err := dnsProvider.Validate(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("配置验证失败: %v", err),
		})
		return
	}

	// 测试连接并获取域名列表
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	domains, err := dnsProvider.ListDomains(ctx)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("无法连接到 %s API 或获取域名列表失败: %v", req.Type, err),
		})
		return
	}

	// 统计域名数量（只统计 type 为 "domain" 的）
	domainCount := 0
	for _, domain := range domains {
		if domain.Type == "domain" {
			domainCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	// 限制返回的域名数量（最多10个）
	maxDomains := 10
	if len(domains) < maxDomains {
		maxDomains = len(domains)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"message":      fmt.Sprintf("连接成功！找到 %d 个域名", domainCount),
		"domain_count": domainCount,
		"domains":      domains[:maxDomains], // 只返回前10个域名作为示例
	})
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

// handleAPIDNSRefresh 刷新DNS缓存
func (s *Server) handleAPIDNSRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取所有启用的提供商名称
	var enabledProviders []string
	for _, provider := range s.config.SSL.DNSProviders {
		if provider.Enabled {
			enabledProviders = append(enabledProviders, provider.Name)
		}
	}

	// 触发所有启用提供商的缓存更新
	s.dnsCache.UpdateAllProvidersCache(enabledProviders)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"message":   "DNS cache refresh initiated",
		"providers": enabledProviders,
	})
}

// registerDNSProvider 注册DNS provider到SSL Manager
func (s *Server) registerDNSProvider(provider config.DNSProvider) error {
	var dnsProvider ssl.DNSProviderInterface

	switch strings.ToLower(provider.Type) {
	case "cloudflare":
		dnsProvider = ssl.NewCloudflareProvider(provider.APIKey, provider.ZoneID, s.log)
	case "aliyun":
		dnsProvider = ssl.NewAliyunProvider(provider.APIKey, provider.APISecret, s.log)
	case "tencent":
		dnsProvider = ssl.NewTencentProvider(provider.APIKey, provider.APISecret, s.log)
	case "godaddy":
		dnsProvider = ssl.NewGoDaddyProvider(provider.APIKey, provider.APISecret, s.log)
	case "namecheap":
		dnsProvider = ssl.NewNamecheapProvider(provider.APIKey, provider.APISecret, provider.ZoneID, s.log)
	case "aws":
		dnsProvider = ssl.NewAWSRoute53Provider(provider.APIKey, provider.APISecret, "us-east-1", s.log)
	case "custom":
		dnsProvider = ssl.NewCustomProvider(provider.Endpoint, provider.APIKey, s.log)
	default:
		return fmt.Errorf("Unknown DNS provider type: %s", provider.Type)
	}

	if err := dnsProvider.Validate(); err != nil {
		return fmt.Errorf("DNS provider %s validation failed: %v", provider.Name, err)
	}

	// 注册provider到SSL Manager
	s.sslManager.RegisterDNSProvider(provider.Name, dnsProvider, provider.Priority)
	s.log.Infof("Registered DNS provider: %s (%s) with priority %d", provider.Name, provider.Type, provider.Priority)
	return nil
}

// unregisterDNSProvider 从SSL Manager中注销DNS provider
func (s *Server) unregisterDNSProvider(providerName string) {
	s.sslManager.UnregisterDNSProvider(providerName)
	s.log.Infof("Unregistered DNS provider: %s", providerName)
}
