package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/ssl"
)

// handleAPISSLGenerate 申请SSL证书
func (s *Server) handleAPISSLGenerate(w http.ResponseWriter, r *http.Request) {
	// 处理 OPTIONS 预检请求
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domains []string `json:"domains"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if len(req.Domains) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domains are required"})
		return
	}

	results := make(map[string]interface{})
	var successCount, failureCount int

	for _, domain := range req.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		s.log.Infof("API: Starting certificate request for domain: %s", domain)
		if err := s.sslManager.EnsureDomainCert(domain); err != nil {
			results[domain] = map[string]interface{}{
				"success":    false,
				"error":      err.Error(),
				"retry_info": "Certificate request failed after retry attempts",
			}
			failureCount++
			s.log.Errorf("API: Failed to generate certificate for %s: %v", domain, err)
		} else {
			results[domain] = map[string]interface{}{
				"success":    true,
				"message":    "Certificate request successful",
				"retry_info": "Request completed successfully",
			}
			successCount++
			s.log.Infof("API: Certificate request successful for domain: %s", domain)
		}
	}

	// 记录总体结果
	s.log.Infof("API: Certificate request batch completed: %d successful, %d failed", successCount, failureCount)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"results": results,
		"summary": map[string]interface{}{
			"total_domains": len(req.Domains),
			"successful":    successCount,
			"failed":        failureCount,
			"retry_enabled": true,
		},
	})
}

// handleAPISSLGenerateStream 申请SSL证书（支持SSE流式进度）
func (s *Server) handleAPISSLGenerateStream(w http.ResponseWriter, r *http.Request) {
	// 处理 OPTIONS 预检请求
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain is required"})
		return
	}

	// 设置 SSE 响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// 创建进度通道
	progressCh := s.sslManager.CreateProgressChannel(domain)
	
	// 使用 done 通道来协调 goroutine 和主循环
	done := make(chan struct{})
	var closeOnce sync.Once
	
	// 在 goroutine 中执行证书申请
	go func() {
		defer func() {
			// 捕获 panic，避免向已关闭的通道发送
			if r := recover(); r != nil {
				s.log.Errorf("Certificate request goroutine panic: %v", r)
			}
			// 通知主循环 goroutine 已完成
			close(done)
			// 延迟关闭进度通道，确保所有事件都已发送
			time.Sleep(200 * time.Millisecond)
			closeOnce.Do(func() {
				s.sslManager.CloseProgressChannel(domain)
			})
		}()

		if err := s.sslManager.EnsureDomainCert(domain); err != nil {
			// 发送失败事件（使用非阻塞方式，带 recover）
			func() {
				defer func() {
					if r := recover(); r != nil {
						// 通道已关闭，忽略
					}
				}()
				select {
				case progressCh <- ssl.CertProgressEvent{
					Domain:      domain,
					Status:      "failed",
					Message:     fmt.Sprintf("证书申请失败: %v", err),
					Progress:    100,
					Error:       err.Error(),
					Timestamp:   time.Now(),
				}:
				case <-time.After(100 * time.Millisecond):
					// 超时，通道可能已关闭，忽略
				}
			}()
		}
	}()

	// 监听进度事件并发送到客户端
	ctx := r.Context()
	defer func() {
		// 确保通道被关闭
		closeOnce.Do(func() {
			s.sslManager.CloseProgressChannel(domain)
		})
	}()

	for {
		select {
		case event, ok := <-progressCh:
			if !ok {
				// 通道已关闭
				return
			}

			// 发送 SSE 事件
			eventJSON, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", eventJSON)
			flusher.Flush()

			// 如果已完成或失败，等待 goroutine 完成后再返回
			if event.Status == "success" || event.Status == "failed" || event.Status == "completed" {
				// 等待 goroutine 完成
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					// 超时，强制关闭
				}
				return
			}

		case <-ctx.Done():
			// 客户端断开连接，等待 goroutine 完成
			select {
			case <-done:
			case <-time.After(1 * time.Second):
			}
			return
			
		case <-done:
			// goroutine 已完成，等待最后的事件
			select {
			case event, ok := <-progressCh:
				if ok {
					eventJSON, _ := json.Marshal(event)
					fmt.Fprintf(w, "data: %s\n\n", eventJSON)
					flusher.Flush()
				}
			case <-time.After(500 * time.Millisecond):
				// 超时，没有更多事件
			}
			return
		}
	}
}

// handleAPISSLRetryConfig 获取重试配置信息
func (s *Server) handleAPISSLRetryConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 获取DNS服务商信息
	var dnsProviders []string
	if s.sslManager != nil {
		dnsProviders = s.sslManager.GetDNSProviders()
	}

	config := map[string]interface{}{
		"retry_enabled": true,
		"max_retries": map[string]int{
			"http_validation": 3,
			"dns_validation":  2,
		},
		"retry_delays": map[string]string{
			"http_validation": "10s, 20s, 30s",
			"dns_validation":  "15s, 30s",
		},
		"fallback_strategy": "HTTP-01 -> DNS-01",
		"dns_providers":     dnsProviders,
		"dns_available":     len(dnsProviders) > 0,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"config":  config,
	})
}

// handleAPISSLRetry 手动重试证书申请
func (s *Server) handleAPISSLRetry(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain is required"})
		return
	}

	domain := strings.TrimSpace(req.Domain)
	s.log.Infof("Manual retry requested for domain: %s", domain)

	// 执行重试
	if err := s.sslManager.EnsureDomainCert(domain); err != nil {
		s.log.Errorf("Manual retry failed for domain %s: %v", domain, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
			"domain":  domain,
		})
		return
	}

	s.log.Infof("Manual retry successful for domain: %s", domain)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Certificate request successful",
		"domain":  domain,
	})
}

// handleAPISSLDelete 删除SSL证书
func (s *Server) handleAPISSLDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain parameter is required"})
		return
	}

	// 删除证书文件
	if err := s.sslManager.DeleteCertificate(domain); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "certificate deleted",
		"domain":  domain,
	})
}

// handleAPISSLPreflight 域名预检API，检查DNS Provider、解析IP、挑战方式等
func (s *Server) handleAPISSLPreflight(w http.ResponseWriter, r *http.Request) {
	// 处理 OPTIONS 预检请求
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	if !s.authorizeAPI(w, r, true) { // 只需要读权限
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain parameter is required"})
		return
	}

	if s.sslManager == nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "SSL manager not initialized"})
		return
	}

	// 查找DNS Provider
	dnsProvider := s.sslManager.FindDNSProviderForDomain(domain)
	
	// 检查域名解析
	resolved, resolutionInfo, resolutionErr := s.sslManager.CheckDomainResolution(domain)
	
	// 提取IP地址信息
	var pointsToServer bool
	if resolutionErr == nil {
		pointsToServer = resolved
	}

	// 判断挑战方式
	supportsDNS := s.sslManager.SupportsDNSChallenge()
	hasProvider := s.sslManager.HasAvailableDNSProvider()
	var challengeType string
	var challengeReason string

	if supportsDNS && hasProvider && dnsProvider != "" {
		challengeType = "DNS-01"
		challengeReason = fmt.Sprintf("域名在 DNS 服务商 %s 中，将使用 DNS-01 验证", dnsProvider)
	} else {
		challengeType = "HTTP-01"
		if dnsProvider == "" {
			challengeReason = "域名不在已配置的 DNS 服务商中，将使用 HTTP-01 验证"
		} else if !supportsDNS {
			challengeReason = "DNS-01 挑战未启用，将使用 HTTP-01 验证"
		} else if !hasProvider {
			challengeReason = "没有可用的 DNS 服务商，将使用 HTTP-01 验证"
		} else {
			challengeReason = "将使用 HTTP-01 验证"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"domain":  domain,
		"dns_provider": map[string]interface{}{
			"name":      dnsProvider,
			"found":     dnsProvider != "",
			"available": dnsProvider != "",
		},
		"resolution": map[string]interface{}{
			"resolved":         resolved,
			"points_to_server": pointsToServer,
			"info":             resolutionInfo,
			"error":            func() string {
				if resolutionErr != nil {
					return resolutionErr.Error()
				}
				return ""
			}(),
		},
		"challenge": map[string]interface{}{
			"type":   challengeType,
			"reason": challengeReason,
		},
	})
}

// handleAPISSLUpload 上传SSL证书
func (s *Server) handleAPISSLUpload(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain      string `json:"domain"`
		Certificate string `json:"certificate"` // PEM格式证书内容
		PrivateKey  string `json:"private_key"` // PEM格式私钥内容
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Domain == "" || req.Certificate == "" || req.PrivateKey == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "domain, certificate and private_key are required"})
		return
	}

	// 确保证书和密钥目录存在
	if err := os.MkdirAll(s.config.SSL.CertDir, 0755); err != nil {
		s.log.Errorf("Failed to create cert directory: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to create cert directory"})
		return
	}
	if err := os.MkdirAll(s.config.SSL.KeyDir, 0755); err != nil {
		s.log.Errorf("Failed to create key directory: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to create key directory"})
		return
	}

	// 使用 filepath.Join 构建路径，确保跨平台兼容性
	certPath := filepath.Join(s.config.SSL.CertDir, req.Domain+".crt")
	keyPath := filepath.Join(s.config.SSL.KeyDir, req.Domain+".key")

	if err := os.WriteFile(certPath, []byte(req.Certificate), 0644); err != nil {
		s.log.Errorf("Failed to save certificate to %s: %v", certPath, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save certificate"})
		return
	}

	if err := os.WriteFile(keyPath, []byte(req.PrivateKey), 0600); err != nil {
		s.log.Errorf("Failed to save private key to %s: %v", keyPath, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save private key"})
		return
	}

	s.log.Infof("Certificate uploaded via API successfully: domain=%s, cert=%s, key=%s", req.Domain, certPath, keyPath)

	// 加载证书到内存
	if err := s.sslManager.LoadCertificateFromDisk(req.Domain); err != nil {
		s.log.Warnf("Failed to load certificate after upload: %v", err)
		// 即使加载失败也返回成功，因为文件已保存
	} else {
		s.log.Infof("Certificate loaded to memory successfully: domain=%s", req.Domain)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "certificate uploaded and saved",
		"domain":  req.Domain,
	})
}
