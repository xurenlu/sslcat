package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// handleAPISSLGenerate 申请SSL证书
func (s *Server) handleAPISSLGenerate(w http.ResponseWriter, r *http.Request) {
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
	for _, domain := range req.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		if err := s.sslManager.EnsureDomainCert(domain); err != nil {
			results[domain] = map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			}
			s.log.Warnf("Failed to generate certificate for %s: %v", domain, err)
		} else {
			results[domain] = map[string]interface{}{
				"success": true,
				"message": "certificate request initiated",
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"results": results,
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

	// 保存证书和私钥（需要实现 SaveCertificate 方法或使用现有方法）
	// 临时使用文件写入，后续可优化为调用 sslManager 方法
	certPath := s.config.SSL.CertDir + "/" + req.Domain + ".crt"
	keyPath := s.config.SSL.KeyDir + "/" + req.Domain + ".key"
	
	if err := os.WriteFile(certPath, []byte(req.Certificate), 0644); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save certificate"})
		return
	}
	
	if err := os.WriteFile(keyPath, []byte(req.PrivateKey), 0600); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to save private key"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "certificate uploaded and saved",
		"domain":  req.Domain,
	})
}
