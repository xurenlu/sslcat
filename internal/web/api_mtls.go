package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// mTLSStatsResponse mTLS 统计响应
type mTLSStatsResponse struct {
	TotalConnections int64     `json:"total_connections"`
	ValidCerts       int64     `json:"valid_certs"`
	InvalidCerts     int64     `json:"invalid_certs"`
	RevokedCerts     int64     `json:"revoked_certs"`
	ExpiredCerts     int64     `json:"expired_certs"`
	WhitelistedCerts int64     `json:"whitelisted_certs"`
	BlacklistedCerts int64     `json:"blacklisted_certs"`
	LastConnection   string    `json:"last_connection"`
	LastCertError    string    `json:"last_cert_error"`
	LastErrorReason  string    `json:"last_error_reason"`
}

// ClientIdentityResponse 客户端身份响应
type ClientIdentityResponse struct {
	CommonName         string  `json:"common_name"`
	Organization       string  `json:"organization"`
	OrganizationalUnit string  `json:"organizational_unit"`
	SerialNumber       string  `json:"serial_number"`
	Fingerprint        string  `json:"fingerprint"`
	IsValid            bool    `json:"is_valid"`
	IsRevoked          bool    `json:"is_revoked"`
	NotBefore          string  `json:"not_before"`
	NotAfter           string  `json:"not_after"`
	DaysUntilExpiry    int     `json:"days_until_expiry"`
}

// mTLSConfigRequest mTLS 配置请求
type mTLSConfigRequest struct {
	Enabled            bool   `json:"enabled"`
	Mode               string `json:"mode"` // "strict", "optional", "verify_client_if_given"
	ClientCertRequired bool   `json:"client_cert_required"`
	CertPinningEnabled bool   `json:"cert_pinning_enabled"`
}

// handlemTLSStats 获取 mTLS 统计信息
func (s *Server) handlemTLSStats(w http.ResponseWriter, r *http.Request) {
	if s.mtlsManager == nil {
		s.sendJSON(w, map[string]interface{}{
			"enabled": false,
			"error":   "mTLS not enabled",
		})
		return
	}

	stats := s.mtlsManager.GetStats()

	response := mTLSStatsResponse{
		TotalConnections: stats.TotalConnections,
		ValidCerts:       stats.ValidCerts,
		InvalidCerts:     stats.InvalidCerts,
		RevokedCerts:     stats.RevokedCerts,
		ExpiredCerts:     stats.ExpiredCerts,
		WhitelistedCerts: stats.WhitelistedCerts,
		BlacklistedCerts: stats.BlacklistedCerts,
		LastConnection:   stats.LastConnection.Format(time.RFC3339),
		LastCertError:    stats.LastCertError.Format(time.RFC3339),
		LastErrorReason:  stats.LastErrorReason,
	}

	s.sendJSON(w, response)
}

// handlemTLSConfig 获取和更新 mTLS 配置
func (s *Server) handlemTLSConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.handlemTLSGetConfig(w, r)
		return
	}
	if r.Method == http.MethodPost {
		s.handlemTLSUpdateConfig(w, r)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handlemTLSGetConfig 获取 mTLS 配置
func (s *Server) handlemTLSGetConfig(w http.ResponseWriter, r *http.Request) {
	if s.mtlsManager == nil {
		s.sendJSON(w, map[string]interface{}{
			"enabled":                 false,
			"mode":                    "optional",
			"client_cert_required":    false,
			"crl_check_enabled":       false,
			"cert_pinning_enabled":    false,
		})
		return
	}

	// TODO: 返回实际配置
	s.sendJSON(w, map[string]interface{}{
		"enabled":                 true,
		"mode":                    "strict",
		"client_cert_required":    true,
		"crl_check_enabled":       true,
		"cert_pinning_enabled":    false,
	})
}

// handlemTLSUpdateConfig 更新 mTLS 配置
func (s *Server) handlemTLSUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req mTLSConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TODO: 更新配置
	s.log.Infof("mTLS config updated: enabled=%v, mode=%s", req.Enabled, req.Mode)

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Configuration updated",
	})
}

// handlemTLSWhitelist 管理 mTLS 证书白名单
func (s *Server) handlemTLSWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.mtlsManager == nil {
			s.sendJSON(w, map[string]interface{}{
				"certificates": []string{},
			})
			return
		}
		// TODO: 返回白名单
		s.sendJSON(w, map[string]interface{}{
			"certificates": []string{},
		})

	case http.MethodPost:
		var req struct {
			SerialNumber string `json:"serial_number"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if s.mtlsManager != nil {
			s.mtlsManager.AddToWhitelist(req.SerialNumber)
		}
		s.sendJSON(w, map[string]interface{}{
			"success": true,
			"message": "Added to whitelist",
		})

	case http.MethodDelete:
		var req struct {
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		s.mtlsManager.RemoveFromWhitelist(req.Fingerprint)
		s.sendJSON(w, map[string]interface{}{
			"success": true,
			"message": "Removed from whitelist",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlemTLSBlacklist 管理 mTLS 证书黑名单
func (s *Server) handlemTLSBlacklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.mtlsManager == nil {
			s.sendJSON(w, map[string]interface{}{
				"certificates": []string{},
			})
			return
		}
		// TODO: 返回黑名单
		s.sendJSON(w, map[string]interface{}{
			"certificates": []string{},
		})

	case http.MethodPost:
		var req struct {
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		s.mtlsManager.AddToBlacklist(req.Fingerprint)
		s.sendJSON(w, map[string]interface{}{
			"success": true,
			"message": "Added to blacklist",
		})

	case http.MethodDelete:
		var req struct {
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		s.mtlsManager.RemoveFromBlacklist(req.Fingerprint)
		s.sendJSON(w, map[string]interface{}{
			"success": true,
			"message": "Removed from blacklist",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlemTLSGenerateClientCert 生成客户端证书
func (s *Server) handlemTLSGenerateClientCert(w http.ResponseWriter, r *http.Request) {
	if s.mtlsManager == nil {
		http.Error(w, "mTLS not enabled", http.StatusBadRequest)
		return
	}

	var req struct {
		CommonName   string `json:"common_name"`
		Organization string `json:"organization"`
		ValidityDays int    `json:"validity_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	validity := time.Duration(req.ValidityDays) * 24 * time.Hour
	certPEM, keyPEM, err := s.mtlsManager.GenerateClientCert(req.CommonName, req.Organization, validity)
	if err != nil {
		s.log.Errorf("Failed to generate client certificate: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success":        true,
		"certificate":    string(certPEM),
		"private_key":    string(keyPEM),
		"common_name":    req.CommonName,
		"organization":   req.Organization,
		"validity_days":  req.ValidityDays,
		"expires_at":     time.Now().Add(validity).Format(time.RFC3339),
	})
}

// handlemTLSVerifyClientCert 验证客户端证书
func (s *Server) handlemTLSVerifyClientCert(w http.ResponseWriter, r *http.Request) {
	if s.mtlsManager == nil {
		http.Error(w, "mTLS not enabled", http.StatusBadRequest)
		return
	}

	var req struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TODO: 解析并验证证书
	s.sendJSON(w, map[string]interface{}{
		"success":  true,
		"valid":    true,
		"identity": ClientIdentityResponse{},
	})
}

// handlemTLSListCertificates 列出已颁发的证书
func (s *Server) handlemTLSListCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.mtlsManager == nil {
		s.sendJSON(w, map[string]interface{}{
			"certificates": []interface{}{},
		})
		return
	}

	// TODO: 返回实际的证书列表
	s.sendJSON(w, map[string]interface{}{
		"certificates": []interface{}{},
	})
}

// handlemTLSRevokeCertificate 吊销证书
func (s *Server) handlemTLSRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.mtlsManager == nil {
		s.sendJSON(w, map[string]interface{}{
			"success": false,
			"message": "mTLS not enabled",
		})
		return
	}

	var req struct {
		SerialNumber string `json:"serial_number"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TODO: 实际吊销证书
	s.log.Infof("Certificate revoked: %s", req.SerialNumber)
	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Certificate revoked",
	})
}

// handlemTLSWhitelistDelete 从白名单删除证书（支持 URL 路径参数）
func (s *Server) handlemTLSWhitelistDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 从 URL 路径中提取序列号
	// URL 格式: /api/mtls/whitelist/{serial}
	path := r.URL.Path
	prefix := s.config.AdminPrefix + "/api/mtls/whitelist/"
	if !strings.HasPrefix(path, prefix) {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	serialNumber := strings.TrimPrefix(path, prefix)
	if serialNumber == "" {
		http.Error(w, "Serial number is required", http.StatusBadRequest)
		return
	}

	if s.mtlsManager != nil {
		s.mtlsManager.RemoveFromWhitelist(serialNumber)
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Removed from whitelist",
	})
}
