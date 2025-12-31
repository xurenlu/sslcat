package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/waf"
)

// handleAPISecurityBlockedList 获取统一封禁列表
func (s *Server) handleAPISecurityBlockedList(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	result := map[string]interface{}{
		"ips":             []map[string]interface{}{},
		"tls_fingerprints": []map[string]interface{}{},
		"user_agents":     []map[string]interface{}{},
	}

	// 1. 获取Security Manager的IP封禁列表（包括DDoS封禁的IP）
	blockedIPs := s.securityManager.GetBlockedIPs()
	for _, blocked := range blockedIPs {
		// 判断来源：如果原因包含"DDoS攻击"，标记为ddos，否则为security
		source := "security"
		if strings.Contains(blocked.Reason, "DDoS攻击") {
			source = "ddos"
		} else if strings.Contains(blocked.Reason, "机器人") || strings.Contains(blocked.Reason, "bot") {
			source = "bot"
		}
		
		result["ips"] = append(result["ips"].([]map[string]interface{}), map[string]interface{}{
			"source":      source,
			"ip":          blocked.IP,
			"reason":      blocked.Reason,
			"block_time":  blocked.BlockTime,
			"expire_time": blocked.ExpireTime,
		})
	}

	// 2. 获取WAF的IP和TLS指纹封禁列表
	if s.wafEngine != nil && s.wafEngine.Engine != nil {
		// WAF IP封禁列表
		wafIPBlocks := s.wafEngine.Engine.GetMultiDimBlockedList(waf.DimensionIP)
		for _, blocked := range wafIPBlocks {
			result["ips"] = append(result["ips"].([]map[string]interface{}), map[string]interface{}{
				"source":      "waf",
				"ip":          blocked.Value,
				"reason":      blocked.Reason,
				"block_time":  blocked.FirstSeen,
				"expire_time": blocked.ExpireTime,
			})
		}

		// WAF TLS指纹封禁列表
		wafTLSBlocks := s.wafEngine.Engine.GetMultiDimBlockedList(waf.DimensionTLS)
		for _, blocked := range wafTLSBlocks {
			result["tls_fingerprints"] = append(result["tls_fingerprints"].([]map[string]interface{}), map[string]interface{}{
				"fingerprint": blocked.Value,
				"reason":      blocked.Reason,
				"block_time":  blocked.FirstSeen,
				"expire_time": blocked.ExpireTime,
			})
		}
	}

	// 3. 获取User-Agent封禁列表
	blockedUAs := s.securityManager.GetBlockedUserAgents()
	for _, blocked := range blockedUAs {
		result["user_agents"] = append(result["user_agents"].([]map[string]interface{}), map[string]interface{}{
			"user_agent":  blocked.UserAgent,
			"reason":      blocked.Reason,
			"block_time":  blocked.BlockTime,
			"expire_time": blocked.ExpireTime,
		})
	}

	s.writeSuccessResponse(w, result, "Blocked list retrieved successfully")
}

// handleAPISecurityBlock 手动封禁
func (s *Server) handleAPISecurityBlock(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Type     string `json:"type"`      // "ip", "tls_fingerprint", "user_agent"
		Value    string `json:"value"`     // 要封禁的值
		Duration int    `json:"duration"`  // 封禁时长（秒），0表示永久
		Reason   string `json:"reason"`    // 封禁原因（可选）
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	if req.Type == "" || req.Value == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Type and value are required")
		return
	}

	duration := time.Duration(req.Duration) * time.Second
	if req.Duration == 0 {
		duration = 0 // 永久封禁
	}

	reason := req.Reason
	if reason == "" {
		reason = "Manual block"
	}

	switch req.Type {
	case "ip":
		// 同时封禁到security manager和WAF
		s.securityManager.BlockIP(req.Value, duration, reason)
		if s.wafEngine != nil && s.wafEngine.Engine != nil {
			s.wafEngine.Engine.BlockMultiDim(waf.DimensionIP, req.Value, duration, reason)
		}
		s.writeSuccessResponse(w, map[string]interface{}{
			"type":        "ip",
			"value":       req.Value,
			"duration":    req.Duration,
			"reason":      reason,
			"blocked_at":  time.Now().Format("2006-01-02 15:04:05"),
		}, fmt.Sprintf("IP %s blocked successfully", req.Value))

	case "tls_fingerprint":
		// 只封禁到WAF
		if s.wafEngine == nil || s.wafEngine.Engine == nil {
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
			return
		}
		s.wafEngine.Engine.BlockMultiDim(waf.DimensionTLS, req.Value, duration, reason)
		s.writeSuccessResponse(w, map[string]interface{}{
			"type":        "tls_fingerprint",
			"value":       req.Value[:min(len(req.Value), 16)] + "...",
			"duration":    req.Duration,
			"reason":      reason,
			"blocked_at":  time.Now().Format("2006-01-02 15:04:05"),
		}, "TLS fingerprint blocked successfully")

	case "user_agent":
		// 只封禁到security manager
		s.securityManager.BlockUserAgent(req.Value, duration, reason)
		s.writeSuccessResponse(w, map[string]interface{}{
			"type":        "user_agent",
			"value":       req.Value,
			"duration":    req.Duration,
			"reason":      reason,
			"blocked_at":  time.Now().Format("2006-01-02 15:04:05"),
		}, "User-Agent blocked successfully")

	default:
		s.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid type: %s. Must be 'ip', 'tls_fingerprint', or 'user_agent'", req.Type))
	}
}

// handleAPISecurityUnblock 统一解封
func (s *Server) handleAPISecurityUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Type  string `json:"type"`  // "ip", "tls_fingerprint", "user_agent"
		Value string `json:"value"` // 要解封的值
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	if req.Type == "" || req.Value == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Type and value are required")
		return
	}

	switch req.Type {
	case "ip":
		// 从security manager和WAF都解封
		s.securityManager.UnblockIP(req.Value)
		if s.wafEngine != nil && s.wafEngine.Engine != nil {
			s.wafEngine.Engine.UnblockMultiDim(waf.DimensionIP, req.Value)
		}
		s.writeSuccessResponse(w, map[string]interface{}{
			"type":         "ip",
			"value":        req.Value,
			"unblocked_at": time.Now().Format("2006-01-02 15:04:05"),
		}, fmt.Sprintf("IP %s unblocked successfully", req.Value))

	case "tls_fingerprint":
		// 只从WAF解封
		if s.wafEngine == nil || s.wafEngine.Engine == nil {
			s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
			return
		}
		s.wafEngine.Engine.UnblockMultiDim(waf.DimensionTLS, req.Value)
		s.writeSuccessResponse(w, map[string]interface{}{
			"type":         "tls_fingerprint",
			"value":        req.Value[:min(len(req.Value), 16)] + "...",
			"unblocked_at": time.Now().Format("2006-01-02 15:04:05"),
		}, "TLS fingerprint unblocked successfully")

	case "user_agent":
		// 只从security manager解封
		s.securityManager.UnblockUserAgent(req.Value)
		s.writeSuccessResponse(w, map[string]interface{}{
			"type":         "user_agent",
			"value":        req.Value,
			"unblocked_at": time.Now().Format("2006-01-02 15:04:05"),
		}, "User-Agent unblocked successfully")

	default:
		s.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid type: %s. Must be 'ip', 'tls_fingerprint', or 'user_agent'", req.Type))
	}
}

// handleAPIDDoSStats 获取DDoS攻击统计和监控信息
func (s *Server) handleAPIDDoSStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查DDoS防护器是否可用
	if s.ddosProtector == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "DDoS protector not available")
		return
	}

	// 获取基础统计
	stats := s.ddosProtector.GetStats()
	
	// 获取全局攻击统计
	globalStats := s.ddosProtector.GetGlobalAttackStats()
	
	// 获取最近的攻击记录（最近50条）
	recentAttacks := s.ddosProtector.GetAttacks(50)
	
	// 转换为JSON友好的格式
	var attacksList []map[string]interface{}
	for _, attack := range recentAttacks {
		attacksList = append(attacksList, map[string]interface{}{
			"id":           attack.ID,
			"client_ip":    attack.ClientIP,
			"user_agent":   attack.UserAgent,
			"url":          attack.URL,
			"method":       attack.Method,
			"attack_type":  attack.AttackType,
			"severity":     attack.Severity,
			"timestamp":    attack.Timestamp,
			"blocked":      attack.Blocked,
			"reason":       attack.Reason,
			"country":      attack.Country,
			"country_code": attack.CountryCode,
			"isp":          attack.ISP,
		})
	}

	result := map[string]interface{}{
		"stats":         stats,
		"global_stats":  globalStats,
		"recent_attacks": attacksList,
	}

	s.writeSuccessResponse(w, result, "DDoS statistics retrieved successfully")
}
