package web

import (
	"net/http"
)

// handleAPIConfigBotAPIPrefix 返回机器人检测 API 前缀
func (s *Server) handleAPIConfigBotAPIPrefix(w http.ResponseWriter, r *http.Request) {
	// 验证管理员权限
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	prefix := s.config.BotAPIPrefix
	if prefix == "" {
		prefix = "/bot-api" // 兼容旧配置
	}

	writeJSON(w, map[string]interface{}{
		"success": true,
		"prefix":  prefix,
	})
}

