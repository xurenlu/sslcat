package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// ============================================
// HTTP/2 动态控制
// ============================================

// SetHTTP2Enabled 动态启用/禁用 HTTP/2
func (s *Server) SetHTTP2Enabled(enabled bool, reason string) {
	s.http2Mutex.Lock()
	defer s.http2Mutex.Unlock()

	if !enabled && s.http2DisableUntil.IsZero() {
		s.http2DisableUntil = time.Now().Add(10 * time.Minute)
		s.http2Enabled = false
		s.http2DisableReason = reason
		s.log.WithFields(logrus.Fields{
			"reason":         reason,
			"auto_resume_at": s.http2DisableUntil.Format(time.RFC3339),
		}).Warn("HTTP/2 已被禁用，将在 10 分钟后自动恢复")
	} else if enabled {
		s.http2DisableUntil = time.Time{}
		s.http2Enabled = true
		s.http2DisableReason = ""
		s.log.Info("HTTP/2 已被手动启用")
	}
}

// SetHTTP2DisabledForDuration 在指定时间内禁用 HTTP/2
func (s *Server) SetHTTP2DisabledForDuration(duration time.Duration, reason string) {
	s.http2Mutex.Lock()
	defer s.http2Mutex.Unlock()

	s.http2Enabled = false
	s.http2DisableUntil = time.Now().Add(duration)
	s.http2DisableReason = reason

	s.log.WithFields(logrus.Fields{
		"duration":       duration.String(),
		"reason":         reason,
		"auto_resume_at": s.http2DisableUntil.Format(time.RFC3339),
	}).Warn("HTTP/2 已被禁用")
}

// IsHTTP2Enabled 检查 HTTP/2 是否启用（考虑自动恢复）
func (s *Server) IsHTTP2Enabled() bool {
	s.http2Mutex.RLock()
	defer s.http2Mutex.RUnlock()

	if !s.http2Enabled && !s.http2DisableUntil.IsZero() && time.Now().After(s.http2DisableUntil) {
		s.http2Mutex.RUnlock()
		s.http2Mutex.Lock()
		if !s.http2Enabled && time.Now().After(s.http2DisableUntil) {
			s.http2Enabled = true
			s.http2DisableUntil = time.Time{}
			s.http2DisableReason = ""
			s.log.Info("HTTP/2 已自动恢复启用")
		}
		s.http2Mutex.Unlock()
		s.http2Mutex.RLock()
	}

	return s.http2Enabled
}

// GetHTTP2Status 获取 HTTP/2 状态信息
func (s *Server) GetHTTP2Status() map[string]interface{} {
	s.http2Mutex.RLock()
	defer s.http2Mutex.RUnlock()

	status := map[string]interface{}{
		"enabled":        s.http2Enabled,
		"config_enabled": s.config.Server.HTTP2Enabled,
	}

	if !s.http2Enabled && !s.http2DisableUntil.IsZero() {
		remaining := time.Until(s.http2DisableUntil)
		status["disabled_until"] = s.http2DisableUntil.Format(time.RFC3339)
		status["remaining_seconds"] = int(remaining.Seconds())
		status["reason"] = s.http2DisableReason
	}

	return status
}

// ============================================
// HTTP/2 API 处理器
// ============================================

// handleHTTP2Status 处理获取 HTTP/2 状态请求
func (s *Server) handleHTTP2Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    s.GetHTTP2Status(),
	})
}

// handleHTTP2Enable 处理启用 HTTP/2 请求
func (s *Server) handleHTTP2Enable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.SetHTTP2Enabled(true, "手动启用")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "HTTP/2 已启用",
		"data":    s.GetHTTP2Status(),
	})
}

// handleHTTP2Disable 处理禁用 HTTP/2 请求
func (s *Server) handleHTTP2Disable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Duration int    `json:"duration"` // 禁用时长（秒），0 表示默认 10 分钟
		Reason   string `json:"reason"`   // 禁用原因
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Duration = 0
		req.Reason = "手动禁用"
	}

	if req.Duration <= 0 {
		s.SetHTTP2Enabled(false, req.Reason)
	} else {
		s.SetHTTP2DisabledForDuration(time.Duration(req.Duration)*time.Second, req.Reason)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "HTTP/2 已禁用",
		"data":    s.GetHTTP2Status(),
	})
}
