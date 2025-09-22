package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Session 会话信息
type Session struct {
	SessionID  string    `json:"session_id"`
	Username   string    `json:"username"`
	Role       string    `json:"role"`
	LoginTime  time.Time `json:"login_time"`
	ExpiresAt  time.Time `json:"expires_at"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	LastAccess time.Time `json:"last_access"`
}

// SessionManager 会话管理器
type SessionManager struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
	log      SessionLogger
}

// SessionLogger 会话管理器日志接口
type SessionLogger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// NewSessionManager 创建会话管理器
func NewSessionManager(log SessionLogger) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		log:      log,
	}

	// 启动清理过期会话的goroutine
	go sm.cleanupExpiredSessions()

	return sm
}

// CreateSession 创建会话
func (sm *SessionManager) CreateSession(username, role, ipAddress, userAgent string) (*Session, error) {
	sessionID := sm.generateSessionID()

	session := &Session{
		SessionID:  sessionID,
		Username:   username,
		Role:       role,
		LoginTime:  time.Now(),
		ExpiresAt:  time.Now().Add(8 * time.Hour), // 8小时过期
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		LastAccess: time.Now(),
	}

	sm.mutex.Lock()
	sm.sessions[sessionID] = session
	sm.mutex.Unlock()

	sm.log.Infof("会话创建成功: %s (用户: %s, 角色: %s)", sessionID, username, role)
	return session, nil
}

// GetSession 获取会话
func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(session.ExpiresAt) {
		// 异步删除过期会话
		go func() {
			sm.mutex.Lock()
			delete(sm.sessions, sessionID)
			sm.mutex.Unlock()
		}()
		return nil, false
	}

	// 更新最后访问时间
	session.LastAccess = time.Now()
	return session, true
}

// DeleteSession 删除会话
func (sm *SessionManager) DeleteSession(sessionID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		sm.log.Infof("会话删除: %s (用户: %s)", sessionID, session.Username)
		delete(sm.sessions, sessionID)
	}
}

// SetSessionCookie 设置会话Cookie
func (sm *SessionManager) SetSessionCookie(w http.ResponseWriter, sessionID string, secure bool) {
	cookie := &http.Cookie{
		Name:     "sslcat_session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   8 * 3600, // 8小时
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// GetSessionFromRequest 从请求中获取会话
func (sm *SessionManager) GetSessionFromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie("sslcat_session")
	if err != nil {
		return nil, false
	}

	return sm.GetSession(cookie.Value)
}

// GetAllSessions 获取所有会话
func (sm *SessionManager) GetAllSessions() []*Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	var sessions []*Session
	for _, session := range sm.sessions {
		// 检查是否过期
		if time.Now().Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// GetUserSessions 获取用户的所有会话
func (sm *SessionManager) GetUserSessions(username string) []*Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	var sessions []*Session
	for _, session := range sm.sessions {
		if session.Username == username && time.Now().Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// DeleteUserSessions 删除用户的所有会话
func (sm *SessionManager) DeleteUserSessions(username string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	for sessionID, session := range sm.sessions {
		if session.Username == username {
			sm.log.Infof("删除用户会话: %s (用户: %s)", sessionID, username)
			delete(sm.sessions, sessionID)
		}
	}
}

// ExtendSession 延长会话过期时间
func (sm *SessionManager) ExtendSession(sessionID string, duration time.Duration) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return false
	}

	session.ExpiresAt = time.Now().Add(duration)
	session.LastAccess = time.Now()
	return true
}

// cleanupExpiredSessions 清理过期会话
func (sm *SessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mutex.Lock()
		now := time.Now()
		expiredCount := 0

		for sessionID, session := range sm.sessions {
			if now.After(session.ExpiresAt) {
				delete(sm.sessions, sessionID)
				expiredCount++
			}
		}

		if expiredCount > 0 {
			sm.log.Debugf("清理过期会话: %d 个", expiredCount)
		}
		sm.mutex.Unlock()
	}
}

// generateSessionID 生成会话ID
func (sm *SessionManager) generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetSessionStats 获取会话统计信息
func (sm *SessionManager) GetSessionStats() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	now := time.Now()
	activeSessions := 0
	expiredSessions := 0
	userCount := make(map[string]int)

	for _, session := range sm.sessions {
		if now.Before(session.ExpiresAt) {
			activeSessions++
			userCount[session.Username]++
		} else {
			expiredSessions++
		}
	}

	return map[string]interface{}{
		"active_sessions":  activeSessions,
		"expired_sessions": expiredSessions,
		"total_sessions":   len(sm.sessions),
		"unique_users":     len(userCount),
		"user_sessions":    userCount,
	}
}
