package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
	storage SessionStorage
	mutex   sync.RWMutex
	log     SessionLogger
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
		storage: NewMemorySessionStorage(),
		log:     log,
	}

	// 启动清理过期会话的goroutine
	go sm.cleanupExpiredSessions()

	return sm
}

// NewSessionManagerWithStorage 创建带存储后端的会话管理器
func NewSessionManagerWithStorage(storage SessionStorage, log SessionLogger) *SessionManager {
	sm := &SessionManager{
		storage: storage,
		log:     log,
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
	err := sm.storage.Set(sessionID, session)
	sm.mutex.Unlock()

	if err != nil {
		return nil, fmt.Errorf("保存会话失败: %v", err)
	}

	sm.log.Infof("会话创建成功: %s (用户: %s, 角色: %s)", sessionID, username, role)
	return session, nil
}

// GetSession 获取会话
func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mutex.RLock()
	session, err := sm.storage.Get(sessionID)
	sm.mutex.RUnlock()

	if err != nil {
		return nil, false
	}

	// 更新最后访问时间
	session.LastAccess = time.Now()

	// 异步更新会话
	go func() {
		sm.mutex.Lock()
		sm.storage.Set(sessionID, session)
		sm.mutex.Unlock()
	}()

	return session, true
}

// DeleteSession 删除会话
func (sm *SessionManager) DeleteSession(sessionID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	// 先获取会话信息用于日志
	if session, err := sm.storage.Get(sessionID); err == nil {
		sm.log.Infof("会话删除: %s (用户: %s)", sessionID, session.Username)
	}

	sm.storage.Delete(sessionID)
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

	sessionMap, err := sm.storage.GetAll()
	if err != nil {
		sm.log.Errorf("获取所有会话失败: %v", err)
		return []*Session{}
	}

	var sessions []*Session
	for _, session := range sessionMap {
		sessions = append(sessions, session)
	}

	return sessions
}

// GetUserSessions 获取用户的所有会话
func (sm *SessionManager) GetUserSessions(username string) []*Session {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	sessionMap, err := sm.storage.GetAll()
	if err != nil {
		sm.log.Errorf("获取用户会话失败: %v", err)
		return []*Session{}
	}

	var sessions []*Session
	for _, session := range sessionMap {
		if session.Username == username {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// DeleteUserSessions 删除用户的所有会话
func (sm *SessionManager) DeleteUserSessions(username string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sessionMap, err := sm.storage.GetAll()
	if err != nil {
		sm.log.Errorf("获取用户会话失败: %v", err)
		return
	}

	for sessionID, session := range sessionMap {
		if session.Username == username {
			sm.log.Infof("删除用户会话: %s (用户: %s)", sessionID, username)
			sm.storage.Delete(sessionID)
		}
	}
}

// ExtendSession 延长会话过期时间
func (sm *SessionManager) ExtendSession(sessionID string, duration time.Duration) bool {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	session, err := sm.storage.Get(sessionID)
	if err != nil {
		return false
	}

	session.ExpiresAt = time.Now().Add(duration)
	session.LastAccess = time.Now()

	err = sm.storage.Set(sessionID, session)
	return err == nil
}

// cleanupExpiredSessions 清理过期会话
func (sm *SessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mutex.Lock()
		sessionMap, err := sm.storage.GetAll()
		if err != nil {
			sm.log.Errorf("清理过期会话失败: %v", err)
			sm.mutex.Unlock()
			continue
		}

		expiredCount := 0
		now := time.Now()

		for sessionID, session := range sessionMap {
			if now.After(session.ExpiresAt) {
				sm.storage.Delete(sessionID)
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

	sessionMap, err := sm.storage.GetAll()
	if err != nil {
		sm.log.Errorf("获取会话统计失败: %v", err)
		return map[string]interface{}{
			"active_sessions":  0,
			"expired_sessions": 0,
			"total_sessions":   0,
			"unique_users":     0,
			"user_sessions":    make(map[string]int),
		}
	}

	now := time.Now()
	activeSessions := 0
	expiredSessions := 0
	userCount := make(map[string]int)

	for _, session := range sessionMap {
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
		"total_sessions":   len(sessionMap),
		"unique_users":     len(userCount),
		"user_sessions":    userCount,
	}
}

// Close 关闭会话管理器
func (sm *SessionManager) Close() error {
	return sm.storage.Close()
}
