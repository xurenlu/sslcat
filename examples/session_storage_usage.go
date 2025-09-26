package main

import (
	"fmt"
	"log"
	"time"

	"github.com/xurenlu/sslcat/internal/web"
)

func main() {
	// 创建日志接口
	logger := &SimpleLogger{}

	// 创建会话管理器工厂
	factory := web.NewSessionManagerFactory()

	// 使用文件存储
	sessionManager, err := factory.CreateSessionManager(logger, "file", "./data")
	if err != nil {
		log.Fatalf("创建会话管理器失败: %v", err)
	}
	defer sessionManager.Close()

	// 创建会话
	session, err := sessionManager.CreateSession("admin", "super_admin", "127.0.0.1", "Mozilla/5.0")
	if err != nil {
		log.Fatalf("创建会话失败: %v", err)
	}

	fmt.Printf("创建会话成功: %s\n", session.SessionID)

	// 获取会话
	retrievedSession, exists := sessionManager.GetSession(session.SessionID)
	if !exists {
		log.Fatalf("获取会话失败")
	}

	fmt.Printf("获取会话成功: 用户=%s, 角色=%s\n", retrievedSession.Username, retrievedSession.Role)

	// 获取会话统计
	stats := sessionManager.GetSessionStats()
	fmt.Printf("会话统计: %+v\n", stats)

	// 延长会话
	extended := sessionManager.ExtendSession(session.SessionID, 2*time.Hour)
	fmt.Printf("延长会话: %v\n", extended)

	// 删除会话
	sessionManager.DeleteSession(session.SessionID)
	fmt.Println("会话已删除")

	// 再次获取会话（应该失败）
	_, exists = sessionManager.GetSession(session.SessionID)
	fmt.Printf("会话是否存在: %v\n", exists)
}

// SimpleLogger 简单日志实现
type SimpleLogger struct{}

func (l *SimpleLogger) Infof(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func (l *SimpleLogger) Warnf(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func (l *SimpleLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}

func (l *SimpleLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}
