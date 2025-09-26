package web

import (
	"fmt"
	"os"
	"path/filepath"
)

// SessionManagerFactory 会话管理器工厂
type SessionManagerFactory struct{}

// NewSessionManagerFactory 创建会话管理器工厂
func NewSessionManagerFactory() *SessionManagerFactory {
	return &SessionManagerFactory{}
}

// CreateSessionManager 创建会话管理器
func (f *SessionManagerFactory) CreateSessionManager(log SessionLogger, storageType string, dataDir string) (*SessionManager, error) {
	var storage SessionStorage
	var err error

	switch storageType {
	case "file":
		// 确保数据目录存在
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, fmt.Errorf("创建数据目录失败: %v", err)
		}

		sessionDir := filepath.Join(dataDir, "sessions")
		storage, err = NewFileSessionStorage(sessionDir)
		if err != nil {
			return nil, fmt.Errorf("创建文件存储失败: %v", err)
		}

		log.Infof("使用文件存储会话数据: %s", sessionDir)

	case "memory":
		storage = NewMemorySessionStorage()
		log.Infof("使用内存存储会话数据")

	default:
		return nil, fmt.Errorf("不支持的存储类型: %s", storageType)
	}

	return NewSessionManagerWithStorage(storage, log), nil
}

// GetSupportedStorageTypes 获取支持的存储类型
func (f *SessionManagerFactory) GetSupportedStorageTypes() []string {
	return []string{"memory", "file"}
}

// GetStorageInfo 获取存储信息
func (f *SessionManagerFactory) GetStorageInfo(storageType string) map[string]interface{} {
	switch storageType {
	case "file":
		return map[string]interface{}{
			"name":        "文件存储",
			"description": "基于JSON文件的持久化存储",
			"persistent":  true,
			"size":        "几乎无额外开销",
			"features":    []string{"持久化", "简单", "可读性", "跨平台"},
		}
	case "memory":
		return map[string]interface{}{
			"name":        "内存存储",
			"description": "快速内存键值存储",
			"persistent":  false,
			"size":        "几乎无额外开销",
			"features":    []string{"高性能", "简单", "重启丢失"},
		}
	default:
		return map[string]interface{}{
			"name":        "未知",
			"description": "不支持的存储类型",
			"persistent":  false,
			"size":        "未知",
			"features":    []string{},
		}
	}
}
