package web

import (
	"fmt"
	"strings"
)

// UserConflictManager 用户冲突管理器
type UserConflictManager struct {
	adminUsername string
	log           UserLogger
}

// NewUserConflictManager 创建用户冲突管理器
func NewUserConflictManager(adminUsername string, log UserLogger) *UserConflictManager {
	return &UserConflictManager{
		adminUsername: strings.ToLower(adminUsername),
		log:           log,
	}
}

// ValidateUsername 验证用户名是否与超管冲突
func (ucm *UserConflictManager) ValidateUsername(username string) error {
	if strings.ToLower(username) == ucm.adminUsername {
		return fmt.Errorf("用户名不能与超管用户名相同: %s", username)
	}
	
	// 检查其他保留用户名
	reservedNames := []string{
		"root", "administrator", "superuser", "superadmin",
		"system", "sslcat", "sslcat-admin", "sslcat-admin",
	}
	
	lowerUsername := strings.ToLower(username)
	for _, reserved := range reservedNames {
		if lowerUsername == reserved {
			return fmt.Errorf("用户名不能使用保留名称: %s", username)
		}
	}
	
	return nil
}

// IsAdminUsername 检查用户名是否为超管用户名
func (ucm *UserConflictManager) IsAdminUsername(username string) bool {
	return strings.ToLower(username) == ucm.adminUsername
}

// GetSafeUsername 获取安全的用户名建议
func (ucm *UserConflictManager) GetSafeUsername(suggestedUsername string) string {
	baseUsername := suggestedUsername
	suffix := 1
	
	for {
		safeUsername := fmt.Sprintf("%s%d", baseUsername, suffix)
		if !ucm.IsAdminUsername(safeUsername) {
			return safeUsername
		}
		suffix++
		
		// 防止无限循环
		if suffix > 999 {
			break
		}
	}
	
	return fmt.Sprintf("%s_user", baseUsername)
}
