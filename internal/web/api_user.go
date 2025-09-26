package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// handleAPIUsers 用户管理API
func (s *Server) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	switch r.Method {
	case "GET":
		s.handleAPIUsersList(w, r)
	case "POST":
		s.handleAPIUsersCreate(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIUsersList 获取用户列表
func (s *Server) handleAPIUsersList(w http.ResponseWriter, r *http.Request) {
	users, err := s.userManager.GetAllUsers()
	if err != nil {
		s.log.Errorf("获取用户列表失败: %v", err)
		http.Error(w, "获取用户列表失败", http.StatusInternalServerError)
		return
	}

	// 获取会话统计
	sessionStats := s.sessionManager.GetSessionStats()

	response := map[string]interface{}{
		"users":        users,
		"sessionStats": sessionStats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAPIUsersCreate 创建用户
func (s *Server) handleAPIUsersCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 验证输入
	if req.Username == "" || req.Password == "" || req.Role == "" {
		http.Error(w, "用户名、密码和角色不能为空", http.StatusBadRequest)
		return
	}

	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		http.Error(w, "未找到当前用户", http.StatusInternalServerError)
		return
	}

	// 创建用户
	err := s.userManager.CreateUser(req.Username, req.Password, req.Role, req.Email, currentUser.Username)
	if err != nil {
		s.log.Errorf("创建用户失败: %v", err)
		http.Error(w, fmt.Sprintf("创建用户失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 记录操作日志
	s.userManager.LogUserAction(
		currentUser.Username,
		"user_create",
		"user",
		fmt.Sprintf("创建用户: %s (角色: %s)", req.Username, req.Role),
		s.getClientIP(r),
		r.Header.Get("User-Agent"),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "用户创建成功"})
}

// handleAPIUser 单个用户操作
func (s *Server) handleAPIUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 从URL路径中提取用户名
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, s.config.AdminPrefix+"/api/users/"), "/")
	if len(pathParts) == 0 || pathParts[0] == "" {
		http.Error(w, "用户名不能为空", http.StatusBadRequest)
		return
	}
	username := pathParts[0]

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	switch r.Method {
	case "PUT":
		s.handleAPIUserUpdate(w, r, username)
	case "DELETE":
		s.handleAPIUserDelete(w, r, username)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPIUserUpdate 更新用户
func (s *Server) handleAPIUserUpdate(w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		Password *string `json:"password,omitempty"`
		Role     *string `json:"role,omitempty"`
		Email    *string `json:"email,omitempty"`
		IsActive *bool   `json:"is_active,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		http.Error(w, "未找到当前用户", http.StatusInternalServerError)
		return
	}

	// 准备更新参数
	newPassword := ""
	if req.Password != nil {
		newPassword = *req.Password
	}

	newRole := ""
	if req.Role != nil {
		newRole = *req.Role
	}

	newEmail := ""
	if req.Email != nil {
		newEmail = *req.Email
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	// 更新用户
	err := s.userManager.UpdateUser(username, newPassword, newRole, newEmail, isActive)
	if err != nil {
		s.log.Errorf("更新用户失败: %v", err)
		http.Error(w, fmt.Sprintf("更新用户失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 记录操作日志
	s.userManager.LogUserAction(
		currentUser.Username,
		"user_update",
		"user",
		fmt.Sprintf("更新用户: %s", username),
		s.getClientIP(r),
		r.Header.Get("User-Agent"),
	)

	// 如果用户被禁用，删除其所有会话
	if !isActive {
		s.sessionManager.DeleteUserSessions(username)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "用户更新成功"})
}

// handleAPIUserDelete 删除用户
func (s *Server) handleAPIUserDelete(w http.ResponseWriter, r *http.Request, username string) {
	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		http.Error(w, "未找到当前用户", http.StatusInternalServerError)
		return
	}

	// 删除用户
	err := s.userManager.DeleteUser(username)
	if err != nil {
		s.log.Errorf("删除用户失败: %v", err)
		http.Error(w, fmt.Sprintf("删除用户失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 删除用户的所有会话
	s.sessionManager.DeleteUserSessions(username)

	// 记录操作日志
	s.userManager.LogUserAction(
		currentUser.Username,
		"user_delete",
		"user",
		fmt.Sprintf("删除用户: %s", username),
		s.getClientIP(r),
		r.Header.Get("User-Agent"),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "用户删除成功"})
}

// handleAPIChangePassword 修改密码API
func (s *Server) handleAPIChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		http.Error(w, "当前密码和新密码不能为空", http.StatusBadRequest)
		return
	}

	currentUser := s.getCurrentUser(r)
	if currentUser == nil {
		http.Error(w, "未找到当前用户", http.StatusInternalServerError)
		return
	}

	// 验证当前密码
	var isValidPassword bool
	var err error

	// 1. 首先尝试普通用户认证
	_, err = s.userManager.AuthenticateUser(currentUser.Username, req.CurrentPassword)
	if err == nil {
		isValidPassword = true
	} else {
		// 2. 如果是超级管理员，尝试文件密码验证
		if currentUser.Username == s.config.Admin.Username {
			isValidPassword = s.verifyAdminPassword(req.CurrentPassword)
		}
	}

	if !isValidPassword {
		http.Error(w, "当前密码不正确", http.StatusBadRequest)
		return
	}

	// 根据用户类型更新密码
	if currentUser.Username == s.config.Admin.Username {
		// 超级管理员：更新文件中的密码
		if err := s.updateAdminPassword(req.NewPassword); err != nil {
			s.log.Errorf("更新管理员密码失败: %v", err)
			http.Error(w, "密码更新失败", http.StatusInternalServerError)
			return
		}
	} else {
		// 普通用户：更新数据库中的密码
		err := s.userManager.UpdateUser(currentUser.Username, req.NewPassword, "", "", true)
		if err != nil {
			s.log.Errorf("更新用户密码失败: %v", err)
			http.Error(w, "密码更新失败", http.StatusInternalServerError)
			return
		}
	}

	// 记录操作日志
	s.userManager.LogUserAction(
		currentUser.Username,
		"password_change",
		"user",
		"修改密码",
		s.getClientIP(r),
		r.Header.Get("User-Agent"),
	)

	// 删除当前用户的所有会话，强制重新登录
	s.sessionManager.DeleteUserSessions(currentUser.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "密码修改成功"})
}

// updateAdminPassword 更新管理员密码（写入文件）
func (s *Server) updateAdminPassword(newPassword string) error {
	// 生成bcrypt哈希
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码加密失败: %v", err)
	}

	// 写入密码文件
	if err := os.WriteFile(s.config.Admin.PasswordFile, append(hashedPassword, '\n'), 0600); err != nil {
		return fmt.Errorf("写入密码文件失败: %v", err)
	}

	// 更新内存中的配置（避免明文存储）
	s.config.Admin.Password = ""

	// 保存配置文件
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		return fmt.Errorf("保存配置文件失败: %v", err)
	}

	return nil
}
