package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// handleUsers 用户管理页面
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	// 获取用户列表
	users, err := s.userManager.GetAllUsers()
	if err != nil {
		s.log.Errorf("获取用户列表失败: %v", err)
		http.Error(w, "获取用户列表失败", http.StatusInternalServerError)
		return
	}

	// 获取会话统计
	sessionStats := s.sessionManager.GetSessionStats()

	data := map[string]interface{}{
		"AdminPrefix":  s.config.AdminPrefix,
		"Users":        users,
		"SessionStats": sessionStats,
		"CurrentUser":  currentUser,
		"UserRoles": map[string]string{
			RoleSuperAdmin: "超级管理员",
			RoleAdmin:      "管理员",
			RoleOperator:   "操作员",
			RoleViewer:     "只读用户",
		},
	}

	// 检查模板是否存在，如果不存在则回退到前端 SPA
	if !s.templateRenderer.TemplateExists("users.html") {
		s.handleSPA(w, r)
		return
	}

	s.templateRenderer.DetectLanguageAndRender(w, r, "users.html", data)
}

// handleUserAdd 添加用户
func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != RoleSuperAdmin {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	if r.Method == "GET" {
		data := map[string]interface{}{
			"AdminPrefix": s.config.AdminPrefix,
			"UserRoles": map[string]string{
				RoleSuperAdmin: "超级管理员",
				RoleAdmin:      "管理员",
				RoleOperator:   "操作员",
				RoleViewer:     "只读用户",
			},
		}
		s.templateRenderer.DetectLanguageAndRender(w, r, "user_add.html", data)
		return
	}

	if r.Method == "POST" {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		role := strings.TrimSpace(r.FormValue("role"))
		email := strings.TrimSpace(r.FormValue("email"))

		// 验证输入
		if username == "" || password == "" || role == "" {
			s.renderUserAddError(w, r, "用户名、密码和角色不能为空")
			return
		}

		// 创建用户
		err := s.userManager.CreateUser(username, password, role, email, currentUser.Username)
		if err != nil {
			s.log.Errorf("创建用户失败: %v", err)
			s.renderUserAddError(w, r, fmt.Sprintf("创建用户失败: %v", err))
			return
		}

		// 记录操作日志
		s.userManager.LogUserAction(
			currentUser.Username,
			"user_create",
			"user",
			fmt.Sprintf("创建用户: %s (角色: %s)", username, role),
			s.getClientIP(r),
			r.Header.Get("User-Agent"),
		)

		// 重定向到用户列表
		http.Redirect(w, r, s.config.AdminPrefix+"/users", http.StatusFound)
	}
}

// handleUserEdit 编辑用户
func (s *Server) handleUserEdit(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != RoleSuperAdmin {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "用户名不能为空", http.StatusBadRequest)
		return
	}

	// 获取用户信息
	user, err := s.userManager.GetUserByUsername(username)
	if err != nil {
		s.log.Errorf("获取用户信息失败: %v", err)
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}

	if r.Method == "GET" {
		data := map[string]interface{}{
			"AdminPrefix": s.config.AdminPrefix,
			"User":        user,
			"UserRoles": map[string]string{
				RoleSuperAdmin: "超级管理员",
				RoleAdmin:      "管理员",
				RoleOperator:   "操作员",
				RoleViewer:     "只读用户",
			},
		}
		s.templateRenderer.DetectLanguageAndRender(w, r, "user_edit.html", data)
		return
	}

	if r.Method == "POST" {
		newPassword := r.FormValue("password")
		newRole := strings.TrimSpace(r.FormValue("role"))
		newEmail := strings.TrimSpace(r.FormValue("email"))
		isActive := r.FormValue("is_active") == "on"

		// 更新用户
		err := s.userManager.UpdateUser(username, newPassword, newRole, newEmail, isActive)
		if err != nil {
			s.log.Errorf("更新用户失败: %v", err)
			s.renderUserEditError(w, r, user, fmt.Sprintf("更新用户失败: %v", err))
			return
		}

		// 记录操作日志
		s.userManager.LogUserAction(
			currentUser.Username,
			"user_update",
			"user",
			fmt.Sprintf("更新用户: %s (角色: %s, 状态: %v)", username, newRole, isActive),
			s.getClientIP(r),
			r.Header.Get("User-Agent"),
		)

		// 如果用户被禁用，删除其所有会话
		if !isActive {
			s.sessionManager.DeleteUserSessions(username)
		}

		// 重定向到用户列表
		http.Redirect(w, r, s.config.AdminPrefix+"/users", http.StatusFound)
	}
}

// handleUserDelete 删除用户
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || currentUser.Role != RoleSuperAdmin {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "用户名不能为空", http.StatusBadRequest)
		return
	}

	// 不能删除自己
	if username == currentUser.Username {
		http.Error(w, "不能删除自己的账户", http.StatusBadRequest)
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

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "用户删除成功",
	})
}

// handleUserLogs 用户操作日志
func (s *Server) handleUserLogs(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 检查权限
	currentUser := s.getCurrentUser(r)
	if currentUser == nil || (currentUser.Role != RoleSuperAdmin && currentUser.Role != RoleAdmin) {
		http.Error(w, "权限不足", http.StatusForbidden)
		return
	}

	// 获取查询参数
	username := r.URL.Query().Get("username")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	var logs []map[string]interface{}
	var err error

	if username != "" {
		// 获取特定用户的操作日志
		logs, err = s.userManager.GetUserAuditLogs(username, limit)
	} else {
		// 获取所有操作日志
		logs, err = s.userManager.GetAllAuditLogs(limit)
	}

	if err != nil {
		s.log.Errorf("获取操作日志失败: %v", err)
		http.Error(w, "获取操作日志失败", http.StatusInternalServerError)
		return
	}

	// 获取用户列表（用于筛选）
	users, _ := s.userManager.GetAllUsers()

	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Logs":        logs,
		"Users":       users,
		"Username":    username,
		"Limit":       limit,
		"CurrentUser": currentUser,
	}

	s.templateRenderer.DetectLanguageAndRender(w, r, "user_logs.html", data)
}

// renderUserAddError 渲染用户添加错误页面
func (s *Server) renderUserAddError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"Error":       errorMsg,
		"UserRoles": map[string]string{
			RoleSuperAdmin: "超级管理员",
			RoleAdmin:      "管理员",
			RoleOperator:   "操作员",
			RoleViewer:     "只读用户",
		},
	}
	s.templateRenderer.DetectLanguageAndRender(w, r, "user_add.html", data)
}

// renderUserEditError 渲染用户编辑错误页面
func (s *Server) renderUserEditError(w http.ResponseWriter, r *http.Request, user *User, errorMsg string) {
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
		"User":        user,
		"Error":       errorMsg,
		"UserRoles": map[string]string{
			RoleSuperAdmin: "超级管理员",
			RoleAdmin:      "管理员",
			RoleOperator:   "操作员",
			RoleViewer:     "只读用户",
		},
	}
	s.templateRenderer.DetectLanguageAndRender(w, r, "user_edit.html", data)
}
