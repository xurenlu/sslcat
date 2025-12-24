package web

import (
	"encoding/json"
	"fmt"
	"net/http"
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

	// 已迁移到 React SPA
	s.handleSPA(w, r)
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
		// 已迁移到 React SPA
		s.handleSPA(w, r)
		return
	}

	if r.Method == "POST" {
		// POST 请求应该使用 API
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "请使用 /api/users API 端点进行用户管理",
		})
		return
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

	if r.Method == "GET" {
		// 已迁移到 React SPA
		s.handleSPA(w, r)
		return
	}

	if r.Method == "POST" {
		// POST 请求应该使用 API
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "请使用 /api/users API 端点进行用户管理",
		})
		return
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

	// 已迁移到 React SPA
	s.handleSPA(w, r)
}

// renderUserAddError, renderUserEditError 已移除，使用 React SPA 处理错误显示
