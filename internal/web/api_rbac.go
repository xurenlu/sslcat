package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/xurenlu/sslcat/internal/security"
)

// atoi 辅助函数
func atoi(s string) (int, error) {
	return strconv.Atoi(s)
}

// RBACAccessRequest RBAC 访问检查请求
type RBACAccessRequest struct {
	Subject     string            `json:"subject"`
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Context     map[string]string `json:"context"`
	Environment string            `json:"environment"`
}

// RBACAccessResponse RBAC 访问检查响应
type RBACAccessResponse struct {
	Allowed   bool   `json:"allowed"`
	Denied    bool   `json:"denied"`
	Reason    string `json:"reason"`
	PolicyID  string `json:"policy_id,omitempty"`
	MatchedBy string `json:"matched_by,omitempty"`
}

// RoleAssignmentRequest 角色分配请求
type RoleAssignmentRequest struct {
	UserID string `json:"user_id"`
	RoleID string `json:"role_id"`
}

// PolicyRequest 策略请求
type PolicyRequest struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Effect      string            `json:"effect"`
	Subjects    []string          `json:"subjects"`
	Resources   []string          `json:"resources"`
	Actions     []string          `json:"actions"`
	Conditions  map[string]string `json:"conditions"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
}

// RoleRequest 角色请求
type RoleRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Inherits    []string `json:"inherits"`
	Priority    int      `json:"priority"`
}

// handleRBACCheckAccess 检查访问权限
func (s *Server) handleRBACCheckAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RBACAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	accessRequest := security.AccessRequest{
		Subject:     req.Subject,
		Resource:    req.Resource,
		Action:      req.Action,
		Context:     req.Context,
		Environment: req.Environment,
	}

	decision := s.rbacManager.CheckAccess(accessRequest)

	response := RBACAccessResponse{
		Allowed:   decision.Allowed,
		Denied:    decision.Denied,
		Reason:    decision.Reason,
		PolicyID:  decision.PolicyID,
		MatchedBy: decision.MatchedBy,
	}

	s.sendJSON(w, response)
}

// handleRBACListRoles 列出所有角色
func (s *Server) handleRBACListRoles(w http.ResponseWriter, r *http.Request) {
	roles := s.rbacManager.ListRoles()

	s.sendJSON(w, map[string]interface{}{
		"roles": roles,
	})
}

// handleRBACCreateRole 创建角色
func (s *Server) handleRBACCreateRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	role := &security.Role{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		Inherits:    req.Inherits,
		Priority:    req.Priority,
	}

	if err := s.rbacManager.CreateRole(role); err != nil {
		s.log.Errorf("Failed to create role: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Role created successfully",
		"role":    role,
	})
}

// handleRBACAssignRole 分配角色给用户
func (s *Server) handleRBACAssignRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RoleAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.rbacManager.AssignRole(req.UserID, req.RoleID); err != nil {
		s.log.Errorf("Failed to assign role: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Role assigned successfully",
	})
}

// handleRBACRevokeRole 撤销用户角色
func (s *Server) handleRBACRevokeRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RoleAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.rbacManager.RevokeRole(req.UserID, req.RoleID); err != nil {
		s.log.Errorf("Failed to revoke role: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Role revoked successfully",
	})
}

// handleRBACListPolicies 列出所有策略
func (s *Server) handleRBACListPolicies(w http.ResponseWriter, r *http.Request) {
	policies := s.rbacManager.ListPolicies()

	s.sendJSON(w, map[string]interface{}{
		"policies": policies,
	})
}

// handleRBACCreatePolicy 创建策略
func (s *Server) handleRBACCreatePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	policy := &security.Policy{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Effect:      req.Effect,
		Subjects:    req.Subjects,
		Resources:   req.Resources,
		Actions:     req.Actions,
		Conditions:  req.Conditions,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
	}

	if err := s.rbacManager.CreatePolicy(policy); err != nil {
		s.log.Errorf("Failed to create policy: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Policy created successfully",
		"policy":  policy,
	})
}

// handleRBACUpdatePolicy 更新策略
func (s *Server) handleRBACUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	policy := &security.Policy{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		Effect:      req.Effect,
		Subjects:    req.Subjects,
		Resources:   req.Resources,
		Actions:     req.Actions,
		Conditions:  req.Conditions,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
	}

	if err := s.rbacManager.UpdatePolicy(policy); err != nil {
		s.log.Errorf("Failed to update policy: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Policy updated successfully",
		"policy":  policy,
	})
}

// handleRBACDeletePolicy 删除策略
func (s *Server) handleRBACDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.rbacManager.DeletePolicy(req.PolicyID); err != nil {
		s.log.Errorf("Failed to delete policy: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Policy deleted successfully",
	})
}

// handleRBACAuditLog 获取审计日志
func (s *Server) handleRBACAuditLog(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit := 100

	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	// 添加上下文信息
	if subject := query.Get("subject"); subject != "" {
		// TODO: 过滤特定用户的审计日志
	}

	if resource := query.Get("resource"); resource != "" {
		// TODO: 过滤特定资源的审计日志
	}

	logs := s.rbacManager.GetAuditLog(limit)

	s.sendJSON(w, map[string]interface{}{
		"audit_log": logs,
		"count":     len(logs),
	})
}

// handleRBACGetUserRoles 获取用户角色
func (s *Server) handleRBACGetUserRoles(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	userID := query.Get("user_id")

	if userID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	// TODO: 从 RBAC manager 获取用户角色
	s.sendJSON(w, map[string]interface{}{
		"user_id": userID,
		"roles":   []string{},
	})
}

// handleRBACGetUserPermissions 获取用户权限
func (s *Server) handleRBACGetUserPermissions(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	userID := query.Get("user_id")

	if userID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	// TODO: 从 RBAC manager 获取用户权限
	s.sendJSON(w, map[string]interface{}{
		"user_id":    userID,
		"permissions": []string{},
	})
}

// handleRBACExport 导出 RBAC 配置
func (s *Server) handleRBACExport(w http.ResponseWriter, r *http.Request) {
	data, err := s.rbacManager.ExportToJSON()
	if err != nil {
		s.log.Errorf("Failed to export RBAC configuration: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=rbac-config.json")
	w.Write(data)
}

// handleRBACImport 导入 RBAC 配置
func (s *Server) handleRBACImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Config string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.rbacManager.ImportFromJSON([]byte(req.Config)); err != nil {
		s.log.Errorf("Failed to import RBAC configuration: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "RBAC configuration imported successfully",
	})
}
