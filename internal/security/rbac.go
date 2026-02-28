package security

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Permission 权限定义
type Permission struct {
	ID          string   `json:"id"`          // 权限唯一标识
	Name        string   `json:"name"`        // 权限名称
	Description string   `json:"description"` // 权限描述
	Resource    string   `json:"resource"`    // 资源类型: proxy, ssl, waf, user, system, etc.
	Action      string   `json:"action"`      // 操作类型: read, write, delete, execute, admin
	Conditions  []string `json:"conditions"`  // 条件限制，如 "domain=*", "role<admin"
}

// Role 角色定义
type Role struct {
	ID          string       `json:"id"`          // 角色唯一标识
	Name        string       `json:"name"`        // 角色名称
	Description string       `json:"description"` // 角色描述
	Permissions []string     `json:"permissions"` // 权限列表
	Inherits    []string     `json:"inherits"`    // 继承的角色列表
	Priority    int          `json:"priority"`    // 优先级（数字越大优先级越高）
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Policy 访问控制策略
type Policy struct {
	ID          string            `json:"id"`          // 策略唯一标识
	Name        string            `json:"name"`        // 策略名称
	Description string            `json:"description"` // 策略描述
	Effect      string            `json:"effect"`      // 效果: allow, deny
	Subjects    []string          `json:"subjects"`    // 主体：用户、角色、组
	Resources   []string          `json:"resources"`   // 资源：具体资源或模式
	Actions     []string          `json:"actions"`     // 操作：具体操作或*
	Conditions  map[string]string `json:"conditions"`  // 条件：ip, time, environment
	Priority    int               `json:"priority"`    // 优先级（数字越大越优先）
	Enabled     bool              `json:"enabled"`     // 是否启用
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// AccessRequest 访问请求
type AccessRequest struct {
	Subject     string            `json:"subject"`     // 主体标识（用户 ID 或服务账号）
	Resource    string            `json:"resource"`    // 资源标识
	Action      string            `json:"action"`      // 操作标识
	Context     map[string]string `json:"context"`     // 上下文信息（IP、时间等）
	Environment string            `json:"environment"` // 环境：production, staging, development
}

// AccessDecision 访问决策
type AccessDecision struct {
	Allowed   bool   `json:"allowed"`
	Denied    bool   `json:"denied"`
	Reason    string `json:"reason"`
	PolicyID  string `json:"policy_id,omitempty"`
	MatchedBy string `json:"matched_by,omitempty"` // role, policy, permission
}

// RBACManager 基于角色的访问控制管理器
type RBACManager struct {
	roles         map[string]*Role
	permissions   map[string]*Permission
	policies      map[string]*Policy
	userRoles     map[string][]string    // user ID -> role IDs
	userGroups    map[string][]string    // user ID -> group IDs
	groupRoles    map[string][]string    // group ID -> role IDs
	serviceRoles  map[string][]string    // service account -> role IDs
	mutex         sync.RWMutex
	log           *logrus.Entry
	// 审计日志
	auditLog      []AccessAuditEntry
	auditMutex    sync.RWMutex
	maxAuditLogs  int
	// 缓存
	decisionCache map[string]*AccessDecision
	cacheMutex    sync.RWMutex
	cacheTTL      time.Duration
}

// AccessAuditEntry 访问审计日志
type AccessAuditEntry struct {
	Timestamp   time.Time         `json:"timestamp"`
	Request     AccessRequest     `json:"request"`
	Decision    AccessDecision    `json:"decision"`
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent"`
	SessionID   string            `json:"session_id"`
	RequestID   string            `json:"request_id"`
}

// NewRBACManager 创建 RBAC 管理器
func NewRBACManager() *RBACManager {
	log := logrus.WithFields(logrus.Fields{
		"component": "rbac_manager",
	})

	mgr := &RBACManager{
		roles:         make(map[string]*Role),
		permissions:   make(map[string]*Permission),
		policies:      make(map[string]*Policy),
		userRoles:     make(map[string][]string),
		userGroups:    make(map[string][]string),
		groupRoles:    make(map[string][]string),
		serviceRoles:  make(map[string][]string),
		log:           log,
		auditLog:      make([]AccessAuditEntry, 0, 1000),
		maxAuditLogs:  10000,
		decisionCache: make(map[string]*AccessDecision),
		cacheTTL:      5 * time.Minute,
	}

	// 初始化默认权限和角色
	mgr.initializeDefaults()

	return mgr
}

// initializeDefaults 初始化默认权限和角色
func (m *RBACManager) initializeDefaults() {
	// 定义默认权限
	defaultPermissions := []*Permission{
		{ID: "proxy.read", Name: "查看代理配置", Resource: "proxy", Action: "read"},
		{ID: "proxy.write", Name: "修改代理配置", Resource: "proxy", Action: "write"},
		{ID: "proxy.delete", Name: "删除代理配置", Resource: "proxy", Action: "delete"},
		{ID: "ssl.read", Name: "查看SSL证书", Resource: "ssl", Action: "read"},
		{ID: "ssl.write", Name: "管理SSL证书", Resource: "ssl", Action: "write"},
		{ID: "waf.read", Name: "查看WAF规则", Resource: "waf", Action: "read"},
		{ID: "waf.write", Name: "修改WAF规则", Resource: "waf", Action: "write"},
		{ID: "user.read", Name: "查看用户", Resource: "user", Action: "read"},
		{ID: "user.write", Name: "管理用户", Resource: "user", Action: "write"},
		{ID: "user.delete", Name: "删除用户", Resource: "user", Action: "delete"},
		{ID: "system.read", Name: "查看系统信息", Resource: "system", Action: "read"},
		{ID: "system.admin", Name: "系统管理", Resource: "system", Action: "admin"},
		{ID: "security.read", Name: "查看安全日志", Resource: "security", Action: "read"},
		{ID: "security.write", Name: "管理安全设置", Resource: "security", Action: "write"},
		{ID: "cluster.read", Name: "查看集群状态", Resource: "cluster", Action: "read"},
		{ID: "cluster.write", Name: "管理集群", Resource: "cluster", Action: "write"},
	}

	for _, perm := range defaultPermissions {
		m.permissions[perm.ID] = perm
	}

	// 定义默认角色
	now := time.Now()

	// 超级管理员角色
	superAdminRole := &Role{
		ID:          "super_admin",
		Name:        "超级管理员",
		Description: "拥有所有权限",
		Permissions: []string{"*"}, // 所有权限
		Priority:    1000,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// 管理员角色
	adminRole := &Role{
		ID:          "admin",
		Name:        "管理员",
		Description: "系统管理员",
		Permissions: []string{
			"proxy.read", "proxy.write",
			"ssl.read", "ssl.write",
			"waf.read", "waf.write",
			"user.read", "user.write",
			"system.read", "system.admin",
			"security.read", "security.write",
			"cluster.read", "cluster.write",
		},
		Priority:  100,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 操作员角色
	operatorRole := &Role{
		ID:          "operator",
		Name:        "操作员",
		Description: "日常运维操作",
		Permissions: []string{
			"proxy.read", "proxy.write",
			"ssl.read", "ssl.write",
			"waf.read",
			"system.read",
			"security.read",
			"cluster.read",
		},
		Priority:  50,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 只读用户角色
	viewerRole := &Role{
		ID:          "viewer",
		Name:        "只读用户",
		Description: "只读访问权限",
		Permissions: []string{
			"proxy.read",
			"ssl.read",
			"waf.read",
			"user.read",
			"system.read",
			"security.read",
			"cluster.read",
		},
		Priority:  10,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 安全管理员角色
	securityAdminRole := &Role{
		ID:          "security_admin",
		Name:        "安全管理员",
		Description: "安全策略管理",
		Permissions: []string{
			"proxy.read",
			"ssl.read", "ssl.write",
			"waf.read", "waf.write",
			"security.read", "security.write",
			"system.read",
			"user.read",
		},
		Priority:  200,
		CreatedAt: now,
		UpdatedAt: now,
	}

	m.roles["super_admin"] = superAdminRole
	m.roles["admin"] = adminRole
	m.roles["operator"] = operatorRole
	m.roles["viewer"] = viewerRole
	m.roles["security_admin"] = securityAdminRole

	m.log.Info("Default RBAC roles and permissions initialized")
}

// CheckAccess 检查访问权限
func (m *RBACManager) CheckAccess(request AccessRequest) *AccessDecision {
	// 检查缓存
	cacheKey := m.buildCacheKey(request)
	if cached := m.getFromCache(cacheKey); cached != nil {
		return cached
	}

	decision := &AccessDecision{
		Allowed: false,
		Denied:  true,
		Reason:  "default deny",
	}

	// 1. 检查策略优先（显式策略优先于角色）
	m.mutex.RLock()
	for _, policy := range m.policies {
		if !policy.Enabled {
			continue
		}
		if m.matchesPolicy(policy, request) {
			decision.Allowed = (policy.Effect == "allow")
			decision.Denied = !decision.Allowed
			decision.Reason = fmt.Sprintf("matched policy: %s", policy.Name)
			decision.PolicyID = policy.ID
			decision.MatchedBy = "policy"
			break
		}
	}
	m.mutex.RUnlock()

	// 如果策略没有匹配，检查角色权限
	if decision.MatchedBy == "" {
		userRoles := m.getUserRoles(request.Subject)

		// 按优先级排序角色
		sortedRoles := m.sortRolesByPriority(userRoles)

		for _, roleID := range sortedRoles {
			m.mutex.RLock()
			role := m.roles[roleID]
			m.mutex.RUnlock()

			if role == nil {
				continue
			}

			if m.hasPermission(role, request.Resource, request.Action) {
				decision.Allowed = true
				decision.Denied = false
				decision.Reason = fmt.Sprintf("matched role: %s", role.Name)
				decision.MatchedBy = "role"
				break
			}
		}
	}

	// 记录审计日志
	m.logAccess(request, *decision)

	// 缓存决策
	m.addToCache(cacheKey, decision)

	return decision
}

// matchesPolicy 检查策略是否匹配请求
func (m *RBACManager) matchesPolicy(policy *Policy, request AccessRequest) bool {
	// 检查主体
	subjectMatched := false
	for _, subject := range policy.Subjects {
		if subject == "*" || subject == request.Subject {
			subjectMatched = true
			break
		}
		// 检查角色匹配
		if strings.HasPrefix(subject, "role:") {
			roleName := strings.TrimPrefix(subject, "role:")
			if m.userHasRole(request.Subject, roleName) {
				subjectMatched = true
				break
			}
		}
	}
	if !subjectMatched {
		return false
	}

	// 检查资源
	resourceMatched := false
	for _, resource := range policy.Resources {
		if resource == "*" || m.matchResourcePattern(resource, request.Resource) {
			resourceMatched = true
			break
		}
	}
	if !resourceMatched {
		return false
	}

	// 检查操作
	actionMatched := false
	for _, action := range policy.Actions {
		if action == "*" || action == request.Action {
			actionMatched = true
			break
		}
	}
	if !actionMatched {
		return false
	}

	// 检查条件
	for key, value := range policy.Conditions {
		switch key {
		case "ip":
			if request.Context["ip"] != value {
				return false
			}
		case "time":
			if !m.matchTimeCondition(value, time.Now()) {
				return false
			}
		case "environment":
			if request.Environment != value {
				return false
			}
		}
	}

	return true
}

// matchResourcePattern 匹配资源模式
func (m *RBACManager) matchResourcePattern(pattern, resource string) bool {
	// 支持通配符
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(resource, prefix)
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(resource, suffix)
	}
	return pattern == resource
}

// hasPermission 检查角色是否有指定权限
func (m *RBACManager) hasPermission(role *Role, resource, action string) bool {
	for _, permID := range role.Permissions {
		if permID == "*" {
			return true
		}

		m.mutex.RLock()
		perm := m.permissions[permID]
		m.mutex.RUnlock()

		if perm != nil && perm.Resource == resource && (perm.Action == action || perm.Action == "*") {
			return true
		}
	}

	// 检查继承的角色
	for _, inheritedRoleID := range role.Inherits {
		m.mutex.RLock()
		inheritedRole := m.roles[inheritedRoleID]
		m.mutex.RUnlock()

		if inheritedRole != nil && m.hasPermission(inheritedRole, resource, action) {
			return true
		}
	}

	return false
}

// getUserRoles 获取用户的所有角色
func (m *RBACManager) getUserRoles(userID string) []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	roles := make([]string, 0)

	// 直接角色
	if userRoles, ok := m.userRoles[userID]; ok {
		roles = append(roles, userRoles...)
	}

	// 通过组继承的角色
	if groups, ok := m.userGroups[userID]; ok {
		for _, groupID := range groups {
			if groupRoles, ok := m.groupRoles[groupID]; ok {
				roles = append(roles, groupRoles...)
			}
		}
	}

	return roles
}

// sortRolesByPriority 按优先级排序角色
func (m *RBACManager) sortRolesByPriority(roleIDs []string) []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 简单实现：直接返回
	// 实际应该按 priority 排序
	return roleIDs
}

// userHasRole 检查用户是否有指定角色
func (m *RBACManager) userHasRole(userID, roleName string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	roles := m.getUserRoles(userID)
	for _, roleID := range roles {
		if role := m.roles[roleID]; role != nil && role.Name == roleName {
			return true
		}
	}
	return false
}

// AssignRole 为用户分配角色
func (m *RBACManager) AssignRole(userID, roleID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 检查角色是否存在
	if _, exists := m.roles[roleID]; !exists {
		return fmt.Errorf("role not found: %s", roleID)
	}

	// 添加角色
	if m.userRoles[userID] == nil {
		m.userRoles[userID] = make([]string, 0)
	}

	// 检查是否已存在
	for _, r := range m.userRoles[userID] {
		if r == roleID {
			return fmt.Errorf("user already has role: %s", roleID)
		}
	}

	m.userRoles[userID] = append(m.userRoles[userID], roleID)
	m.log.Infof("Assigned role %s to user %s", roleID, userID)

	// 清除缓存
	m.clearCache()

	return nil
}

// RevokeRole 撤销用户角色
func (m *RBACManager) RevokeRole(userID, roleID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.userRoles[userID] == nil {
		return fmt.Errorf("user has no roles")
	}

	// 移除角色
	newRoles := make([]string, 0, len(m.userRoles[userID]))
	for _, r := range m.userRoles[userID] {
		if r != roleID {
			newRoles = append(newRoles, r)
		}
	}

	if len(newRoles) == len(m.userRoles[userID]) {
		return fmt.Errorf("user does not have role: %s", roleID)
	}

	m.userRoles[userID] = newRoles
	m.log.Infof("Revoked role %s from user %s", roleID, userID)

	// 清除缓存
	m.clearCache()

	return nil
}

// CreateRole 创建自定义角色
func (m *RBACManager) CreateRole(role *Role) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.roles[role.ID]; exists {
		return fmt.Errorf("role already exists: %s", role.ID)
	}

	role.CreatedAt = time.Now()
	role.UpdatedAt = time.Now()
	m.roles[role.ID] = role

	m.log.Infof("Created role: %s", role.ID)
	return nil
}

// CreatePolicy 创建访问控制策略
func (m *RBACManager) CreatePolicy(policy *Policy) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.policies[policy.ID]; exists {
		return fmt.Errorf("policy already exists: %s", policy.ID)
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	m.policies[policy.ID] = policy

	m.log.Infof("Created policy: %s", policy.ID)
	m.clearCache()
	return nil
}

// UpdatePolicy 更新访问控制策略
func (m *RBACManager) UpdatePolicy(policy *Policy) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.policies[policy.ID]; !exists {
		return fmt.Errorf("policy not found: %s", policy.ID)
	}

	policy.UpdatedAt = time.Now()
	m.policies[policy.ID] = policy

	m.log.Infof("Updated policy: %s", policy.ID)
	m.clearCache()
	return nil
}

// DeletePolicy 删除访问控制策略
func (m *RBACManager) DeletePolicy(policyID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.policies[policyID]; !exists {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	delete(m.policies, policyID)

	m.log.Infof("Deleted policy: %s", policyID)
	m.clearCache()
	return nil
}

// ListPolicies 列出所有策略
func (m *RBACManager) ListPolicies() []*Policy {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	policies := make([]*Policy, 0, len(m.policies))
	for _, policy := range m.policies {
		policies = append(policies, policy)
	}
	return policies
}

// ListRoles 列出所有角色
func (m *RBACManager) ListRoles() []*Role {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	roles := make([]*Role, 0, len(m.roles))
	for _, role := range m.roles {
		roles = append(roles, role)
	}
	return roles
}

// logAccess 记录访问日志
func (m *RBACManager) logAccess(request AccessRequest, decision AccessDecision) {
	m.auditMutex.Lock()
	defer m.auditMutex.Unlock()

	entry := AccessAuditEntry{
		Timestamp: time.Now(),
		Request:   request,
		Decision:  decision,
	}

	m.auditLog = append(m.auditLog, entry)

	// 限制日志大小
	if len(m.auditLog) > m.maxAuditLogs {
		// 保留最近的日志
		m.auditLog = m.auditLog[len(m.auditLog)-m.maxAuditLogs:]
	}
}

// GetAuditLog 获取审计日志
func (m *RBACManager) GetAuditLog(limit int) []AccessAuditEntry {
	m.auditMutex.RLock()
	defer m.auditMutex.RUnlock()

	if limit <= 0 || limit > len(m.auditLog) {
		limit = len(m.auditLog)
	}

	// 返回最近的日志
	start := len(m.auditLog) - limit
	if start < 0 {
		start = 0
	}

	result := make([]AccessAuditEntry, limit)
	copy(result, m.auditLog[start:])
	return result
}

// buildCacheKey 构建缓存键
func (m *RBACManager) buildCacheKey(request AccessRequest) string {
	return fmt.Sprintf("%s:%s:%s", request.Subject, request.Resource, request.Action)
}

// getFromCache 从缓存获取
func (m *RBACManager) getFromCache(key string) *AccessDecision {
	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()
	return m.decisionCache[key]
}

// addToCache 添加到缓存
func (m *RBACManager) addToCache(key string, decision *AccessDecision) {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	m.decisionCache[key] = decision

	// 定期清理过期缓存
	go func() {
		time.Sleep(m.cacheTTL)
		m.cacheMutex.Lock()
		delete(m.decisionCache, key)
		m.cacheMutex.Unlock()
	}()
}

// clearCache 清除缓存
func (m *RBACManager) clearCache() {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	m.decisionCache = make(map[string]*AccessDecision)
}

// matchTimeCondition 匹配时间条件
func (m *RBACManager) matchTimeCondition(condition string, t time.Time) bool {
	// 支持简单的时间条件
	// 例如: "office_hours" (9-18), "24/7", "weekdays"
	switch condition {
	case "24/7":
		return true
	case "office_hours":
		hour := t.Hour()
		return hour >= 9 && hour < 18
	case "weekdays":
		day := t.Weekday()
		return day >= time.Monday && day <= time.Friday
	default:
		return true
	}
}

// ExportToJSON 导出 RBAC 配置到 JSON
func (m *RBACManager) ExportToJSON() ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	data := map[string]interface{}{
		"roles":       m.roles,
		"permissions": m.permissions,
		"policies":    m.policies,
		"user_roles":  m.userRoles,
		"user_groups": m.userGroups,
	}

	return json.MarshalIndent(data, "", "  ")
}

// ImportFromJSON 从 JSON 导入 RBAC 配置
func (m *RBACManager) ImportFromJSON(data []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// TODO: 实现导入逻辑
	m.log.Info("RBAC configuration imported")
	m.clearCache()
	return nil
}
