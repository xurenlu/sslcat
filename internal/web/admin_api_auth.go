package web

import (
	"net/http"
	"strings"
)

// publicAdminAPIPaths 管理面板前缀下无需登录即可访问的 API 路径。
// 这些端点是登录流程本身或登录页渲染所必需的，其余 /api/ 路径一律要求凭据。
var publicAdminAPIPaths = map[string]bool{
	"/api/auth/login":            true,
	"/api/auth/totp-login":       true,
	"/api/auth/logout":           true,
	"/api/settings/public":       true,
	"/api/captcha":               true,
	"/api/captcha/image":         true,
	"/api/webauthn/login/begin":  true,
	"/api/webauthn/login/finish": true,
	// 集群对等端点自校验 X-Cluster-Key，不走会话鉴权
	"/api/cluster/export-certs": true,
}

// adminAPIAuthGuard 对管理面板前缀下的 API 做统一鉴权。
//
// 面板页面与静态资源刻意不在此层拦截：SPA 自行处理登录态跳转，若在这里挡住
// 登录页的脚本与样式，管理员将无法进入登录页。返回 false 表示响应已写出。
func (s *Server) adminAPIAuthGuard(w http.ResponseWriter, r *http.Request) bool {
	adminPrefix := s.config.AdminPrefix
	if !strings.HasPrefix(r.URL.Path, adminPrefix+"/api/") {
		return true
	}

	if publicAdminAPIPaths[strings.TrimPrefix(r.URL.Path, adminPrefix)] {
		return true
	}

	if s.hasAdminCredentials(r) {
		return true
	}

	s.log.Warnf("拒绝未鉴权的管理 API 请求: %s %s from %s", r.Method, r.URL.Path, s.getClientIP(r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	return false
}

// hasAdminCredentials 校验会话或 API token，非查询请求要求 write 角色。
func (s *Server) hasAdminCredentials(r *http.Request) bool {
	if s.sessionManager != nil {
		if _, exists := s.sessionManager.GetSessionFromRequest(r); exists {
			return true
		}
	}

	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return false
	}
	tok := strings.TrimSpace(authz[len("Bearer "):])
	if tok == "" || s.tokenStore == nil {
		return false
	}
	role, ok := s.tokenStore.Validate(tok)
	if !ok {
		return false
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	return role == "write"
}
