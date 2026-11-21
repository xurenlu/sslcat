package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/security"
)

const authGuardTestAdminPrefix = "/sslcat-panel"

func newAuthGuardTestServer(t *testing.T) *Server {
	t.Helper()

	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)

	return &Server{
		config: &config.Config{
			AdminPrefix: authGuardTestAdminPrefix,
		},
		log:        logrus.NewEntry(log),
		tokenStore: security.NewTokenStore(filepath.Join(t.TempDir(), "tokens.json")),
	}
}

// 面板前缀下改状态或读敏感数据的 API，无凭据时必须被拒。
func TestAdminAPIAuthGuardRejectsUnauthenticated(t *testing.T) {
	protected := []string{
		authGuardTestAdminPrefix + "/api/bot-detection/config",
		authGuardTestAdminPrefix + "/api/bot-detection/whitelist",
		authGuardTestAdminPrefix + "/api/cache/clear",
		authGuardTestAdminPrefix + "/api/http2/enable",
		authGuardTestAdminPrefix + "/api/http2/disable",
		authGuardTestAdminPrefix + "/api/ml/train",
		authGuardTestAdminPrefix + "/api/sites",
		// 登录后的凭证管理不属于登录流程，不得公开
		authGuardTestAdminPrefix + "/api/webauthn/credentials",
		authGuardTestAdminPrefix + "/api/webauthn/credentials/delete",
	}

	s := newAuthGuardTestServer(t)
	for _, p := range protected {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, p, nil)

		if s.adminAPIAuthGuard(w, r) {
			t.Errorf("%s：无凭据请求不应放行", p)
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s：期望 401，实际 %d", p, w.Code)
		}
	}
}

// 登录流程本身必须保持可达，否则管理员无法进入面板。
func TestAdminAPIAuthGuardAllowsLoginFlowPaths(t *testing.T) {
	public := []string{
		authGuardTestAdminPrefix + "/api/auth/login",
		authGuardTestAdminPrefix + "/api/auth/totp-login",
		authGuardTestAdminPrefix + "/api/auth/logout",
		authGuardTestAdminPrefix + "/api/settings/public",
		authGuardTestAdminPrefix + "/api/captcha",
		authGuardTestAdminPrefix + "/api/captcha/image",
		authGuardTestAdminPrefix + "/api/webauthn/login/begin",
		authGuardTestAdminPrefix + "/api/webauthn/login/finish",
		// 集群对等端点自校验 X-Cluster-Key
		authGuardTestAdminPrefix + "/api/cluster/export-certs",
	}

	s := newAuthGuardTestServer(t)
	for _, p := range public {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, p, nil)

		if !s.adminAPIAuthGuard(w, r) {
			t.Errorf("%s：公开端点应放行", p)
		}
	}
}

// 登录页要靠面板前缀下的脚本与样式才能渲染，这些路径绝不能被拦。
func TestAdminAPIAuthGuardLeavesNonAPIPathsAlone(t *testing.T) {
	paths := []string{
		authGuardTestAdminPrefix + "/assets/index-B3rM2ONO.js",
		authGuardTestAdminPrefix + "/logo.png",
		authGuardTestAdminPrefix + "/favicon.ico",
		authGuardTestAdminPrefix + "/login",
		authGuardTestAdminPrefix + "/sites",
		authGuardTestAdminPrefix + "/mcp/stream",
		"/static/css/bootstrap.min.css",
		"/favicon.ico",
		"/metrics",
		"/",
	}

	s := newAuthGuardTestServer(t)
	for _, p := range paths {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, p, nil)

		if !s.adminAPIAuthGuard(w, r) {
			t.Errorf("%s：非 API 路径不应被统一鉴权拦截", p)
		}
	}
}

func TestAdminAPIAuthGuardRejectsInvalidBearerToken(t *testing.T) {
	s := newAuthGuardTestServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, authGuardTestAdminPrefix+"/api/sites", nil)
	r.Header.Set("Authorization", "Bearer not-a-real-token")

	if s.adminAPIAuthGuard(w, r) {
		t.Fatal("无效 Bearer token 不应放行")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d", w.Code)
	}
}

func TestAdminAPIAuthGuardAcceptsValidBearerToken(t *testing.T) {
	s := newAuthGuardTestServer(t)

	tok, err := s.tokenStore.Generate(security.TokenRoleWrite, "auth guard test")
	if err != nil {
		t.Fatalf("生成测试 token 失败: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, authGuardTestAdminPrefix+"/api/cache/clear", nil)
	r.Header.Set("Authorization", "Bearer "+tok.Token)

	if !s.adminAPIAuthGuard(w, r) {
		t.Fatal("有效 Bearer token 应放行")
	}
}

// 统一鉴权只覆盖当前配置的管理前缀，避免误伤其他路径。
func TestAdminAPIAuthGuardScopedToConfiguredAdminPrefix(t *testing.T) {
	s := newAuthGuardTestServer(t)
	s.config.AdminPrefix = "/other-panel"

	for _, p := range []string{
		"/api/cache/clear",
		authGuardTestAdminPrefix + "/api/cache/clear",
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, p, nil)

		if !s.adminAPIAuthGuard(w, r) {
			t.Errorf("%s：不属于当前管理前缀，不应被拦截", p)
		}
	}
}

// 管理前缀留空时退化为裸 /api/ 前缀，仍应正常拦截。
func TestAdminAPIAuthGuardWithEmptyAdminPrefix(t *testing.T) {
	s := newAuthGuardTestServer(t)
	s.config.AdminPrefix = ""

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/cache/clear", nil)

	if s.adminAPIAuthGuard(w, r) {
		t.Fatal("空前缀下无凭据的 /api/ 请求不应放行")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d", w.Code)
	}
}
