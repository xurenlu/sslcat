package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xurenlu/sslcat/internal/security"
)

func TestAdminAPIAuthGuardTokenPermissions(t *testing.T) {
	for _, role := range []security.TokenRole{security.TokenRoleRead, security.TokenRoleWrite} {
		s := newAuthGuardTestServer(t)
		token, err := s.tokenStore.Generate(role, "permission regression")
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			method string
			path   string
			query  bool
		}{
			{http.MethodGet, "/api/cache/stats", true},
			{http.MethodHead, "/api/cache/stats", true},
			{http.MethodPost, "/api/cache/clear", false},
			{http.MethodPut, "/api/sites", false},
			{http.MethodPatch, "/api/sites", false},
			{http.MethodDelete, "/api/webauthn/credentials/delete", false},
		} {
			t.Run(string(role)+"/"+tc.method+tc.path, func(t *testing.T) {
				r := httptest.NewRequest(tc.method, authGuardTestAdminPrefix+tc.path, nil)
				r.Header.Set("Authorization", "Bearer "+token.Token)
				w := httptest.NewRecorder()
				want := tc.query || role == security.TokenRoleWrite
				if got := s.adminAPIAuthGuard(w, r); got != want {
					t.Fatalf("allowed=%v, want %v (status %d)", got, want, w.Code)
				}
			})
		}
	}
}

func TestAdminAPIAuthGuardReadTokenCannotReachCacheClear(t *testing.T) {
	s := newAuthGuardTestServer(t)
	token, err := s.tokenStore.Generate(security.TokenRoleRead, "cache clear regression")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	reached := false
	mux.HandleFunc(authGuardTestAdminPrefix+"/api/cache/clear", func(w http.ResponseWriter, r *http.Request) {
		reached = true
		s.handleCacheClear(w, r)
	})
	r := httptest.NewRequest(http.MethodPost, authGuardTestAdminPrefix+"/api/cache/clear?type=all", nil)
	r.Header.Set("Authorization", "Bearer "+token.Token)
	w := httptest.NewRecorder()
	if s.adminAPIAuthGuard(w, r) {
		mux.ServeHTTP(w, r)
	}
	if reached || w.Code != http.StatusUnauthorized {
		t.Fatalf("read token reached mutation: reached=%v status=%d", reached, w.Code)
	}
}
