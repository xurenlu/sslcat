package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/monitor"
	"github.com/xurenlu/sslcat/internal/security"
)

func TestMonitoringBaselinesReset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    security.TokenRole
		method  string
		manager bool
		want    int
	}{
		{"anonymous", "", http.MethodPost, true, http.StatusUnauthorized},
		{"read token", security.TokenRoleRead, http.MethodPost, true, http.StatusUnauthorized},
		{"wrong method", security.TokenRoleWrite, http.MethodGet, true, http.StatusMethodNotAllowed},
		{"missing manager", security.TokenRoleWrite, http.MethodPost, false, http.StatusBadRequest},
		{"write token", security.TokenRoleWrite, http.MethodPost, true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			s := &Server{
				log:            logrus.NewEntry(logger),
				sessionManager: &SessionManager{log: logger},
				tokenStore:     security.NewTokenStore(filepath.Join(t.TempDir(), "tokens.json")),
			}
			if tc.manager {
				s.monitorManager = monitor.NewManager(monitor.ManagerOptions{})
			}
			r := httptest.NewRequest(tc.method, "/sslcat-panel/api/monitoring/baselines/reset", nil)
			if tc.role != "" {
				token, err := s.tokenStore.Generate(tc.role, "monitoring baseline test")
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "Bearer "+token.Token)
			}
			w := httptest.NewRecorder()
			s.handleAPIMonitoringBaselinesReset(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
}
