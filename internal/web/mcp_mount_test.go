package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

func TestMCPRoutesStayMountedAcrossEnableToggle(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)

	cfg := &config.Config{
		AdminPrefix: "/admin",
		MCP: config.MCPConfig{
			Enabled:    false,
			PathPrefix: "/mcp",
			Audit:      config.MCPAuditConfig{Enabled: false},
		},
	}
	s := &Server{
		config:  cfg,
		mux:     http.NewServeMux(),
		log:     logrus.NewEntry(log),
		version: "2.3.0-test",
	}
	s.setupMCPRoutes()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/mcp/health", nil)
	s.mux.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled health: status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"disabled"`) {
		t.Fatalf("disabled health body should be explicit, got %s", w.Body.String())
	}

	cfg.MCP.Enabled = true
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/admin/mcp/health", nil)
	s.mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("enabled health: status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-MCP-Protocol-Version"); got == "" {
		t.Fatal("enabled health should expose MCP protocol version")
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/admin/mcp/stream",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	r.Header.Set("Content-Type", "application/json")
	s.mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("enabled stream without token should reach MCP auth, status=%d body=%s", w.Code, w.Body.String())
	}

	cfg.MCP.Enabled = false
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/admin/mcp/stream",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	r.Header.Set("Content-Type", "application/json")
	s.mux.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled stream should stay mounted but unavailable, status=%d body=%s", w.Code, w.Body.String())
	}
}
