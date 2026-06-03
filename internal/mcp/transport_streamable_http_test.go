package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
)

func newTestHandler(t *testing.T) (http.Handler, string /*token*/) {
	t.Helper()

	plain := "sslcat_mcp_unit_test_token_xxxxxxx"
	hash, err := HashToken(plain)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	cfg := &config.MCPConfig{
		Tokens: []config.MCPToken{
			{Name: "ut", TokenHash: hash, Scopes: []string{"read"}},
		},
	}

	reg := NewRegistry()
	_ = reg.RegisterTool(&Tool{
		Name:        "noop",
		Description: "noop",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Scope:       ScopeRead,
		Handler: func(ctx context.Context, _ json.RawMessage, _ *CallContext) (ToolResult, error) {
			return TextResult(map[string]string{"ok": "yes"}), nil
		},
	})

	srv := NewServer(ServerInfo{Name: "ut", Version: "0.0.0"}, reg, nil)
	auth := NewAuthenticator(cfg)
	return NewStreamableHTTPHandler(srv, auth, HTTPHandlerOptions{}), plain
}

func TestHTTP_RejectUnauthorized(t *testing.T) {
	h, _ := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/sslcat-panel/mcp/stream",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestHTTP_InitializeSetsSessionId(t *testing.T) {
	h, tok := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/sslcat-panel/mcp/stream",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	sid := w.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("expected Mcp-Session-Id header on initialize response")
	}
}

func TestHTTP_ToolsCallEndToEnd(t *testing.T) {
	h, tok := newTestHandler(t)

	// initialize
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/sslcat-panel/mcp/stream",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(w, r)
	sid := w.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("missing session id")
	}

	// tools/call without session id → should fail
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/sslcat-panel/mcp/stream",
		strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"noop"}}`))
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without session id, got %d body=%s", w2.Code, w2.Body.String())
	}

	// tools/call with session id → ok
	w3 := httptest.NewRecorder()
	body := []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"noop","arguments":{}}}`)
	r3 := httptest.NewRequest("POST", "/sslcat-panel/mcp/stream", bytes.NewReader(body))
	r3.Header.Set("Content-Type", "application/json")
	r3.Header.Set("Authorization", "Bearer "+tok)
	r3.Header.Set("Mcp-Session-Id", sid)
	h.ServeHTTP(w3, r3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w3.Code, w3.Body.String())
	}
	var resp Response
	if err := json.Unmarshal(w3.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse resp: %v body=%s", err, w3.Body.String())
	}
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
}

func TestHTTP_GETNotSupported(t *testing.T) {
	h, tok := newTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/sslcat-panel/mcp/stream", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestHTTP_DeleteSession(t *testing.T) {
	h, tok := newTestHandler(t)
	// initialize first
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/sslcat-panel/mcp/stream",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(w, r)
	sid := w.Header().Get("Mcp-Session-Id")

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("DELETE", "/sslcat-panel/mcp/stream", nil)
	r2.Header.Set("Authorization", "Bearer "+tok)
	r2.Header.Set("Mcp-Session-Id", sid)
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w2.Code)
	}

	// session 已删，再调 tools/list 应 400
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("POST", "/sslcat-panel/mcp/stream",
		strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	r3.Header.Set("Authorization", "Bearer "+tok)
	r3.Header.Set("Mcp-Session-Id", sid)
	h.ServeHTTP(w3, r3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 after session deleted, got %d body=%s", w3.Code, w3.Body.String())
	}
}
