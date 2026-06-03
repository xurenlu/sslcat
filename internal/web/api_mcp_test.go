package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

// 测试范围：纯函数 + 不依赖 authorizeAPI 的辅助。
// authorizeAPI 强耦合 Server 整体；这里只覆盖 PEM/scope 校验、publicToken 脱敏、writeJSONStatus、validateMCPScopes。

func TestValidateMCPScopes_Allowed(t *testing.T) {
	cases := [][]string{
		{"read"},
		{"site:write", "cert:write"},
		{"admin"},
	}
	for _, sc := range cases {
		if err := validateMCPScopes(sc); err != nil {
			t.Errorf("expected %v to be valid, err=%v", sc, err)
		}
	}
}

func TestValidateMCPScopes_Rejected(t *testing.T) {
	cases := [][]string{
		{"unknown"},
		{"read", "typo"},
		{""},
	}
	for _, sc := range cases {
		if err := validateMCPScopes(sc); err == nil {
			t.Errorf("expected %v to be rejected", sc)
		}
	}
}

func TestPublicToken_DoesNotLeakHash(t *testing.T) {
	hash, _ := mcp.HashToken("plain-token-for-test")
	tk := &config.MCPToken{
		Name:      "ut",
		TokenHash: hash,
		Scopes:    []string{"read"},
		CreatedAt: "2026-06-03T00:00:00Z",
	}
	pub := publicToken(tk)
	// JSON marshal + 反序列化，确保不存在 token_hash 字段
	b, err := json.Marshal(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(b, []byte("token_hash")) || bytes.Contains(b, []byte(hash)) {
		t.Fatalf("publicToken leaked hash: %s", string(b))
	}
	if pub.Name != "ut" || len(pub.Scopes) != 1 {
		t.Errorf("public fields lost: %+v", pub)
	}
}

func TestWriteJSONStatus(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONStatus(w, http.StatusCreated, map[string]string{"a": "b"})
	if w.Code != http.StatusCreated {
		t.Errorf("code=%d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type=%s", ct)
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out["a"] != "b" {
		t.Errorf("body=%v", out)
	}
}

func TestMCPTokenCreateReq_DecodeShape(t *testing.T) {
	body := `{"name":"x","scopes":["read","site:write"],"ip_allowlist":["10.0.0.0/8"],"expires_at":"2027-01-01T00:00:00Z","rate_limit":"60/min","description":"d"}`
	var r mcpTokenCreateReq
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Name != "x" || len(r.Scopes) != 2 || len(r.IPAllowlist) != 1 {
		t.Errorf("shape wrong: %+v", r)
	}
}
