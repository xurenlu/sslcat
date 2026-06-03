package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditor_LogAndSanitize(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "mcp_audit.log")
	a, err := NewAuditor(base)
	if err != nil {
		t.Fatalf("NewAuditor: %v", err)
	}
	defer a.Close()

	args := json.RawMessage(`{
        "domain": "example.com",
        "password": "should-be-masked",
        "nested": {"api_key": "also-masked", "harmless": "ok"}
    }`)
	now := time.Now()
	a.Log(AuditEntry{
		Time:      now,
		TokenName: "test-tk",
		IP:        "127.0.0.1",
		Tool:      "site_add",
		Args:      args,
		Status:    "ok",
		LatencyMS: 42,
	})

	expected := filepath.Join(dir, "mcp_audit."+now.Format("20060102")+".log")
	data, err := os.ReadFile(expected)
	if err != nil {
		t.Fatalf("read audit log %s: %v", expected, err)
	}
	body := string(data)
	if !strings.Contains(body, `"tool":"site_add"`) {
		t.Errorf("audit line missing tool name: %s", body)
	}
	if strings.Contains(body, "should-be-masked") || strings.Contains(body, "also-masked") {
		t.Errorf("sensitive value leaked in audit log: %s", body)
	}
	if !strings.Contains(body, `"harmless":"ok"`) {
		t.Errorf("non-sensitive value should be preserved: %s", body)
	}
}

func TestSanitizeArgs_NonObjectPassthrough(t *testing.T) {
	raw := json.RawMessage(`["just","an","array"]`)
	got := sanitizeArgs(raw)
	if string(got) != string(raw) {
		t.Fatalf("non-object should pass through, got %s", got)
	}
}

func TestIsSensitive(t *testing.T) {
	cases := map[string]bool{
		"password":      true,
		"api_key":       true,
		"X-Api-Secret":  true,
		"totp_secret":   true,
		"domain":        false,
		"name":          false,
		"description":   false,
		"private_key":   true,
		"":              false,
	}
	for k, want := range cases {
		if got := isSensitive(k); got != want {
			t.Errorf("isSensitive(%q) = %v, want %v", k, got, want)
		}
	}
}
