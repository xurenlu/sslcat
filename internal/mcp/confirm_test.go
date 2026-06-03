package mcp

import (
	"encoding/json"
	"testing"
	"time"
)

func TestConfirmGate_HappyPath(t *testing.T) {
	g := NewConfirmGate(time.Minute)
	args := json.RawMessage(`{"domain":"x.example.com"}`)
	caller := &CallContext{TokenName: "tk"}

	tok := g.Issue("site_delete", args, caller)
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	if !g.Consume(tok, "site_delete", args, caller) {
		t.Fatal("Consume should succeed with matching token")
	}
	// 已消费，再用应失败
	if g.Consume(tok, "site_delete", args, caller) {
		t.Fatal("Consume should fail second time")
	}
}

func TestConfirmGate_ArgsMustMatch(t *testing.T) {
	g := NewConfirmGate(time.Minute)
	caller := &CallContext{TokenName: "tk"}
	tok := g.Issue("site_delete", json.RawMessage(`{"domain":"a.com"}`), caller)
	// 不同 args
	if g.Consume(tok, "site_delete", json.RawMessage(`{"domain":"b.com"}`), caller) {
		t.Fatal("Consume should fail when args differ")
	}
}

func TestConfirmGate_ToolMustMatch(t *testing.T) {
	g := NewConfirmGate(time.Minute)
	caller := &CallContext{TokenName: "tk"}
	args := json.RawMessage(`{}`)
	tok := g.Issue("site_delete", args, caller)
	if g.Consume(tok, "cert_delete", args, caller) {
		t.Fatal("Consume should fail across tools")
	}
}

func TestConfirmGate_TokenNameMustMatch(t *testing.T) {
	g := NewConfirmGate(time.Minute)
	args := json.RawMessage(`{}`)
	tok := g.Issue("site_delete", args, &CallContext{TokenName: "alice"})
	if g.Consume(tok, "site_delete", args, &CallContext{TokenName: "bob"}) {
		t.Fatal("Consume should fail when token name differs")
	}
}

func TestConfirmGate_ArgsCanonicalization(t *testing.T) {
	// 同语义不同 key 顺序应该产生同 token
	g1 := NewConfirmGate(time.Minute)
	caller := &CallContext{TokenName: "tk"}
	tok := g1.Issue("site_delete", json.RawMessage(`{"a":1,"b":2}`), caller)
	if !g1.Consume(tok, "site_delete", json.RawMessage(`{"b":2,"a":1}`), caller) {
		t.Fatal("Consume should succeed regardless of key order")
	}

	// 第二次调用带 confirm 字段，不影响哈希
	g2 := NewConfirmGate(time.Minute)
	tok2 := g2.Issue("site_delete", json.RawMessage(`{"domain":"x.com"}`), caller)
	if !g2.Consume(tok2, "site_delete",
		json.RawMessage(`{"domain":"x.com","confirm":"`+tok2+`"}`), caller) {
		t.Fatal("Consume should succeed when client adds confirm field on second call")
	}
}

func TestConfirmGate_Expiry(t *testing.T) {
	g := NewConfirmGate(10 * time.Millisecond)
	caller := &CallContext{TokenName: "tk"}
	args := json.RawMessage(`{}`)
	tok := g.Issue("site_delete", args, caller)
	time.Sleep(30 * time.Millisecond)
	if g.Consume(tok, "site_delete", args, caller) {
		t.Fatal("Consume should fail after TTL")
	}
}

func TestConfirmGate_PendingCount(t *testing.T) {
	g := NewConfirmGate(time.Minute)
	caller := &CallContext{TokenName: "tk"}
	if g.PendingCount() != 0 {
		t.Fatal("initial pending should be 0")
	}
	g.Issue("site_delete", json.RawMessage(`{"a":1}`), caller)
	g.Issue("cert_delete", json.RawMessage(`{"a":2}`), caller)
	if got := g.PendingCount(); got != 2 {
		t.Fatalf("pending=%d, want 2", got)
	}
}
