package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMetrics 收集调用计数，供测试断言。
type fakeMetrics struct {
	calls   int64
	lastVal int64
}

func (f *fakeMetrics) ObserveToolCall(tool, status string, latencySec float64) {
	atomic.AddInt64(&f.calls, 1)
	_ = tool
	_ = status
	_ = latencySec
}
func (f *fakeMetrics) SetPendingConfirmations(n int) {
	atomic.StoreInt64(&f.lastVal, int64(n))
}

// makeDestructiveServer 构造一个含 destructive tool 的 server，使用 ConfirmGate。
func makeDestructiveServer(t *testing.T) (*Server, *int64 /*execCount*/) {
	t.Helper()
	reg := NewRegistry()
	var execCount int64
	_ = reg.RegisterTool(&Tool{
		Name:        "wipe",
		Description: "destructive tool for tests",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Scope:       ScopeSiteWrite,
		Destructive: true,
		Handler: func(ctx context.Context, args json.RawMessage, caller *CallContext) (ToolResult, error) {
			if !caller.Confirmed {
				return TextResult(map[string]any{
					"requires_confirmation": true,
					"confirm_token":         caller.ConfirmToken,
				}), nil
			}
			atomic.AddInt64(&execCount, 1)
			return TextResult(map[string]any{"ok": true}), nil
		},
	})
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, reg, nil)
	srv.Confirm = NewConfirmGate(time.Minute)
	return srv, &execCount
}

func TestDestructive_TwoPhaseAtServerLayer(t *testing.T) {
	srv, execCount := makeDestructiveServer(t)
	caller := &CallContext{
		TokenName: "ut",
		Scopes:    []Scope{ScopeSiteWrite},
	}

	// 第一次：不带 confirm，应返回 requires_confirmation + confirm_token；不执行。
	req1 := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"wipe","arguments":{"domain":"a"}}`)}
	resp1 := srv.Handle(context.Background(), req1, caller)
	if resp1.Error != nil {
		t.Fatalf("unexpected rpc error: %+v", resp1.Error)
	}
	var r1 ToolResult
	_ = json.Unmarshal(resp1.Result, &r1)
	var body1 struct {
		Requires bool   `json:"requires_confirmation"`
		Token    string `json:"confirm_token"`
	}
	_ = json.Unmarshal([]byte(r1.Content[0].Text), &body1)
	if !body1.Requires || body1.Token == "" {
		t.Fatalf("expected requires_confirmation + token, got %+v", body1)
	}
	if atomic.LoadInt64(execCount) != 0 {
		t.Fatal("destructive tool should NOT execute on first call")
	}

	// 第二次：带 confirm，应真正执行。
	argsWithConfirm := `{"name":"wipe","arguments":{"domain":"a","confirm":"` + body1.Token + `"}}`
	req2 := &Request{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "tools/call",
		Params: json.RawMessage(argsWithConfirm)}
	resp2 := srv.Handle(context.Background(), req2, caller)
	if resp2.Error != nil {
		t.Fatalf("unexpected rpc error on confirmed call: %+v", resp2.Error)
	}
	if atomic.LoadInt64(execCount) != 1 {
		t.Fatal("destructive tool should execute after confirm")
	}
	// resp2.Result 是被两次 JSON-encode 的：先 ToolResult 序列化，再外层 JSON-RPC 序列化，
	// 所以内层字符串里的引号都被转义。直接断言 ToolResult 内 IsError=false + 含 ok 字段。
	var r2 ToolResult
	_ = json.Unmarshal(resp2.Result, &r2)
	if r2.IsError {
		t.Fatalf("confirmed call returned isError=true: %+v", r2)
	}
	if len(r2.Content) == 0 || !strings.Contains(r2.Content[0].Text, `"ok"`) {
		t.Fatalf("confirmed call missing ok field: %+v", r2)
	}

	// 第三次：用同一 token 重放，应失败（token 已消费），返回新的 dry-run。
	resp3 := srv.Handle(context.Background(), req2, caller)
	var r3 ToolResult
	_ = json.Unmarshal(resp3.Result, &r3)
	var body3 struct {
		Requires bool `json:"requires_confirmation"`
	}
	_ = json.Unmarshal([]byte(r3.Content[0].Text), &body3)
	if !body3.Requires {
		t.Fatal("replayed confirm token should not execute again")
	}
	if atomic.LoadInt64(execCount) != 1 {
		t.Fatal("token replay should not execute again")
	}
}

func TestDestructive_DryRunDoesNotRequireConfirm_NoGate(t *testing.T) {
	// 不挂 ConfirmGate 时，destructive tool 应当被当作 Confirmed=true（向后兼容）。
	reg := NewRegistry()
	var execCount int64
	_ = reg.RegisterTool(&Tool{
		Name:        "wipe",
		Description: "destructive",
		Scope:       ScopeSiteWrite,
		Destructive: true,
		Handler: func(ctx context.Context, args json.RawMessage, caller *CallContext) (ToolResult, error) {
			if !caller.Confirmed {
				t.Error("expected Confirmed=true when no ConfirmGate set")
			}
			atomic.AddInt64(&execCount, 1)
			return TextResult("done"), nil
		},
	})
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, reg, nil)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"wipe","arguments":{}}`)}
	srv.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeSiteWrite}})
	if atomic.LoadInt64(&execCount) != 1 {
		t.Fatal("expected exec without ConfirmGate")
	}
}

func TestMetrics_HookCalled(t *testing.T) {
	reg := NewRegistry()
	_ = reg.RegisterTool(&Tool{
		Name:        "noop",
		Description: "x",
		Scope:       ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *CallContext) (ToolResult, error) {
			return TextResult("ok"), nil
		},
	})
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, reg, nil)
	m := &fakeMetrics{}
	srv.Metrics = m
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"noop","arguments":{}}`)}
	srv.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	if atomic.LoadInt64(&m.calls) != 1 {
		t.Fatalf("expected 1 metric observation, got %d", m.calls)
	}
}

func TestPromMetrics_RegisterIsIdempotent(t *testing.T) {
	a := NewPromMetrics()
	b := NewPromMetrics()
	if a != b {
		t.Fatal("NewPromMetrics should be a singleton")
	}
	a.ObserveToolCall("noop", "ok", 0.01)
	a.SetPendingConfirmations(3)
}
