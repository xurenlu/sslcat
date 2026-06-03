package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func makeServer(t *testing.T) *Server {
	t.Helper()
	reg := NewRegistry()
	if err := reg.RegisterTool(&Tool{
		Name:        "echo",
		Description: "echo input back",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Scope:       ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *CallContext) (ToolResult, error) {
			return TextResult(map[string]any{"got": json.RawMessage(args)}), nil
		},
	}); err != nil {
		t.Fatalf("register echo: %v", err)
	}
	if err := reg.RegisterTool(&Tool{
		Name:        "destroy",
		Description: "needs site:write",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Scope:       ScopeSiteWrite,
		Destructive: true,
		Handler: func(ctx context.Context, args json.RawMessage, caller *CallContext) (ToolResult, error) {
			return TextResult("done"), nil
		},
	}); err != nil {
		t.Fatalf("register destroy: %v", err)
	}
	return NewServer(ServerInfo{Name: "sslcat-test", Version: "0.0.0"}, reg, nil)
}

func parseResult(t *testing.T, resp *Response, out any) {
	t.Helper()
	if resp == nil {
		t.Fatal("nil response")
	}
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	if err := json.Unmarshal(resp.Result, out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
}

func TestServer_Initialize(t *testing.T) {
	s := makeServer(t)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize",
		Params: json.RawMessage(`{"protocolVersion":"2025-06-18","clientInfo":{"name":"go-test","version":"1"}}`)}
	resp := s.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	var r initializeResult
	parseResult(t, resp, &r)
	if r.ProtocolVersion == "" {
		t.Fatal("empty protocolVersion in response")
	}
	if r.ServerInfo.Name != "sslcat-test" {
		t.Fatalf("unexpected serverInfo: %+v", r.ServerInfo)
	}
}

func TestServer_Ping(t *testing.T) {
	s := makeServer(t)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "ping"}
	resp := s.Handle(context.Background(), req, &CallContext{})
	if resp == nil || resp.Error != nil {
		t.Fatalf("ping failed: %+v", resp)
	}
}

func TestServer_ToolsList(t *testing.T) {
	s := makeServer(t)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`3`), Method: "tools/list"}
	resp := s.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	var r toolsListResult
	parseResult(t, resp, &r)
	if len(r.Tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(r.Tools))
	}
	// echo 应该排在 destroy 前面（字母序）
	if r.Tools[0].Name != "destroy" || r.Tools[1].Name != "echo" {
		t.Fatalf("unexpected sort order: %v", r.Tools)
	}
	for _, td := range r.Tools {
		if td.Name == "destroy" && (td.Annotations == nil || !td.Annotations.Destructive) {
			t.Fatalf("destroy should be marked destructive: %+v", td.Annotations)
		}
	}
}

func TestServer_ToolsCall_Success(t *testing.T) {
	s := makeServer(t)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`4`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"echo","arguments":{"hello":"world"}}`)}
	resp := s.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	var r ToolResult
	parseResult(t, resp, &r)
	if r.IsError {
		t.Fatalf("unexpected error result: %+v", r)
	}
	if len(r.Content) == 0 || !strings.Contains(r.Content[0].Text, "hello") {
		t.Fatalf("echo output missing input: %+v", r)
	}
}

func TestServer_ToolsCall_ScopeForbidden(t *testing.T) {
	s := makeServer(t)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`5`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"destroy","arguments":{}}`)}
	resp := s.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	if resp.Error == nil || resp.Error.Code != CodeForbidden {
		t.Fatalf("expected forbidden, got %+v", resp)
	}
}

func TestServer_ToolsCall_AdminScopeBypass(t *testing.T) {
	s := makeServer(t)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`6`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"destroy","arguments":{}}`)}
	resp := s.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeAdmin}})
	if resp.Error != nil {
		t.Fatalf("admin should bypass: %+v", resp.Error)
	}
}

func TestServer_ToolsCall_UnknownTool(t *testing.T) {
	s := makeServer(t)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`7`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"nope"}`)}
	resp := s.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeAdmin}})
	if resp.Error == nil || resp.Error.Code != CodeMethodNotFound {
		t.Fatalf("expected method not found, got %+v", resp)
	}
}

func TestServer_Notification_NoResponse(t *testing.T) {
	s := makeServer(t)
	req := &Request{JSONRPC: "2.0", Method: "notifications/initialized"}
	resp := s.Handle(context.Background(), req, &CallContext{})
	if resp != nil {
		t.Fatalf("notification should not produce response, got %+v", resp)
	}
}

func TestParseRequest_Validation(t *testing.T) {
	good := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if _, err := ParseRequest(good); err != nil {
		t.Fatalf("good request rejected: %v", err)
	}
	bad := [][]byte{
		[]byte(`{"jsonrpc":"1.0","id":1,"method":"x"}`),
		[]byte(`{"jsonrpc":"2.0","id":1}`),
		[]byte(`not json`),
	}
	for _, b := range bad {
		if _, err := ParseRequest(b); err == nil {
			t.Errorf("bad request should be rejected: %s", b)
		}
	}
}
