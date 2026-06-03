package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func newTestResourceRegistry(t *testing.T) *ResourceRegistry {
	t.Helper()
	reg := NewResourceRegistry()
	if err := reg.Register(&Resource{
		URI:      "sslcat://static/one",
		Name:     "one",
		Scope:    ScopeRead,
		MimeType: "application/json",
		Reader: func(ctx context.Context, uri string, c *CallContext) (string, string, error) {
			return "application/json", `{"k":"v"}`, nil
		},
	}); err != nil {
		t.Fatalf("register static: %v", err)
	}
	if err := reg.RegisterTemplate(&ResourceTemplate{
		URITemplate: "sslcat://logs/access{?since,domain}",
		Name:        "access log",
		Scope:       ScopeRead,
		MimeType:    "text/plain",
		MatchPrefix: "sslcat://logs/access",
		Reader: func(ctx context.Context, uri string, c *CallContext) (string, string, error) {
			q, _ := ParseURIQuery(uri)
			return "text/plain", "since=" + q.Get("since") + " domain=" + q.Get("domain"), nil
		},
	}); err != nil {
		t.Fatalf("register template: %v", err)
	}
	return reg
}

func TestResourceRegistry_ResolveStatic(t *testing.T) {
	reg := newTestResourceRegistry(t)
	r, scope, ok := reg.Resolve("sslcat://static/one")
	if !ok {
		t.Fatal("static resolve failed")
	}
	if scope != ScopeRead {
		t.Errorf("scope=%s", scope)
	}
	_, text, err := r(context.Background(), "sslcat://static/one", &CallContext{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if text != `{"k":"v"}` {
		t.Errorf("unexpected body: %s", text)
	}
}

func TestResourceRegistry_ResolveTemplate(t *testing.T) {
	reg := newTestResourceRegistry(t)
	// 不带 query
	if _, _, ok := reg.Resolve("sslcat://logs/access"); !ok {
		t.Error("template should match bare prefix")
	}
	// 带 query
	r, _, ok := reg.Resolve("sslcat://logs/access?since=10m&domain=x.com")
	if !ok {
		t.Fatal("template should match with query")
	}
	_, text, _ := r(context.Background(), "sslcat://logs/access?since=10m&domain=x.com", nil)
	if !strings.Contains(text, "since=10m") || !strings.Contains(text, "domain=x.com") {
		t.Errorf("query not parsed: %s", text)
	}
}

func TestResourceRegistry_UnknownURI(t *testing.T) {
	reg := newTestResourceRegistry(t)
	if _, _, ok := reg.Resolve("sslcat://nope"); ok {
		t.Error("unknown uri should not resolve")
	}
}

func TestResourceRegistry_Lists(t *testing.T) {
	reg := newTestResourceRegistry(t)
	if got := len(reg.ListResources()); got != 1 {
		t.Errorf("expected 1 static, got %d", got)
	}
	if got := len(reg.ListTemplates()); got != 1 {
		t.Errorf("expected 1 template, got %d", got)
	}
}

func TestServer_ResourcesList(t *testing.T) {
	reg := newTestResourceRegistry(t)
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, NewRegistry(), nil)
	srv.Resources = reg

	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "resources/list"}
	resp := srv.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	var r resourceListResult
	_ = json.Unmarshal(resp.Result, &r)
	if len(r.Resources) != 1 {
		t.Errorf("expected 1 static, got %d", len(r.Resources))
	}
}

func TestServer_ResourcesTemplatesList(t *testing.T) {
	reg := newTestResourceRegistry(t)
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, NewRegistry(), nil)
	srv.Resources = reg

	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "resources/templates/list"}
	resp := srv.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	var r resourceTemplatesListResult
	_ = json.Unmarshal(resp.Result, &r)
	if len(r.ResourceTemplates) != 1 {
		t.Errorf("expected 1 template, got %d", len(r.ResourceTemplates))
	}
}

func TestServer_ResourcesRead_Success(t *testing.T) {
	reg := newTestResourceRegistry(t)
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, NewRegistry(), nil)
	srv.Resources = reg

	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"sslcat://static/one"}`)}
	resp := srv.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	if resp.Error != nil {
		t.Fatalf("rpc error: %+v", resp.Error)
	}
	var r resourceReadResult
	_ = json.Unmarshal(resp.Result, &r)
	if len(r.Contents) != 1 || r.Contents[0].Text != `{"k":"v"}` {
		t.Errorf("unexpected contents: %+v", r.Contents)
	}
}

func TestServer_ResourcesRead_UnknownURI(t *testing.T) {
	reg := newTestResourceRegistry(t)
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, NewRegistry(), nil)
	srv.Resources = reg

	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"sslcat://nope"}`)}
	resp := srv.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	if resp.Error == nil || resp.Error.Code != CodeResourceNotFound {
		t.Fatalf("expected ResourceNotFound, got %+v", resp.Error)
	}
}

func TestServer_ResourcesRead_ScopeForbidden(t *testing.T) {
	reg := NewResourceRegistry()
	_ = reg.Register(&Resource{
		URI:    "sslcat://secret/x",
		Scope:  ScopeAdmin, // 要求 admin
		Reader: func(ctx context.Context, uri string, c *CallContext) (string, string, error) { return "text/plain", "x", nil },
	})
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, NewRegistry(), nil)
	srv.Resources = reg

	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"sslcat://secret/x"}`)}
	resp := srv.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	if resp.Error == nil || resp.Error.Code != CodeForbidden {
		t.Fatalf("expected forbidden, got %+v", resp.Error)
	}
}

func TestServer_ResourcesDisabled(t *testing.T) {
	// Resources 字段未设：resources/* 应当返回空列表或 method not found（按实现）
	srv := NewServer(ServerInfo{Name: "ut", Version: "0"}, NewRegistry(), nil)
	req := &Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "resources/list"}
	resp := srv.Handle(context.Background(), req, &CallContext{Scopes: []Scope{ScopeRead}})
	if resp.Error != nil {
		t.Fatalf("list should soft-fail to empty, got %+v", resp.Error)
	}
	var r resourceListResult
	_ = json.Unmarshal(resp.Result, &r)
	if len(r.Resources) != 0 {
		t.Errorf("expected empty list, got %d", len(r.Resources))
	}

	// read 时无 Resources 应 MethodNotFound
	req2 := &Request{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "resources/read",
		Params: json.RawMessage(`{"uri":"x"}`)}
	resp2 := srv.Handle(context.Background(), req2, &CallContext{Scopes: []Scope{ScopeRead}})
	if resp2.Error == nil {
		t.Fatal("read should error when Resources nil")
	}
}
