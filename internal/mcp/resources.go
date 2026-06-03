package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// ResourceReader 读取一个 resource，按需根据 URI 中的 query 参数返回内容。
//
// 返回 (mimeType, text, err)。
type ResourceReader func(ctx context.Context, uri string, caller *CallContext) (string, string, error)

// Resource 一个静态 resource。
type Resource struct {
	URI         string         `json:"uri"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	MimeType    string         `json:"mimeType,omitempty"`
	Scope       Scope          `json:"-"`
	Reader      ResourceReader `json:"-"`
}

// ResourceTemplate 一个带 URI Template 的 resource（RFC 6570 简化版，仅支持 {?param}）。
type ResourceTemplate struct {
	URITemplate string         `json:"uriTemplate"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	MimeType    string         `json:"mimeType,omitempty"`
	Scope       Scope          `json:"-"`
	// MatchPrefix 命中检查：read 时 URI 是否以该前缀开始（不含 query）
	// 例如模板 "sslcat://logs/access{?since,domain,limit}" 的 MatchPrefix 是 "sslcat://logs/access"。
	MatchPrefix string         `json:"-"`
	Reader      ResourceReader `json:"-"`
}

// ResourceRegistry 注册中心。
type ResourceRegistry struct {
	mu        sync.RWMutex
	statics   map[string]*Resource         // URI -> Resource
	templates []*ResourceTemplate
}

// NewResourceRegistry 创建注册中心。
func NewResourceRegistry() *ResourceRegistry {
	return &ResourceRegistry{
		statics: make(map[string]*Resource),
	}
}

// Register 注册一个静态 resource。重复 URI 报错。
func (r *ResourceRegistry) Register(res *Resource) error {
	if res == nil || res.URI == "" {
		return fmt.Errorf("resource uri required")
	}
	if res.Reader == nil {
		return fmt.Errorf("resource %s: reader is nil", res.URI)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.statics[res.URI]; ok {
		return fmt.Errorf("resource %s already registered", res.URI)
	}
	r.statics[res.URI] = res
	return nil
}

// RegisterTemplate 注册一个带 URI Template 的 resource。
func (r *ResourceRegistry) RegisterTemplate(t *ResourceTemplate) error {
	if t == nil || t.URITemplate == "" {
		return fmt.Errorf("resource template uri required")
	}
	if t.MatchPrefix == "" {
		return fmt.Errorf("resource template %s: MatchPrefix is required", t.URITemplate)
	}
	if t.Reader == nil {
		return fmt.Errorf("resource template %s: reader is nil", t.URITemplate)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.templates = append(r.templates, t)
	return nil
}

// ListResources 返回所有静态 resource。
func (r *ResourceRegistry) ListResources() []*Resource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Resource, 0, len(r.statics))
	for _, res := range r.statics {
		out = append(out, res)
	}
	return out
}

// ListTemplates 返回所有 resource templates。
func (r *ResourceRegistry) ListTemplates() []*ResourceTemplate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*ResourceTemplate, 0, len(r.templates))
	out = append(out, r.templates...)
	return out
}

// Resolve 根据 URI 找匹配的 reader：先查静态，再扫模板。返回 (reader, scope, ok)。
func (r *ResourceRegistry) Resolve(uri string) (ResourceReader, Scope, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.statics[uri]; ok {
		return s.Reader, s.Scope, true
	}
	// 模板：去掉 query 再前缀匹配
	bare := uri
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		bare = uri[:i]
	}
	for _, t := range r.templates {
		if bare == t.MatchPrefix || strings.HasPrefix(bare, t.MatchPrefix+"/") || strings.HasPrefix(bare, t.MatchPrefix+"?") {
			return t.Reader, t.Scope, true
		}
		// 兼容写法：MatchPrefix 不带尾斜杠时也允许直接相等
		if bare == t.MatchPrefix {
			return t.Reader, t.Scope, true
		}
	}
	return nil, "", false
}

// ParseURIQuery 工具函数：把 URI 中的 query 解析成 map。
func ParseURIQuery(uri string) (url.Values, error) {
	i := strings.IndexByte(uri, '?')
	if i < 0 {
		return url.Values{}, nil
	}
	return url.ParseQuery(uri[i+1:])
}

// resourceListResult MCP resources/list 响应。
type resourceListResult struct {
	Resources []*Resource `json:"resources"`
}

// resourceTemplatesListResult MCP resources/templates/list 响应。
type resourceTemplatesListResult struct {
	ResourceTemplates []*ResourceTemplate `json:"resourceTemplates"`
}

// resourceReadResult MCP resources/read 响应。
type resourceReadResult struct {
	Contents []resourceContent `json:"contents"`
}

type resourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text"`
}

// 内部辅助：JSON marshal 一个 result。
func jsonMustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
