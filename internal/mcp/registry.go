package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// Scope 表示一个 tool 所需的权限范围。
type Scope string

const (
	ScopeRead          Scope = "read"
	ScopeSiteWrite     Scope = "site:write"
	ScopeCertWrite     Scope = "cert:write"
	ScopeProxyWrite    Scope = "proxy:write"
	ScopeSecurityWrite Scope = "security:write"
	ScopeOpsWrite      Scope = "ops:write"
	ScopeAdmin         Scope = "admin"
)

// ToolHandler 工具实现函数。返回的 result 会被序列化为 MCP 规范的 tool 响应。
type ToolHandler func(ctx context.Context, args json.RawMessage, caller *CallContext) (ToolResult, error)

// CallContext 包含调用方信息，供 tool 内部审计与限权使用。
type CallContext struct {
	TokenName string
	Scopes    []Scope
	IP        string
}

// Tool 一个注册到 MCP 的工具。
type Tool struct {
	Name        string          // 工具名，全局唯一，建议蛇形命名
	Title       string          // 人类可读名（可选，MCP 客户端展示用）
	Description string          // 详细描述
	InputSchema json.RawMessage // JSON Schema（draft 2020-12）
	Scope       Scope           // 所需 scope
	Destructive bool            // 是否破坏性操作（会被审计与二次确认）
	Handler     ToolHandler     `json:"-"`
}

// Registry 工具/资源/提示注册中心。
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*Tool
}

// NewRegistry 创建新注册中心。
func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]*Tool)}
}

// RegisterTool 注册工具。重复注册同名工具会返回 error。
func (r *Registry) RegisterTool(t *Tool) error {
	if t == nil || t.Name == "" {
		return fmt.Errorf("tool name required")
	}
	if t.Handler == nil {
		return fmt.Errorf("tool %s: handler is nil", t.Name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.tools[t.Name]; ok {
		return fmt.Errorf("tool %s already registered", t.Name)
	}
	r.tools[t.Name] = t
	return nil
}

// ListTools 返回排序后的工具列表（用于 tools/list）。
func (r *Registry) ListTools() []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// GetTool 按名查询。
func (r *Registry) GetTool(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// ToolResult MCP tool 响应内容（content array）。
// 仅支持文本内容（text），其它类型（image/resource）后续按需扩展。
type ToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ToolContent 一段响应内容。
type ToolContent struct {
	Type string `json:"type"` // "text"
	Text string `json:"text,omitempty"`
}

// TextResult 便捷构造：返回一段 JSON 文本作为 tool 响应。
func TextResult(payload any) ToolResult {
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return ToolResult{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("marshal error: %v", err)}},
			IsError: true,
		}
	}
	return ToolResult{Content: []ToolContent{{Type: "text", Text: string(raw)}}}
}

// ErrorResult 便捷构造：返回一段错误文本作为 tool 响应（isError=true）。
func ErrorResult(msg string) ToolResult {
	return ToolResult{
		Content: []ToolContent{{Type: "text", Text: msg}},
		IsError: true,
	}
}
