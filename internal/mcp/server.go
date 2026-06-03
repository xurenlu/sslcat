package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// ProtocolVersion 当前实现支持的 MCP 协议版本。
//
// 写代码时跟随 MCP 规范的 stable revision；如果客户端声明的版本不同，
// initialize 阶段直接回我们支持的，由客户端决定是否继续。
const ProtocolVersion = "2025-06-18"

// ServerInfo MCP server 自我介绍信息。
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Server MCP 协议核心。无状态，由 transport 复用。
type Server struct {
	Info     ServerInfo
	Registry *Registry
	Auditor  *Auditor     // 可选，nil 表示不审计
	Confirm  *ConfirmGate // 可选，nil 表示对 destructive tool 不做二次确认（不推荐生产使用）

	// Metrics 可选指标钩子。每次 tool 调用结束后回调一次。
	Metrics MetricsRecorder

	log *logrus.Entry
}

// MetricsRecorder Prometheus 等观测系统的钩子。
type MetricsRecorder interface {
	ObserveToolCall(tool, status string, latencySec float64)
	SetPendingConfirmations(n int)
}

// NewServer 构造一个 MCP 协议核心。
func NewServer(info ServerInfo, reg *Registry, auditor *Auditor) *Server {
	return &Server{
		Info:     info,
		Registry: reg,
		Auditor:  auditor,
		log:      logrus.WithField("component", "mcp"),
	}
}

// Handle 处理一条已解析的 JSON-RPC 请求。caller 必须由调用方在鉴权后填充。
// 返回值为 nil 表示这是 notification（不需要响应）。
func (s *Server) Handle(ctx context.Context, req *Request, caller *CallContext) *Response {
	if req == nil {
		return NewErrorResponse(nil, NewError(CodeInvalidRequest, "nil request"))
	}

	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "ping":
		return NewResponse(req.ID, struct{}{})
	case "tools/list":
		return s.handleToolsList(req, caller)
	case "tools/call":
		return s.handleToolsCall(ctx, req, caller)
	case "notifications/initialized":
		// 客户端通知，无需响应
		return nil
	default:
		if req.IsNotification() {
			return nil
		}
		return NewErrorResponse(req.ID, NewError(CodeMethodNotFound, "method not found: "+req.Method))
	}
}

// ----- initialize -----

type initializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ClientInfo      map[string]any `json:"clientInfo,omitempty"`
	Capabilities    map[string]any `json:"capabilities,omitempty"`
}

type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	ServerInfo      ServerInfo     `json:"serverInfo"`
	Capabilities    map[string]any `json:"capabilities"`
	Instructions    string         `json:"instructions,omitempty"`
}

func (s *Server) handleInitialize(req *Request) *Response {
	var p initializeParams
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &p)
	}

	caps := map[string]any{
		"tools": map[string]any{
			// 工具列表不会动态变化（注册一次），不发送 list_changed 通知
			"listChanged": false,
		},
	}

	res := initializeResult{
		ProtocolVersion: ProtocolVersion,
		ServerInfo:      s.Info,
		Capabilities:    caps,
		Instructions: "sslcat 内置 MCP 服务。可用工具通过 tools/list 查询。" +
			"破坏性工具会在描述中标注 [destructive]，调用前请向用户确认。",
	}
	return NewResponse(req.ID, res)
}

// ----- tools/list -----

type toolDescriptor struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations *toolAnnots     `json:"annotations,omitempty"`
}

type toolAnnots struct {
	Destructive bool   `json:"destructiveHint,omitempty"`
	ReadOnly    bool   `json:"readOnlyHint,omitempty"`
	Scope       string `json:"scope,omitempty"` // 自定义字段，方便 AI 客户端理解
}

type toolsListResult struct {
	Tools []toolDescriptor `json:"tools"`
}

func (s *Server) handleToolsList(req *Request, caller *CallContext) *Response {
	tools := s.Registry.ListTools()
	out := make([]toolDescriptor, 0, len(tools))
	for _, t := range tools {
		// 调用方 scope 不足的 tool 也列出来，但客户端可以根据 annotations 决定是否展示。
		// 实际调用时鉴权层再拦截。
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out = append(out, toolDescriptor{
			Name:        t.Name,
			Title:       t.Title,
			Description: t.Description,
			InputSchema: schema,
			Annotations: &toolAnnots{
				Destructive: t.Destructive,
				ReadOnly:    !t.Destructive && t.Scope == ScopeRead,
				Scope:       string(t.Scope),
			},
		})
	}
	_ = caller
	return NewResponse(req.ID, toolsListResult{Tools: out})
}

// ----- tools/call -----

type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

func (s *Server) handleToolsCall(ctx context.Context, req *Request, caller *CallContext) *Response {
	var p toolsCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return NewErrorResponse(req.ID, NewError(CodeInvalidParams, "invalid params: "+err.Error()))
	}
	if p.Name == "" {
		return NewErrorResponse(req.ID, NewError(CodeInvalidParams, "tool name required"))
	}
	tool, ok := s.Registry.GetTool(p.Name)
	if !ok {
		return NewErrorResponse(req.ID, NewError(CodeMethodNotFound, "tool not found: "+p.Name))
	}

	if caller == nil {
		caller = &CallContext{}
	}
	if !hasScope(caller.Scopes, tool.Scope) {
		s.audit(caller, tool, p.Arguments, "forbidden", 0)
		s.observe(tool.Name, "forbidden", 0)
		return NewErrorResponse(req.ID, NewError(CodeForbidden,
			fmt.Sprintf("scope required: %s", tool.Scope)))
	}

	// destructive tool 的二次确认：
	//   - 客户端可在 arguments 中带 "confirm": "<token>"；
	//   - 若 ConfirmGate 命中并消费，则 Confirmed=true，handler 真正执行；
	//   - 否则 server 生成新 token 并放进 CallContext.ConfirmToken，
	//     handler 负责返回预演并把 token 透传给客户端。
	if tool.Destructive && s.Confirm != nil {
		confirmToken := extractConfirm(p.Arguments)
		if confirmToken != "" && s.Confirm.Consume(confirmToken, tool.Name, p.Arguments, caller) {
			caller.Confirmed = true
		} else {
			caller.Confirmed = false
			caller.ConfirmToken = s.Confirm.Issue(tool.Name, p.Arguments, caller)
		}
		if s.Metrics != nil {
			s.Metrics.SetPendingConfirmations(s.Confirm.PendingCount())
		}
	} else {
		caller.Confirmed = true
	}

	start := time.Now()
	result, err := tool.Handler(ctx, p.Arguments, caller)
	latency := time.Since(start)
	if err != nil {
		s.audit(caller, tool, p.Arguments, "error: "+err.Error(), latency)
		s.observe(tool.Name, "error", latency.Seconds())
		// 业务层错误用 isError=true 返回 tool result，而非协议层 error，
		// 这样 AI 客户端可以把错误内容呈现给用户。
		return NewResponse(req.ID, ErrorResult("tool error: "+err.Error()))
	}
	status := statusFromResult(result)
	if tool.Destructive && !caller.Confirmed {
		status = "pending_confirm"
	}
	s.audit(caller, tool, p.Arguments, status, latency)
	s.observe(tool.Name, status, latency.Seconds())
	return NewResponse(req.ID, result)
}

func (s *Server) observe(tool, status string, latencySec float64) {
	if s.Metrics != nil {
		s.Metrics.ObserveToolCall(tool, status, latencySec)
	}
}

// extractConfirm 从 arguments 中读取 "confirm" 字段（字符串）。其它类型/缺失返回 ""。
func extractConfirm(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	v, ok := m["confirm"]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return ""
	}
	return s
}

func statusFromResult(r ToolResult) string {
	if r.IsError {
		return "tool_error"
	}
	return "ok"
}

func (s *Server) audit(caller *CallContext, tool *Tool, args json.RawMessage, status string, latency time.Duration) {
	if s.Auditor == nil {
		return
	}
	s.Auditor.Log(AuditEntry{
		Time:      time.Now(),
		TokenName: caller.TokenName,
		IP:        caller.IP,
		Tool:      tool.Name,
		Args:      args,
		Status:    status,
		LatencyMS: latency.Milliseconds(),
	})
}

func hasScope(have []Scope, need Scope) bool {
	if need == "" {
		return true
	}
	for _, s := range have {
		if s == ScopeAdmin || s == need {
			return true
		}
	}
	return false
}
