package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/mcp"
	"github.com/xurenlu/sslcat/internal/mcp/logview"
)

var errorLogListSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "kind": {"type": "string", "description": "按日志来源类型过滤：internal/proxy/static/php"},
    "domain": {"type": "string", "description": "按站点域名过滤"}
  },
  "additionalProperties": false
}`)

var errorLogTailSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "id": {"type": "string", "description": "日志源 ID，例如 internal、proxy:example.com、static:example.com、php:example.com"},
    "kind": {"type": "string", "description": "日志来源类型：internal/proxy/static/php；未传 id 时可配合 domain 使用"},
    "domain": {"type": "string", "description": "站点域名过滤；未传 id 时用于选择站点日志源，读取时也用于行过滤"},
    "keyword": {"type": "string", "description": "按日志行关键字过滤"},
    "since": {"type": "string", "description": "仅保留该时间之后的日志，支持 10m/1h 或 RFC3339"},
    "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "description": "返回行数，默认 200，最大 2000"},
    "max_bytes": {"type": "integer", "minimum": 1024, "maximum": 4194304, "description": "从文件尾部读取的最大字节数，默认 1MB，最大 4MB"}
  },
  "additionalProperties": false
}`)

type errorLogListArgs struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
}

type errorLogTailArgs struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Domain   string `json:"domain"`
	Keyword  string `json:"keyword"`
	Since    string `json:"since"`
	Limit    int    `json:"limit"`
	MaxBytes int64  `json:"max_bytes"`
}

func errorLogListTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "error_log_list",
		Title:       "列出错误日志源",
		Description: "列出 sslcat 内部错误日志和所有站点（proxy/static/php）的 error log 配置、启用状态、文件大小和更新时间。",
		InputSchema: errorLogListSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p errorLogListArgs
			if len(args) > 0 {
				_ = json.Unmarshal(args, &p)
			}
			kind := strings.ToLower(strings.TrimSpace(p.Kind))
			domain := strings.ToLower(strings.TrimSpace(p.Domain))
			all := logview.ListSources(d.Config)
			out := make([]logview.Source, 0, len(all))
			for _, src := range all {
				if kind != "" && src.Kind != kind {
					continue
				}
				if domain != "" && !strings.Contains(strings.ToLower(src.Domain), domain) {
					continue
				}
				out = append(out, src)
			}
			return mcp.TextResult(map[string]any{
				"total":   len(out),
				"sources": out,
			}), nil
		},
	}
}

func errorLogTailTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "error_log_tail",
		Title:       "读取近期错误日志",
		Description: "读取 sslcat 内部错误日志或指定站点 error log 的尾部内容；默认只读最后 1MB，避免大日志阻塞 MCP。",
		InputSchema: errorLogTailSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p errorLogTailArgs
			if len(args) > 0 {
				_ = json.Unmarshal(args, &p)
			}
			src, ok := logview.FindSource(d.Config, p.ID, p.Kind, p.Domain)
			if !ok {
				return mcp.ErrorResult("error log source not found"), nil
			}
			since, err := logview.ParseSince(strings.TrimSpace(p.Since), time.Now())
			if err != nil {
				return mcp.ErrorResult(fmt.Sprintf("invalid since: %v", err)), nil
			}
			res, err := logview.ReadTail(src, logview.TailOptions{
				Limit:    p.Limit,
				MaxBytes: p.MaxBytes,
				Since:    since,
				Domain:   p.Domain,
				Keyword:  p.Keyword,
			})
			if err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}
			return mcp.TextResult(res), nil
		},
	}
}
