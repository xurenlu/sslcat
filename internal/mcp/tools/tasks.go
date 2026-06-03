package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xurenlu/sslcat/internal/mcp"
)

// RegisterTaskReaders 注册 task_status / task_list（只读，read scope）。
func RegisterTaskReaders(reg *mcp.Registry, d *Deps) error {
	if err := reg.RegisterTool(taskStatusTool(d)); err != nil {
		return err
	}
	if err := reg.RegisterTool(taskListTool(d)); err != nil {
		return err
	}
	return nil
}

// ---------- task_status ----------

var taskStatusSchema = json.RawMessage(`{
  "type": "object",
  "required": ["task_id"],
  "properties": {
    "task_id":      {"type": "string", "description": "由 cert_issue / cert_renew 等异步工具返回的 task_id"},
    "include_events": {"type": "boolean", "description": "是否返回事件历史（默认 true）"}
  },
  "additionalProperties": false
}`)

type taskStatusArgs struct {
	TaskID        string `json:"task_id"`
	IncludeEvents *bool  `json:"include_events,omitempty"`
}

func taskStatusTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "task_status",
		Title:       "查询长任务状态",
		Description: "查询异步任务（如 cert_issue）的当前状态、进度与事件历史。AI 客户端可循环调用直到 status=succeeded/failed。每个 token 只能查到自己创建的任务（admin scope 可查全部）。",
		InputSchema: taskStatusSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p taskStatusArgs
			if err := json.Unmarshal(args, &p); err != nil {
				return mcp.ErrorResult("invalid params: " + err.Error()), nil
			}
			if p.TaskID == "" {
				return mcp.ErrorResult("task_id required"), nil
			}
			if d.Tasks == nil {
				return mcp.ErrorResult("task registry not available"), nil
			}
			t, ok := d.Tasks.Get(p.TaskID, caller)
			if !ok {
				return mcp.ErrorResult(fmt.Sprintf("task %q not found (or not visible to current token)", p.TaskID)), nil
			}
			include := true
			if p.IncludeEvents != nil {
				include = *p.IncludeEvents
			}
			if !include {
				t.Events = nil
			}
			return mcp.TextResult(t), nil
		},
	}
}

// ---------- task_list ----------

var taskListSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "status": {"type": "string", "enum": ["pending","running","succeeded","failed"], "description": "按状态过滤（可选）"},
    "limit":  {"type": "integer", "minimum": 1, "maximum": 200, "description": "返回条数上限，默认 50"}
  },
  "additionalProperties": false
}`)

type taskListArgs struct {
	Status string `json:"status,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

func taskListTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "task_list",
		Title:       "列出长任务",
		Description: "列出本 token 创建的异步任务（按 updated_at 倒序）。可按状态过滤。事件历史不展开，需要详情请用 task_status。",
		InputSchema: taskListSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p taskListArgs
			if len(args) > 0 {
				_ = json.Unmarshal(args, &p)
			}
			if d.Tasks == nil {
				return mcp.TextResult(map[string]any{"total": 0, "tasks": []any{}}), nil
			}
			limit := p.Limit
			if limit <= 0 {
				limit = 50
			}
			list := d.Tasks.List(caller, mcp.TaskStatus(p.Status), limit)
			// 简化输出：去掉 events
			out := make([]map[string]any, 0, len(list))
			for _, t := range list {
				out = append(out, map[string]any{
					"id":         t.ID,
					"tool":       t.Tool,
					"status":     t.Status,
					"progress":   t.Progress,
					"message":    t.Message,
					"created_at": t.CreatedAt,
					"updated_at": t.UpdatedAt,
					"error":      t.Error,
				})
			}
			return mcp.TextResult(map[string]any{
				"total": len(out),
				"tasks": out,
			}), nil
		},
	}
}
