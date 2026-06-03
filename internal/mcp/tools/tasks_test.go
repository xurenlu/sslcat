package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xurenlu/sslcat/internal/mcp"
)

func TestTaskStatusTool_OwnerIsolation(t *testing.T) {
	reg := mcp.NewRegistry()
	tasks := mcp.NewTaskRegistry()
	defer tasks.Close()
	deps := &Deps{Tasks: tasks}
	if err := RegisterTaskReaders(reg, deps); err != nil {
		t.Fatalf("register: %v", err)
	}

	// alice 创建任务
	task := tasks.Create("cert_issue", "alice", nil)

	tool, _ := reg.GetTool("task_status")

	// bob 不能查
	bob := &mcp.CallContext{TokenName: "bob", Scopes: []mcp.Scope{mcp.ScopeRead}}
	res, _ := tool.Handler(context.Background(),
		json.RawMessage(`{"task_id":"`+task.ID+`"}`), bob)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "not found") {
		t.Errorf("bob should not see alice's task, got %+v", res)
	}

	// alice 可以查
	alice := &mcp.CallContext{TokenName: "alice", Scopes: []mcp.Scope{mcp.ScopeRead}}
	res, _ = tool.Handler(context.Background(),
		json.RawMessage(`{"task_id":"`+task.ID+`"}`), alice)
	if res.IsError {
		t.Errorf("alice should see own task, got error: %s", res.Content[0].Text)
	}
}

func TestTaskStatusTool_IncludeEventsOptOut(t *testing.T) {
	reg := mcp.NewRegistry()
	tasks := mcp.NewTaskRegistry()
	defer tasks.Close()
	deps := &Deps{Tasks: tasks}
	_ = RegisterTaskReaders(reg, deps)

	task := tasks.Create("cert_issue", "alice", nil)
	tasks.AppendEvent(task.ID, mcp.TaskEvent{Progress: 10, Message: "step 1"})
	tasks.AppendEvent(task.ID, mcp.TaskEvent{Progress: 20, Message: "step 2"})

	tool, _ := reg.GetTool("task_status")
	alice := &mcp.CallContext{TokenName: "alice", Scopes: []mcp.Scope{mcp.ScopeRead}}

	// 默认带 events
	res, _ := tool.Handler(context.Background(),
		json.RawMessage(`{"task_id":"`+task.ID+`"}`), alice)
	var withEvents struct {
		Events []map[string]any `json:"events"`
	}
	_ = json.Unmarshal([]byte(res.Content[0].Text), &withEvents)
	if len(withEvents.Events) != 2 {
		t.Errorf("expected 2 events in default output, got %d body=%s", len(withEvents.Events), res.Content[0].Text)
	}

	// include_events=false
	res, _ = tool.Handler(context.Background(),
		json.RawMessage(`{"task_id":"`+task.ID+`","include_events":false}`), alice)
	var noEvents struct {
		Events []map[string]any `json:"events"`
	}
	_ = json.Unmarshal([]byte(res.Content[0].Text), &noEvents)
	if len(noEvents.Events) != 0 {
		t.Errorf("expected NO events when include_events=false, got %d body=%s", len(noEvents.Events), res.Content[0].Text)
	}
}

func TestTaskListTool_FilterAndIsolation(t *testing.T) {
	reg := mcp.NewRegistry()
	tasks := mcp.NewTaskRegistry()
	defer tasks.Close()
	deps := &Deps{Tasks: tasks}
	_ = RegisterTaskReaders(reg, deps)

	a1 := tasks.Create("cert_issue", "alice", nil)
	a2 := tasks.Create("cert_renew", "alice", nil)
	_ = tasks.Create("cert_issue", "bob", nil)
	tasks.MarkSucceeded(a1.ID, nil)
	tasks.MarkFailed(a2.ID, "boom")

	tool, _ := reg.GetTool("task_list")
	alice := &mcp.CallContext{TokenName: "alice", Scopes: []mcp.Scope{mcp.ScopeRead}}

	// 无过滤：alice 只看到自己的 2 条
	res, _ := tool.Handler(context.Background(), json.RawMessage(`{}`), alice)
	var out struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal([]byte(res.Content[0].Text), &out)
	if out.Total != 2 {
		t.Errorf("alice should see 2 tasks, got %d", out.Total)
	}

	// status=succeeded
	res, _ = tool.Handler(context.Background(), json.RawMessage(`{"status":"succeeded"}`), alice)
	_ = json.Unmarshal([]byte(res.Content[0].Text), &out)
	if out.Total != 1 {
		t.Errorf("expected 1 succeeded task, got %d", out.Total)
	}
}

func TestTaskStatusTool_RequiresID(t *testing.T) {
	reg := mcp.NewRegistry()
	tasks := mcp.NewTaskRegistry()
	defer tasks.Close()
	deps := &Deps{Tasks: tasks}
	_ = RegisterTaskReaders(reg, deps)

	tool, _ := reg.GetTool("task_status")
	res, _ := tool.Handler(context.Background(), json.RawMessage(`{}`),
		&mcp.CallContext{TokenName: "x", Scopes: []mcp.Scope{mcp.ScopeRead}})
	if !res.IsError {
		t.Error("missing task_id should error")
	}
}
