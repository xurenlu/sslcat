package mcp

import (
	"testing"
)

func newTestRegistry(t *testing.T) *TaskRegistry {
	t.Helper()
	r := NewTaskRegistry()
	t.Cleanup(r.Close)
	return r
}

func TestTaskRegistry_CreateAndGet(t *testing.T) {
	r := newTestRegistry(t)
	task := r.Create("cert_issue", "alice", map[string]any{"domain": "a.com"})
	if task.ID == "" {
		t.Fatal("expected non-empty id")
	}
	if task.Status != TaskPending {
		t.Fatalf("status=%s, want pending", task.Status)
	}
	got, ok := r.Get(task.ID, &CallContext{TokenName: "alice", Scopes: []Scope{ScopeRead}})
	if !ok {
		t.Fatal("owner should be able to Get own task")
	}
	if got.ID != task.ID {
		t.Errorf("id mismatch")
	}
}

func TestTaskRegistry_OwnerIsolation(t *testing.T) {
	r := newTestRegistry(t)
	task := r.Create("cert_issue", "alice", nil)

	// bob 不能读 alice 的任务
	_, ok := r.Get(task.ID, &CallContext{TokenName: "bob", Scopes: []Scope{ScopeRead}})
	if ok {
		t.Fatal("non-owner should NOT see task")
	}

	// admin scope 可读
	_, ok = r.Get(task.ID, &CallContext{TokenName: "bob", Scopes: []Scope{ScopeAdmin}})
	if !ok {
		t.Fatal("admin should see any task")
	}

	// nil caller 表示内部调用（如 GC、metrics），放行。
	if _, ok := r.Get(task.ID, nil); !ok {
		t.Fatal("nil caller (internal call) should pass")
	}
}

func TestTaskRegistry_List(t *testing.T) {
	r := newTestRegistry(t)
	r.Create("cert_issue", "alice", nil)
	r.Create("cert_renew", "alice", nil)
	r.Create("cert_issue", "bob", nil)

	aliceCaller := &CallContext{TokenName: "alice", Scopes: []Scope{ScopeRead}}
	list := r.List(aliceCaller, "", 0)
	if len(list) != 2 {
		t.Fatalf("alice should see 2 tasks, got %d", len(list))
	}
	for _, x := range list {
		if x.OwnerName != "alice" {
			t.Errorf("got non-alice task: %s", x.OwnerName)
		}
	}

	// admin 看全部
	adminCaller := &CallContext{TokenName: "ops", Scopes: []Scope{ScopeAdmin}}
	if got := r.List(adminCaller, "", 0); len(got) != 3 {
		t.Errorf("admin should see 3 tasks, got %d", len(got))
	}
}

func TestTaskRegistry_StatusFilter(t *testing.T) {
	r := newTestRegistry(t)
	a := r.Create("x", "alice", nil)
	b := r.Create("x", "alice", nil)
	r.MarkSucceeded(a.ID, nil)
	r.MarkFailed(b.ID, "oops")

	caller := &CallContext{TokenName: "alice", Scopes: []Scope{ScopeRead}}
	if l := r.List(caller, TaskSucceeded, 0); len(l) != 1 || l[0].ID != a.ID {
		t.Errorf("succeeded filter wrong: %+v", l)
	}
	if l := r.List(caller, TaskFailed, 0); len(l) != 1 || l[0].ID != b.ID {
		t.Errorf("failed filter wrong: %+v", l)
	}
}

func TestTaskRegistry_AppendEvent(t *testing.T) {
	r := newTestRegistry(t)
	task := r.Create("cert_issue", "alice", nil)

	// 追加事件应把 status 推进到 running
	r.AppendEvent(task.ID, TaskEvent{Progress: 20, Message: "checking dns"})
	got, _ := r.Get(task.ID, &CallContext{TokenName: "alice", Scopes: []Scope{ScopeRead}})
	if got.Status != TaskRunning {
		t.Errorf("expected running, got %s", got.Status)
	}
	if got.Progress != 20 {
		t.Errorf("progress=%d, want 20", got.Progress)
	}
	if len(got.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(got.Events))
	}
}

func TestTaskRegistry_EventCap(t *testing.T) {
	r := newTestRegistry(t)
	r.maxEvt = 5
	task := r.Create("cert_issue", "alice", nil)
	for i := 0; i < 20; i++ {
		r.AppendEvent(task.ID, TaskEvent{Progress: i, Message: "tick"})
	}
	got, _ := r.Get(task.ID, &CallContext{TokenName: "alice", Scopes: []Scope{ScopeRead}})
	if len(got.Events) != 5 {
		t.Errorf("expected events capped at 5, got %d", len(got.Events))
	}
}

func TestTaskRegistry_MarkSucceededFailed(t *testing.T) {
	r := newTestRegistry(t)
	task := r.Create("cert_issue", "alice", nil)
	r.MarkSucceeded(task.ID, map[string]any{"domain": "x.com"})
	got, _ := r.Get(task.ID, &CallContext{TokenName: "alice", Scopes: []Scope{ScopeRead}})
	if got.Status != TaskSucceeded || got.Progress != 100 {
		t.Errorf("succeeded state wrong: %+v", got)
	}
	if got.Result["domain"] != "x.com" {
		t.Errorf("result not stored: %+v", got.Result)
	}

	r.MarkFailed(task.ID, "boom")
	got, _ = r.Get(task.ID, &CallContext{TokenName: "alice", Scopes: []Scope{ScopeRead}})
	if got.Status != TaskFailed || got.Error != "boom" {
		t.Errorf("failed state wrong: %+v", got)
	}
}
