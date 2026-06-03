package mcp

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// TaskStatus 任务状态。
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskRunning   TaskStatus = "running"
	TaskSucceeded TaskStatus = "succeeded"
	TaskFailed    TaskStatus = "failed"
)

// Task 长任务记录。所有字段通过 TaskRegistry 的方法访问。
type Task struct {
	ID        string                 `json:"id"`
	Tool      string                 `json:"tool"`
	Status    TaskStatus             `json:"status"`
	Progress  int                    `json:"progress"` // 0..100
	Message   string                 `json:"message,omitempty"`
	Result    map[string]any         `json:"result,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Events    []TaskEvent            `json:"events,omitempty"` // 进度事件历史（最近 50 条）
	Metadata  map[string]any         `json:"metadata,omitempty"`
	OwnerName string                 `json:"owner_name"` // 创建方的 token name；list/get 时按它过滤
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// TaskEvent 一条进度事件快照。
type TaskEvent struct {
	Time     time.Time `json:"time"`
	Progress int       `json:"progress"`
	Message  string    `json:"message"`
	Status   string    `json:"status,omitempty"` // 子任务状态：如 "checking_dns"、"using_http01"
}

// TaskRegistry 进程内任务注册表。完成 7 天后自动 GC。
type TaskRegistry struct {
	mu     sync.RWMutex
	tasks  map[string]*Task
	maxEvt int

	stop chan struct{}
}

// NewTaskRegistry 构造任务注册表。
func NewTaskRegistry() *TaskRegistry {
	r := &TaskRegistry{
		tasks:  make(map[string]*Task),
		maxEvt: 50,
		stop:   make(chan struct{}),
	}
	go r.gcLoop()
	return r
}

// Close 停止 GC goroutine（测试场景需要）。
func (r *TaskRegistry) Close() {
	select {
	case <-r.stop:
		// already closed
	default:
		close(r.stop)
	}
}

// Create 新建任务并返回其 ID。
func (r *TaskRegistry) Create(tool, ownerName string, metadata map[string]any) *Task {
	now := time.Now()
	t := &Task{
		ID:        uuid.NewString(),
		Tool:      tool,
		Status:    TaskPending,
		Metadata:  metadata,
		OwnerName: ownerName,
		CreatedAt: now,
		UpdatedAt: now,
	}
	r.mu.Lock()
	r.tasks[t.ID] = t
	r.mu.Unlock()
	return t
}

// Update 安全地修改一个任务。fn 在持锁状态下执行，应保持简短。
func (r *TaskRegistry) Update(id string, fn func(*Task)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tasks[id]
	if !ok {
		return
	}
	fn(t)
	t.UpdatedAt = time.Now()
}

// AppendEvent 追加一条事件，并把 progress/message 同步到 Task 顶层字段。
func (r *TaskRegistry) AppendEvent(id string, e TaskEvent) {
	r.Update(id, func(t *Task) {
		t.Events = append(t.Events, e)
		if len(t.Events) > r.maxEvt {
			t.Events = t.Events[len(t.Events)-r.maxEvt:]
		}
		if e.Progress > 0 {
			t.Progress = e.Progress
		}
		if e.Message != "" {
			t.Message = e.Message
		}
		if t.Status == TaskPending {
			t.Status = TaskRunning
		}
	})
}

// MarkSucceeded 把任务标记为成功。
func (r *TaskRegistry) MarkSucceeded(id string, result map[string]any) {
	r.Update(id, func(t *Task) {
		t.Status = TaskSucceeded
		t.Progress = 100
		t.Result = result
	})
}

// MarkFailed 把任务标记为失败。
func (r *TaskRegistry) MarkFailed(id, errMsg string) {
	r.Update(id, func(t *Task) {
		t.Status = TaskFailed
		t.Error = errMsg
	})
}

// Get 按 ID 查询。
//   - caller 为 nil：表示内部调用（如 GC、指标），放行；
//   - caller 非空：要求 owner 匹配 或 admin scope。
func (r *TaskRegistry) Get(id string, caller *CallContext) (*Task, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tasks[id]
	if !ok {
		return nil, false
	}
	if caller != nil && !canReadTask(caller, t) {
		return nil, false
	}
	// 浅拷贝避免被外部修改
	copy := *t
	return &copy, true
}

// List 列出任务，按 UpdatedAt 倒序。statusFilter 为空表示不过滤。
//   - caller 为 nil：列出全部（内部调用语义）；
//   - caller 非空：只列出 owner 自己创建的（admin 例外）。
func (r *TaskRegistry) List(caller *CallContext, statusFilter TaskStatus, limit int) []*Task {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Task, 0, len(r.tasks))
	for _, t := range r.tasks {
		if caller != nil && !canReadTask(caller, t) {
			continue
		}
		if statusFilter != "" && t.Status != statusFilter {
			continue
		}
		c := *t
		out = append(out, &c)
	}
	// 按 UpdatedAt 倒序
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].UpdatedAt.After(out[i].UpdatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// canReadTask 调用方是否有权读取一个任务。
//   - admin scope：可以；
//   - 否则只能读自己 token name 创建的。
func canReadTask(caller *CallContext, t *Task) bool {
	if caller == nil {
		return false
	}
	for _, s := range caller.Scopes {
		if s == ScopeAdmin {
			return true
		}
	}
	return t.OwnerName != "" && caller.TokenName == t.OwnerName
}

// gcLoop 每小时清理完成超过 7 天的任务。
func (r *TaskRegistry) gcLoop() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case <-t.C:
			r.gc()
		}
	}
}

func (r *TaskRegistry) gc() {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, t := range r.tasks {
		if (t.Status == TaskSucceeded || t.Status == TaskFailed) && t.UpdatedAt.Before(cutoff) {
			delete(r.tasks, id)
		}
	}
}
