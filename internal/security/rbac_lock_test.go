package security

import (
	"sync"
	"testing"
	"time"
)

// TestRBACEvaluateRolePolicyNoDeadlock 验证基于角色的策略匹配在并发写入压力下不会卡死
func TestRBACEvaluateRolePolicyNoDeadlock(t *testing.T) {
	m := NewRBACManager()
	if err := m.AssignRole("alice", "admin"); err != nil {
		t.Fatalf("failed to assign role: %v", err)
	}

	m.mutex.Lock()
	m.policies["policy-role-admin"] = &Policy{
		ID:        "policy-role-admin",
		Name:      "admin policy",
		Effect:    "allow",
		Subjects:  []string{"role:管理员"},
		Resources: []string{"system"},
		Actions:   []string{"read"},
		Enabled:   true,
	}
	m.mutex.Unlock()

	stopWriters := make(chan struct{})
	var writerWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			for {
				select {
				case <-stopWriters:
					return
				default:
					m.mutex.Lock()
					if role := m.roles["admin"]; role != nil {
						role.UpdatedAt = time.Now()
					}
					m.mutex.Unlock()
				}
			}
		}()
	}

	done := make(chan struct{})
	errCh := make(chan string, 1)
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			decision := m.CheckAccess(AccessRequest{
				Subject:  "alice",
				Resource: "system",
				Action:   "read",
			})
			if !decision.Allowed {
				select {
				case errCh <- "expected access to be allowed":
				default:
				}
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RBAC role policy evaluation deadlocked under concurrent writes")
	}

	select {
	case msg := <-errCh:
		t.Fatal(msg)
	default:
	}

	close(stopWriters)
	writerWG.Wait()
}
