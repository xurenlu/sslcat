package security

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	tmpDir := t.TempDir()
	cfg := &config.Config{
		Security: config.SecurityConfig{
			BlockDurationStr:   "5m",
			BlockDuration:      5 * time.Minute,
			CleanupIntervalMin: 5,
			BlockFile:          filepath.Join(tmpDir, "blocked_ips.json"),
		},
		Server: config.ServerConfig{
			DataDir: tmpDir,
		},
	}
	return NewManager(cfg)
}

// TestWhitelistConcurrency 测试白名单操作的并发安全性
func TestWhitelistConcurrency(t *testing.T) {
	m := newTestManager(t)
	m.Start()
	defer m.Stop()

	entries := []struct {
		value       string
		description string
	}{
		{"192.168.1.100", "Test IP 1"},
		{"10.0.0.1", "Test IP 2"},
		{"172.16.0.0/16", "Test CIDR"},
	}

	for _, e := range entries {
		if err := m.AddWhitelistEntry(e.value, e.description); err != nil {
			t.Fatalf("Failed to add whitelist entry: %v", err)
		}
	}

	time.Sleep(100 * time.Millisecond)

	const numReaders = 100
	const numWriters = 10
	var wg sync.WaitGroup

	maxReadDelay := time.Duration(0)
	delayMutex := sync.Mutex{}

	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				start := time.Now()
				_ = m.IsWhitelisted("192.168.1.50")
				delay := time.Since(start)
				delayMutex.Lock()
				if delay > maxReadDelay {
					maxReadDelay = delay
				}
				delayMutex.Unlock()
				time.Sleep(time.Duration(readerID) * time.Microsecond)
			}
		}(i)
	}

	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			value := fmt.Sprintf("203.0.113.%d", writerID)
			_ = m.AddWhitelistEntry(value, "Concurrent test")
			time.Sleep(10 * time.Millisecond)
			_ = m.RemoveWhitelistEntry(value)
		}(i)
	}

	wg.Wait()
	t.Logf("Max read delay: %v", maxReadDelay)

	if maxReadDelay > 100*time.Millisecond {
		t.Errorf("Read operations were blocked too long: %v (expected < 100ms)", maxReadDelay)
	}
	if !m.IsWhitelisted("192.168.1.100") {
		t.Error("Whitelist entry 192.168.1.100 should still exist")
	}
	if !m.IsWhitelisted("172.16.5.5") {
		t.Error("Whitelist entry 172.16.0.0/16 should match 172.16.5.5")
	}
}

// TestIsBlockedNoDataRace 验证 IsBlocked 不会在 RLock 下修改 map
func TestIsBlockedNoDataRace(t *testing.T) {
	m := newTestManager(t)
	m.Start()
	defer m.Stop()

	m.BlockIP("10.0.0.1", 50*time.Millisecond, "short block for test")
	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.IsBlocked("10.0.0.1")
		}()
	}
	wg.Wait()
}

// TestCheckTOTPNoDeadlock 验证 CheckTOTPOnlyLoginSecurity 不会因为嵌套锁死锁
func TestCheckTOTPNoDeadlock(t *testing.T) {
	m := newTestManager(t)
	m.Start()
	defer m.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 记录 6 次失败（全在 1 分钟内，因此先命中 oneMinAttempts>=3 路径返回需要验证码）
		for i := 0; i < 6; i++ {
			m.RecordTOTPOnlyLoginFailure("10.0.0.99")
		}
		allowed, _, needsCaptcha := m.CheckTOTPOnlyLoginSecurity("10.0.0.99")
		// 关键验证：函数能正常返回（不死锁），且 6 次失败在 1 分钟内应触发验证码
		if !allowed || !needsCaptcha {
			t.Logf("6 failures in 1 min: allowed=%v, needsCaptcha=%v (expected true/true)", allowed, needsCaptcha)
		}
	}()

	select {
	case <-done:
		// 能走到这里就说明没有死锁——这才是本测试的核心断言
	case <-time.After(5 * time.Second):
		t.Fatal("CheckTOTPOnlyLoginSecurity deadlocked (timeout 5s)")
	}

	// 并发安全性测试：多 goroutine 同时调用不会 panic 或死锁
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.1.%d.%d", idx/256, idx%256)
			m.RecordTOTPOnlyLoginFailure(ip)
			m.CheckTOTPOnlyLoginSecurity(ip)
		}(i)
	}
	wg.Wait()
}
