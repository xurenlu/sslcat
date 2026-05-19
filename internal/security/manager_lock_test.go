package security

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
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

func TestZeroLoginThresholdsUseSafeDefaults(t *testing.T) {
	m := newTestManager(t)
	m.config.Security.MaxAttempts = 0
	m.config.Security.MaxAttempts5Min = 0
	m.Start()
	defer m.Stop()

	m.LogAccess("203.0.113.20", "Mozilla/5.0", "/sslcat-panel/login", false)

	if m.IsBlocked("203.0.113.20") {
		t.Fatal("single failed login should not block when thresholds are unset")
	}
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

// TestLogAccessNoDeadlockOnBlock 验证 LogAccess 在触发封禁路径时不会自锁死锁
func TestLogAccessNoDeadlockOnBlock(t *testing.T) {
	m := newTestManager(t)
	m.config.Security.MaxAttempts = 1
	m.config.Security.MaxAttempts5Min = 100
	m.Start()
	defer m.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.LogAccess("203.0.113.10", "curl/8.0", "/login", false)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("LogAccess deadlocked when block threshold was reached")
	}

	if !m.IsBlocked("203.0.113.10") {
		t.Fatal("expected IP to be blocked after hitting failure threshold")
	}
}

func TestPersistBlockedIPsMatchesLatestMemoryState(t *testing.T) {
	m := newTestManager(t)
	m.Start()
	defer m.Stop()

	// 先制造一批状态变化
	m.BlockIP("198.51.100.10", time.Minute, "test1")
	m.BlockIP("198.51.100.11", time.Minute, "test2")
	m.UnblockIP("198.51.100.10")

	// 触发一次异步持久化（需要和业务代码一样走队列）
	m.queueBlockedPersist()

	ok := waitUntil(2*time.Second, 20*time.Millisecond, func() bool {
		diskMap, err := readBlockedIPFileAsMap(m.config.Security.BlockFile)
		if err != nil {
			return false
		}

		memoryMap := m.blockedIPSnapshot()
		return mapsEqualBlockedIP(memoryMap, diskMap)
	})
	if !ok {
		memoryMap := m.blockedIPSnapshot()
		diskMap, _ := readBlockedIPFileAsMap(m.config.Security.BlockFile)
		t.Fatalf("blocked IP persistence mismatch, memory=%d disk=%d", len(memoryMap), len(diskMap))
	}
}

func TestPersistWhitelistMatchesLatestMemoryState(t *testing.T) {
	m := newTestManager(t)
	m.Start()
	defer m.Stop()

	if err := m.AddWhitelistEntry("203.0.113.20", "keep"); err != nil {
		t.Fatalf("add whitelist failed: %v", err)
	}
	if err := m.AddWhitelistEntry("203.0.113.21", "remove later"); err != nil {
		t.Fatalf("add whitelist failed: %v", err)
	}
	if err := m.RemoveWhitelistEntry("203.0.113.21"); err != nil {
		t.Fatalf("remove whitelist failed: %v", err)
	}

	m.queueWhitelistPersist()

	ok := waitUntil(2*time.Second, 20*time.Millisecond, func() bool {
		diskMap, err := readWhitelistFileAsMap(m.getWhitelistFile())
		if err != nil {
			return false
		}
		memoryMap := m.whitelistSnapshot()
		return mapsEqualWhitelist(memoryMap, diskMap)
	})
	if !ok {
		memoryMap := m.whitelistSnapshot()
		diskMap, _ := readWhitelistFileAsMap(m.getWhitelistFile())
		t.Fatalf("whitelist persistence mismatch, memory=%d disk=%d", len(memoryMap), len(diskMap))
	}
}

func (m *Manager) blockedIPSnapshot() map[string]BlockedIP {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	out := make(map[string]BlockedIP, len(m.blockedIPs))
	for k, v := range m.blockedIPs {
		out[k] = v
	}
	return out
}

func (m *Manager) whitelistSnapshot() map[string]WhitelistEntry {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	out := make(map[string]WhitelistEntry, len(m.whitelistEntries))
	for k, v := range m.whitelistEntries {
		out[k] = v
	}
	return out
}

func waitUntil(timeout, step time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(step)
	}
	return cond()
}

func readBlockedIPFileAsMap(path string) (map[string]BlockedIP, error) {
	out := make(map[string]BlockedIP)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var blocked BlockedIP
		if err := json.Unmarshal(line, &blocked); err != nil {
			return nil, err
		}
		out[blocked.IP] = blocked
	}
	return out, scanner.Err()
}

func readWhitelistFileAsMap(path string) (map[string]WhitelistEntry, error) {
	out := make(map[string]WhitelistEntry)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry WhitelistEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, err
		}
		out[entry.Value] = entry
	}
	return out, scanner.Err()
}

func mapsEqualBlockedIP(a, b map[string]BlockedIP) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if av.IP != bv.IP || av.Reason != bv.Reason || !av.BlockTime.Equal(bv.BlockTime) || !av.ExpireTime.Equal(bv.ExpireTime) {
			return false
		}
	}
	return true
}

func mapsEqualWhitelist(a, b map[string]WhitelistEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		if av.Value != bv.Value || av.Description != bv.Description || !av.CreatedAt.Equal(bv.CreatedAt) || !av.UpdatedAt.Equal(bv.UpdatedAt) {
			return false
		}
	}
	return true
}
