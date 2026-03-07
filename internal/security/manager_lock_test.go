package security

import (
	"sync"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// TestWhitelistConcurrency 测试白名单操作的并发安全性
// 这个测试验证在修改白名单时，IsWhitelisted 不会被长时间阻塞
func TestWhitelistConcurrency(t *testing.T) {
	// 创建一个临时配置
	cfg := &config.Config{
		Security: config.SecurityConfig{
			BlockDurationStr:     "5m",
			CleanupIntervalMin:   5, // 5分钟清理间隔
		},
		Server: config.ServerConfig{
			DataDir: t.TempDir(),
		},
	}

	m := NewManager(cfg)
	m.Start()
	defer m.Stop()

	// 先添加一些白名单条目
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

	// 等待异步保存完成
	time.Sleep(100 * time.Millisecond)

	// 并发测试：多个 goroutine 同时读取白名单
	const numReaders = 100
	const numWriters = 10
	var wg sync.WaitGroup

	// 记录读操作的最大延迟
	maxReadDelay := time.Duration(0)
	delayMutex := sync.Mutex{}

	// 启动读操作
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()

			for j := 0; j < 10; j++ {
				start := time.Now()
				// 这个调用应该快速返回，不会被写操作阻塞
				_ = m.IsWhitelisted("192.168.1.50")
				delay := time.Since(start)

				delayMutex.Lock()
				if delay > maxReadDelay {
					maxReadDelay = delay
				}
				delayMutex.Unlock()

				// 添加小随机延迟，增加并发竞争
				time.Sleep(time.Duration(readerID) * time.Microsecond)
			}
		}(i)
	}

	// 启动写操作
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()

			// 添加和删除白名单条目
			value := "203.0.113." + string(rune('0'+writerID))

			// 添加
			_ = m.AddWhitelistEntry(value, "Concurrent test")
			time.Sleep(10 * time.Millisecond)

			// 删除
			_ = m.RemoveWhitelistEntry(value)
		}(i)
	}

	// 等待所有操作完成
	wg.Wait()

	t.Logf("Max read delay: %v", maxReadDelay)

	// 验证读操作没有被长时间阻塞
	// 在修复前，读操作可能被阻塞数秒
	// 修复后，读操作应该在 10ms 内完成
	if maxReadDelay > 100*time.Millisecond {
		t.Errorf("Read operations were blocked too long: %v (expected < 100ms)", maxReadDelay)
	}

	// 验证白名单仍然有效
	if !m.IsWhitelisted("192.168.1.100") {
		t.Error("Whitelist entry 192.168.1.100 should still exist")
	}

	if !m.IsWhitelisted("172.16.5.5") {
		t.Error("Whitelist entry 172.16.0.0/16 should match 172.16.5.5")
	}
}
