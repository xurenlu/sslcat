package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeTestConfig 写入一个合法配置文件并返回路径。
func writeTestConfig(t *testing.T, configFile, port string) {
	t.Helper()
	data := `{
		"server": {
			"host": "0.0.0.0",
			"port": ` + port + `,
			"port_mode": "custom",
			"custom_port": ` + port + `,
			"enable_https": false,
			"log_level": "warn"
		},
		"admin_prefix": "/test-panel"
	}`
	if err := os.WriteFile(configFile, []byte(data), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}
}

// newTestWatcher 创建指向给定配置文件的 watcher。
func newTestWatcher(t *testing.T, configFile string) *ConfigWatcher {
	t.Helper()
	watcher, err := NewConfigWatcher(configFile, nil)
	if err != nil {
		t.Fatalf("failed to create config watcher: %v", err)
	}
	return watcher
}

func TestConfigWatcher_ForceReloadReturnsRealErrorOnParseFailure(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test.conf")

	// 初始写入合法配置
	writeTestConfig(t, configFile, "18081")

	watcher := newTestWatcher(t, configFile)
	defer watcher.Stop()

	// 记录回调次数
	var startCalls, successCalls, errorCalls int32
	watcher.OnReloadStart(func() { atomic.AddInt32(&startCalls, 1) })
	watcher.OnReloadSuccess(func(*Config) { atomic.AddInt32(&successCalls, 1) })
	watcher.OnReloadError(func(error) { atomic.AddInt32(&errorCalls, 1) })

	// 无变化时应返回 nil 且不触发成功/错误回调
	if err := watcher.ForceReload(); err != nil {
		t.Fatalf("unexpected error on unchanged config: %v", err)
	}
	if atomic.LoadInt32(&successCalls) != 0 {
		t.Fatalf("unchanged config should not trigger success callback")
	}
	if atomic.LoadInt32(&errorCalls) != 0 {
		t.Fatalf("unchanged config should not trigger error callback")
	}

	// 写入非法配置，破坏 JSON 语法
	if err := os.WriteFile(configFile, []byte("{ invalid json"), 0644); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	err := watcher.ForceReload()
	if err == nil {
		t.Fatal("expected parse error to be returned, got nil")
	}
	if !strings.Contains(err.Error(), "failed to load new config") {
		t.Fatalf("expected load/parse error, got: %v", err)
	}

	// 成功回调不该触发
	if atomic.LoadInt32(&successCalls) != 0 {
		t.Fatalf("parse failure should not trigger success callback")
	}
	// 错误回调应当触发
	if atomic.LoadInt32(&errorCalls) == 0 {
		t.Fatal("parse failure should trigger error callback")
	}
	// verifier 希望不修改旧配置与哈希
	if watcher.GetConfig() != nil {
		t.Fatalf("old config should be preserved, got %v", watcher.GetConfig())
	}
}

func TestConfigWatcher_ForceReloadPreservesOldOnCallbackFailure(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test.conf")

	writeTestConfig(t, configFile, "8082")
	watcher := newTestWatcher(t, configFile)
	defer watcher.Stop()

	oldHash := watcher.GetLastHash()

	var successCalls, errorCalls int32
	watcher.OnReloadSuccess(func(*Config) { atomic.AddInt32(&successCalls, 1) })
	watcher.OnReloadError(func(error) { atomic.AddInt32(&errorCalls, 1) })

	// 配置变化回调失败
	watcher.OnConfigChange(func(oldConfig, newConfig *Config) error {
		return fmt.Errorf("injected failure")
	})

	// 修改配置文件使哈希变化
	writeTestConfig(t, configFile, "8083")

	err := watcher.ForceReload()
	if err == nil {
		t.Fatal("expected callback failure to be returned, got nil")
	}
	if !strings.Contains(err.Error(), "config change callback failed") {
		t.Fatalf("expected callback failure error, got: %v", err)
	}
	if atomic.LoadInt32(&successCalls) != 0 {
		t.Fatal("failed reload should not trigger success callback")
	}
	if atomic.LoadInt32(&errorCalls) == 0 {
		t.Fatal("failed reload should trigger error callback")
	}

	// 失败后必须保留旧配置与旧哈希
	if watcher.GetConfig() != nil {
		t.Fatalf("old config should be preserved on failure, got %v", watcher.GetConfig())
	}
	if watcher.GetLastHash() != oldHash {
		t.Fatalf("last hash should be preserved on failure, got %q want %q", watcher.GetLastHash(), oldHash)
	}
}

func TestConfigWatcher_ConcurrentForceReloadSerialized(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "test.conf")
	writeTestConfig(t, configFile, "8084")
	watcher := newTestWatcher(t, configFile)
	defer watcher.Stop()

	const callers = 16
	entered := make(chan struct{}, callers)
	release := make(chan struct{})
	var reloadCount atomic.Int32
	watcher.OnConfigChange(func(oldConfig, newConfig *Config) error {
		reloadCount.Add(1)
		entered <- struct{}{}
		<-release
		return nil
	})
	writeTestConfig(t, configFile, "8085")

	start := make(chan struct{})
	errors := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errors <- watcher.ForceReload()
		}()
	}
	close(start)
	releaseReload := sync.OnceFunc(func() { close(release) })
	defer wg.Wait()
	defer releaseReload()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("reload callback did not start")
	}
	select {
	case <-entered:
		t.Fatal("concurrent caller entered reload callback before prior reload completed")
	case <-time.After(50 * time.Millisecond):
	}
	releaseReload()
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if reloadCount.Load() != 1 {
		t.Fatalf("same file change was applied %d times, want once", reloadCount.Load())
	}
}
