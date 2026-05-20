package monitor

import (
	"os"
	"testing"
	"time"
)

func TestMonitorStopsAreIdempotent(t *testing.T) {
	goroutineMonitor := NewGoroutineMonitor(time.Minute)
	goroutineMonitor.Stop()
	goroutineMonitor.Stop()
	assertMonitorChannelClosed(t, goroutineMonitor.stopChan, "goroutine monitor stopChan")

	memoryMonitor := NewMemoryMonitor(MemoryMonitorOptions{CheckInterval: time.Minute})
	memoryMonitor.Stop()
	memoryMonitor.Stop()
	assertMonitorChannelClosed(t, memoryMonitor.stopChan, "memory monitor stopChan")

	performanceMonitor := NewPerformanceMonitor(30 * time.Second)
	performanceMonitor.Stop()
	performanceMonitor.Stop()
	assertMonitorChannelClosed(t, performanceMonitor.stopChan, "performance monitor stopChan")

	watchdogMonitor := NewWatchdogMonitor(WatchdogMonitorOptions{Enabled: true, CheckInterval: time.Minute}, nil)
	watchdogMonitor.Stop()
	watchdogMonitor.Stop()
	assertMonitorChannelClosed(t, watchdogMonitor.stopChan, "watchdog monitor stopChan")
}

func TestMetricsStorageStopIsIdempotent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "metrics_storage_stop_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storage, err := NewMetricsStorage(MetricsStorageOptions{
		Enabled:             true,
		DataDir:             tmpDir,
		SamplingInterval:    time.Minute,
		RetentionDays:       7,
		DetailRetentionDays: 3,
		MaxRows:             100000,
	})
	if err != nil {
		t.Fatalf("创建 MetricsStorage 失败: %v", err)
	}

	storage.Stop()
	storage.Stop()
	assertMonitorChannelClosed(t, storage.stopChan, "metrics storage stopChan")
}

func assertMonitorChannelClosed(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("%s was not closed", name)
	}
}
