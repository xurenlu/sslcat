package threatintel

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestTorExitNodesSourceIsDisabledByDefault(t *testing.T) {
	manager := NewThreatIntelManager(nil)
	manager.initSources()

	source, ok := manager.sources["tor_exit_nodes"]
	if !ok {
		t.Fatal("tor exit nodes source is missing")
	}
	if source.Enabled {
		t.Fatal("tor exit nodes source must be disabled by default")
	}
}

func TestAddIOCUsesBoundedPersistenceWorker(t *testing.T) {
	manager := NewThreatIntelManager(nil)
	manager.startPersistenceWorker()
	defer manager.Stop()

	baseline := runtime.NumGoroutine()
	for i := range iocPersistenceQueueSize * 4 {
		manager.AddIOC(&IOC{
			Value: fmt.Sprintf("198.51.100.%d", i),
			Type:  IOCTypeIP,
		})
	}

	deadline := time.Now().Add(time.Second)
	for len(manager.persistenceQueue) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	if current := runtime.NumGoroutine(); current > baseline+2 {
		t.Fatalf("unexpected goroutine growth: baseline=%d current=%d", baseline, current)
	}
}
