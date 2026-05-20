package report

import (
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestReportSchedulerStopIsIdempotent(t *testing.T) {
	scheduler := NewReportScheduler(nil, &config.ReportConfig{})

	scheduler.Stop()
	scheduler.Stop()

	assertReportSchedulerChannelClosed(t, scheduler.stopChan, "scheduler stopChan")
}

func TestReportSchedulerInitialWaitIsInterruptible(t *testing.T) {
	scheduler := NewReportScheduler(nil, &config.ReportConfig{})
	result := make(chan bool, 1)

	go func() {
		result <- scheduler.waitForFirstRun(time.Hour, "测试报告")
	}()

	time.Sleep(10 * time.Millisecond)
	scheduler.Stop()

	select {
	case shouldRun := <-result:
		if shouldRun {
			t.Fatal("waitForFirstRun returned true after scheduler stopped")
		}
	case <-time.After(time.Second):
		t.Fatal("waitForFirstRun did not return promptly after scheduler stopped")
	}
}

func assertReportSchedulerChannelClosed(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("%s was not closed", name)
	}
}
