package waf

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestMultiDimBlockerNormalizesZeroThresholds(t *testing.T) {
	blocker := newWAFMultiDimBlocker(&MultiDimBlockConfig{
		IPEnabled:     true,
		TLSEnabled:    true,
		SubnetEnabled: true,
	}, logrus.NewEntry(logrus.New()))
	defer blocker.Stop()

	if blocker.config.IPMaxHits != 60 {
		t.Fatalf("IPMaxHits = %d, want 60", blocker.config.IPMaxHits)
	}
	if blocker.config.TLSMaxHits != 120 {
		t.Fatalf("TLSMaxHits = %d, want 120", blocker.config.TLSMaxHits)
	}
	if blocker.config.SubnetThreshold != 10 {
		t.Fatalf("SubnetThreshold = %d, want 10", blocker.config.SubnetThreshold)
	}
	if blocker.config.IPBlockDuration != 600*time.Second {
		t.Fatalf("IPBlockDuration = %s, want 10m", blocker.config.IPBlockDuration)
	}
}

func TestMultiDimBlockerZeroThresholdDoesNotBlockFirstHit(t *testing.T) {
	blocker := newWAFMultiDimBlocker(&MultiDimBlockConfig{
		IPEnabled: true,
	}, logrus.NewEntry(logrus.New()))
	defer blocker.Stop()

	blocker.RecordHit("203.0.113.10", "")

	if blocked, dimension, reason := blocker.IsBlocked("203.0.113.10", ""); blocked {
		t.Fatalf("first hit should not be blocked, dimension=%s reason=%s", dimension, reason)
	}
}
