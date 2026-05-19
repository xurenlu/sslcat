package ssl

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()

	tmp := t.TempDir()
	cfg := &config.Config{}
	cfg.SSL.CertDir = filepath.Join(tmp, "certs")
	cfg.SSL.KeyDir = filepath.Join(tmp, "keys")
	cfg.SSL.DisableSelfSigned = true

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)

	return m
}

func TestProgressChannelIsExclusivePerDomain(t *testing.T) {
	m := newTestManager(t)

	ch, created := m.TryCreateProgressChannel("example.com")
	if !created || ch == nil {
		t.Fatal("first progress channel should be created")
	}

	if second, created := m.TryCreateProgressChannel("example.com"); created || second != nil {
		t.Fatal("second same-domain progress channel should be rejected while first is active")
	}

	other, created := m.TryCreateProgressChannel("other.example.com")
	if !created || other == nil {
		t.Fatal("different domain should get an independent progress channel")
	}
}

func TestCloseProgressChannelIfMatchProtectsNewOwner(t *testing.T) {
	m := newTestManager(t)

	first, created := m.TryCreateProgressChannel("example.com")
	if !created {
		t.Fatal("first progress channel should be created")
	}
	if !m.CloseProgressChannelIfMatch("example.com", first) {
		t.Fatal("owner should be able to close its progress channel")
	}

	second, created := m.TryCreateProgressChannel("example.com")
	if !created {
		t.Fatal("second progress channel should be created after first is closed")
	}
	if m.CloseProgressChannelIfMatch("example.com", first) {
		t.Fatal("stale owner must not close the current progress channel")
	}

	got, ok := m.GetProgressChannel("example.com")
	if !ok || got != second {
		t.Fatal("current progress channel should remain available")
	}
}

func TestSendProgressEventDoesNotBlockWhenBufferFull(t *testing.T) {
	m := newTestManager(t)

	ch, created := m.TryCreateProgressChannel("example.com")
	if !created {
		t.Fatal("progress channel should be created")
	}

	for i := 0; i < cap(ch)+10; i++ {
		m.sendProgressEvent("example.com", CertProgressEvent{
			Domain:    "example.com",
			Status:    "checking_dns",
			Timestamp: time.Now(),
		})
	}

	if got := len(ch); got != cap(ch) {
		t.Fatalf("channel should stay capped at %d events, got %d", cap(ch), got)
	}
}

func TestStopIsIdempotent(t *testing.T) {
	m := newTestManager(t)

	m.Stop()
	m.Stop()
}

func TestCertRequestLockIsCleanedUp(t *testing.T) {
	m := newTestManager(t)

	unlock := m.lockCertRequest("example.com")
	m.certRequestMu.Lock()
	if got := len(m.certRequestLocks); got != 1 {
		m.certRequestMu.Unlock()
		t.Fatalf("lock map should contain one domain, got %d", got)
	}
	m.certRequestMu.Unlock()

	unlock()

	m.certRequestMu.Lock()
	defer m.certRequestMu.Unlock()
	if got := len(m.certRequestLocks); got != 0 {
		t.Fatalf("lock map should be cleaned after unlock, got %d", got)
	}
}
