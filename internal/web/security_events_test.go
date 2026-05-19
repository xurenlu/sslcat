package web

import (
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/waf"
)

func TestSecurityEventHubDropsSlowClientSafely(t *testing.T) {
	hub := NewSecurityEventHub()
	client := &SecurityEventClient{
		hub:  hub,
		send: make(chan *SecurityEventMessage),
		id:   "slow-client",
	}

	hub.register <- client
	waitForCondition(t, time.Second, func() bool {
		hub.mu.RLock()
		defer hub.mu.RUnlock()
		return hub.clients[client]
	})

	hub.Broadcast(&waf.AttackEvent{}, "attack")

	waitForCondition(t, time.Second, func() bool {
		hub.mu.RLock()
		defer hub.mu.RUnlock()
		_, ok := hub.clients[client]
		return !ok
	})

	select {
	case _, ok := <-client.send:
		if ok {
			t.Fatal("slow client send channel should be closed")
		}
	default:
		t.Fatal("slow client send channel should be closed")
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
