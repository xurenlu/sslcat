package waf

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestEngineStopIsIdempotentAndStopsChildren(t *testing.T) {
	engine := NewEngine(nil, nil, true)

	engine.Stop()
	engine.Stop()

	assertChannelClosed(t, engine.stopChan, "engine stopChan")
	assertChannelClosed(t, engine.logLimiter.stopChan, "log limiter stopChan")
	assertChannelClosed(t, engine.multiDimBlocker.stopChan, "multi-dimension blocker stopChan")
}

func TestLegacyWAFRateLimiterStopIsIdempotent(t *testing.T) {
	limiter := newWAFRateLimiter(true, 60, 10, 60, logrus.NewEntry(logrus.New()))

	limiter.Stop()
	limiter.Stop()

	assertChannelClosed(t, limiter.stopChan, "legacy rate limiter stopChan")
}

func assertChannelClosed(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("%s was not closed", name)
	}
}
