package proxy

import (
	"net/http"
	"net/http/httputil"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestNewUpstreamTransportUsesBoundedPoolAndTimeouts(t *testing.T) {
	rule := &config.ProxyRule{
		ConnectTimeoutSec:        7,
		KeepAliveTimeoutSec:      11,
		IdleTimeoutSec:           13,
		TLSHandshakeTimeoutSec:   17,
		ExpectContinueTimeoutSec: 19,
		ResponseHeaderTimeoutSec: 23,
		UpstreamHTTP2Enabled:     true,
	}
	proxyConfig := &config.ProxyConfig{
		MaxIdleConns:        600,
		MaxIdleConnsPerHost: 200,
		MaxConnsPerHost:     240,
	}

	transport := newUpstreamTransport(rule, proxyConfig)
	if transport.MaxIdleConns != 600 || transport.MaxIdleConnsPerHost != 200 || transport.MaxConnsPerHost != 240 {
		t.Fatalf("unexpected pool limits: total=%d idle_per_host=%d max_per_host=%d", transport.MaxIdleConns, transport.MaxIdleConnsPerHost, transport.MaxConnsPerHost)
	}
	if transport.IdleConnTimeout != 13*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 13s", transport.IdleConnTimeout)
	}
	if transport.TLSHandshakeTimeout != 17*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 17s", transport.TLSHandshakeTimeout)
	}
	if transport.ExpectContinueTimeout != 19*time.Second {
		t.Fatalf("ExpectContinueTimeout = %v, want 19s", transport.ExpectContinueTimeout)
	}
	if transport.ResponseHeaderTimeout != 23*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want 23s", transport.ResponseHeaderTimeout)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = false, want true")
	}
}

func TestNewUpstreamTransportDefaultsRemainBounded(t *testing.T) {
	transport := newUpstreamTransport(&config.ProxyRule{}, &config.ProxyConfig{})
	if transport.MaxConnsPerHost != defaultMaxConnsPerHost {
		t.Fatalf("MaxConnsPerHost = %d, want %d", transport.MaxConnsPerHost, defaultMaxConnsPerHost)
	}
	if transport.MaxIdleConnsPerHost != defaultMaxIdleConnsPerHost {
		t.Fatalf("MaxIdleConnsPerHost = %d, want %d", transport.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHost)
	}
	if transport.ResponseHeaderTimeout != defaultResponseHeaderTimeoutSec*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v, want %ds", transport.ResponseHeaderTimeout, defaultResponseHeaderTimeoutSec)
	}
}

type closeTrackingTransport struct {
	closed atomic.Bool
}

func (t *closeTrackingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

func (t *closeTrackingTransport) CloseIdleConnections() {
	t.closed.Store(true)
}

func TestCloseProxyIdleConnectionsReachesWrappedTransport(t *testing.T) {
	base := &closeTrackingTransport{}
	proxy := &httputil.ReverseProxy{
		Transport: &loggingTransport{base: base},
	}

	closeProxyIdleConnections(proxy)
	if !base.closed.Load() {
		t.Fatal("wrapped transport did not receive CloseIdleConnections")
	}
}
