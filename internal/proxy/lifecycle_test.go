package proxy

import (
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestEdgeRoutingManagerStopIsIdempotent(t *testing.T) {
	m := NewEdgeRoutingManager(&EdgeRoutingConfig{
		Enabled:             false,
		HealthCheckInterval: time.Minute,
		HealthCheckTimeout:  time.Second,
	}, nil)

	m.Stop()
	m.Stop()
}

func TestServiceMeshManagerStopIsIdempotent(t *testing.T) {
	m := NewServiceMeshManager(&ServiceMeshConfig{
		Enabled:        true,
		Type:           ServiceMeshIstio,
		ConnectTimeout: time.Second,
		RequestTimeout: time.Second,
	}, nil, &config.Config{})
	if m == nil {
		t.Fatal("service mesh manager should be created")
	}

	m.Stop()
	m.Stop()
}
