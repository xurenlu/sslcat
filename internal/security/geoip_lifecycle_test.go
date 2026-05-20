package security

import (
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestGeoIPStopAutoUpdateIsIdempotent(t *testing.T) {
	g, err := NewGeoIPService(config.GeoBlockingConfig{})
	if err != nil {
		t.Fatal(err)
	}

	g.StopAutoUpdate()
	g.StopAutoUpdate()
}
