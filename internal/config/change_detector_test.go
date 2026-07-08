package config

import "testing"

func TestChangeDetectorDetectsSSLChallengeMethods(t *testing.T) {
	oldConfig := getDefaultConfig()
	newConfig := getDefaultConfig()
	oldConfig.SSL.ChallengeMethods = []string{"http-01"}
	newConfig.SSL.ChallengeMethods = []string{"http-01", "dns-01"}

	detector := NewChangeDetector()
	changes := detector.DetectChanges(oldConfig, newConfig)

	var found bool
	for _, change := range changes {
		if change.Field != "SSL.ChallengeMethods" {
			continue
		}
		found = true
		if change.Level != SoftReload {
			t.Fatalf("SSL.ChallengeMethods change level = %s, want %s", change.Level, SoftReload)
		}
	}

	if !found {
		t.Fatalf("SSL.ChallengeMethods change was not detected: %#v", changes)
	}
}

func TestChangeDetectorDetectsUnlistedConfigSection(t *testing.T) {
	oldConfig := getDefaultConfig()
	newConfig := getDefaultConfig()
	newConfig.CDNCache.Enabled = !oldConfig.CDNCache.Enabled

	detector := NewChangeDetector()
	changes := detector.DetectChanges(oldConfig, newConfig)

	var found bool
	for _, change := range changes {
		if change.Field != "CDNCache" {
			continue
		}
		found = true
		if change.Level != SoftReload {
			t.Fatalf("CDNCache change level = %s, want %s", change.Level, SoftReload)
		}
	}

	if !found {
		t.Fatalf("CDNCache change was not detected: %#v", changes)
	}
}
