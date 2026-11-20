package cli

import (
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestRedactedStaticSitesRemovesBasicAuthPasswordHash(t *testing.T) {
	original := []config.StaticSite{
		{
			Domain: "share.example.com",
			BasicAuth: &config.StaticSiteBasicAuth{
				Enabled:      true,
				Username:     "subscriber",
				PasswordHash: "sensitive-hash",
			},
		},
	}

	redacted := redactedStaticSites(original)
	if redacted[0].BasicAuth.PasswordHash != "" {
		t.Fatal("redacted site still contains the password hash")
	}
	if original[0].BasicAuth.PasswordHash != "sensitive-hash" {
		t.Fatal("redaction mutated the original configuration")
	}
}
