package config

import (
	"encoding/json"
	"testing"
)

func TestSSLAutoRenew_OmittedMeansTrue(t *testing.T) {
	const raw = `{
		"ssl": {
			"email": "a@b.c",
			"cert_dir": "./data/certs",
			"key_dir": "./data/keys",
			"disable_self_signed": true
		}
	}`
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.SSL.IsAutoRenewEnabled() {
		t.Fatal("omitted auto_renew should default to true")
	}
	if cfg.SSL.AutoRenew != nil {
		t.Fatal("omitted auto_renew should leave AutoRenew nil")
	}
}

func TestSSLAutoRenew_ExplicitFalse(t *testing.T) {
	const raw = `{
		"ssl": {
			"auto_renew": false,
			"disable_self_signed": true
		}
	}`
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SSL.IsAutoRenewEnabled() {
		t.Fatal("explicit false must disable auto renew")
	}
}
