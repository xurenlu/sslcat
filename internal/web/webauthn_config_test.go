package web

import (
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestResolveWebAuthnRelyingPartyUsesExplicitPublicOrigin(t *testing.T) {
	rpID, rpOrigin, err := resolveWebAuthnRelyingParty(config.ServerConfig{
		Host:             "0.0.0.0",
		WebAuthnRPID:     "h1.niuwoai.com",
		WebAuthnRPOrigin: "https://h1.niuwoai.com",
	})
	if err != nil {
		t.Fatalf("resolve relying party: %v", err)
	}
	if rpID != "h1.niuwoai.com" || rpOrigin != "https://h1.niuwoai.com" {
		t.Fatalf("relying party = %q, %q", rpID, rpOrigin)
	}
}

func TestResolveWebAuthnRelyingPartyRejectsMismatchedOrigin(t *testing.T) {
	_, _, err := resolveWebAuthnRelyingParty(config.ServerConfig{
		WebAuthnRPID:     "h1.niuwoai.com",
		WebAuthnRPOrigin: "https://q3.niuwoai.com",
	})
	if err == nil {
		t.Fatal("expected origin mismatch error")
	}
}
