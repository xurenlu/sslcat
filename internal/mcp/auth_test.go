package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestHashAndVerifyToken(t *testing.T) {
	plain, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(plain, "sslcat_mcp_") {
		t.Fatalf("token should have sslcat_mcp_ prefix, got %s", plain)
	}
	hash, err := HashToken(plain)
	if err != nil {
		t.Fatalf("HashToken: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash should be PHC-encoded, got %s", hash)
	}
	if !VerifyToken(plain, hash) {
		t.Fatal("VerifyToken should accept original token")
	}
	if VerifyToken(plain+"x", hash) {
		t.Fatal("VerifyToken should reject tampered token")
	}
	if VerifyToken("", hash) {
		t.Fatal("VerifyToken should reject empty token")
	}
}

func TestVerifyToken_RejectsMalformedHash(t *testing.T) {
	cases := []string{
		"",
		"$argon2id$v=19$m=64,t=1,p=2$bad$bad",
		"$bcrypt$v=1$x$y",
		"not-a-hash",
	}
	for _, c := range cases {
		if VerifyToken("whatever", c) {
			t.Errorf("VerifyToken should reject malformed hash: %q", c)
		}
	}
}

func TestAuthenticator_Authenticate(t *testing.T) {
	plain := "sslcat_mcp_test_token_1234567890"
	hash, _ := HashToken(plain)

	cfg := &config.MCPConfig{
		Tokens: []config.MCPToken{
			{
				Name:      "good",
				TokenHash: hash,
				Scopes:    []string{"read", "site:write"},
			},
			{
				Name:        "ip-restricted",
				TokenHash:   hash,
				Scopes:      []string{"read"},
				IPAllowlist: []string{"10.0.0.0/8"},
			},
			{
				Name:      "expired",
				TokenHash: hash,
				Scopes:    []string{"read"},
				ExpiresAt: time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			},
		},
	}

	auth := NewAuthenticator(cfg)

	t.Run("success returns first matching token", func(t *testing.T) {
		res, err := auth.Authenticate(plain, "127.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.TokenName != "good" {
			t.Fatalf("expected first matching token 'good', got %s", res.TokenName)
		}
		if len(res.Scopes) != 2 || res.Scopes[0] != ScopeRead {
			t.Fatalf("unexpected scopes: %v", res.Scopes)
		}
	})

	t.Run("wrong token rejected", func(t *testing.T) {
		_, err := auth.Authenticate("sslcat_mcp_wrong", "127.0.0.1")
		if err != ErrUnauthorized {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
	})

	t.Run("empty token rejected", func(t *testing.T) {
		_, err := auth.Authenticate("", "127.0.0.1")
		if err != ErrUnauthorized {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
	})
}

func TestAuthenticator_IPAllowlist(t *testing.T) {
	plain := "sslcat_mcp_ip_test"
	hash, _ := HashToken(plain)
	cfg := &config.MCPConfig{
		Tokens: []config.MCPToken{
			{
				Name:        "lan-only",
				TokenHash:   hash,
				Scopes:      []string{"read"},
				IPAllowlist: []string{"10.0.0.1", "192.168.0.0/16"},
			},
		},
	}
	auth := NewAuthenticator(cfg)

	if _, err := auth.Authenticate(plain, "192.168.1.5"); err != nil {
		t.Fatalf("IP in CIDR should pass: %v", err)
	}
	if _, err := auth.Authenticate(plain, "10.0.0.1"); err != nil {
		t.Fatalf("exact IP should pass: %v", err)
	}
	if _, err := auth.Authenticate(plain, "8.8.8.8"); err != ErrForbidden {
		t.Fatalf("IP outside should be forbidden, got %v", err)
	}
}

func TestAuthenticator_Expired(t *testing.T) {
	plain := "sslcat_mcp_exp_test"
	hash, _ := HashToken(plain)
	cfg := &config.MCPConfig{
		Tokens: []config.MCPToken{
			{
				Name:      "expired",
				TokenHash: hash,
				Scopes:    []string{"read"},
				ExpiresAt: time.Now().Add(-time.Minute).Format(time.RFC3339),
			},
		},
	}
	auth := NewAuthenticator(cfg)
	if _, err := auth.Authenticate(plain, "127.0.0.1"); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestAuthenticator_RateLimit(t *testing.T) {
	plain := "sslcat_mcp_rl_test"
	hash, _ := HashToken(plain)
	cfg := &config.MCPConfig{
		Tokens: []config.MCPToken{
			{
				Name:      "limited",
				TokenHash: hash,
				Scopes:    []string{"read"},
				RateLimit: "2/min",
			},
		},
	}
	auth := NewAuthenticator(cfg)
	for i := 0; i < 2; i++ {
		if _, err := auth.Authenticate(plain, "127.0.0.1"); err != nil {
			t.Fatalf("call %d should succeed: %v", i, err)
		}
	}
	if _, err := auth.Authenticate(plain, "127.0.0.1"); err != ErrRateLimited {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

func TestExtractBearer(t *testing.T) {
	cases := map[string]string{
		"":                         "",
		"Bearer abc":               "abc",
		"bearer xyz":               "xyz",
		"Token xyz":                "",
		"Bearer   spaced   ":       "spaced",
		"Bearer":                   "",
	}
	for in, want := range cases {
		if got := ExtractBearer(in); got != want {
			t.Errorf("ExtractBearer(%q) = %q, want %q", in, got, want)
		}
	}
}
