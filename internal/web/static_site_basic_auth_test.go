package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthorizeStaticSiteBasicAuth(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate password hash: %v", err)
	}
	auth := &config.StaticSiteBasicAuth{
		Enabled:      true,
		Username:     "subscriber",
		PasswordHash: string(hash),
	}

	tests := []struct {
		name           string
		username       string
		password       string
		setCredentials bool
		wantAuthorized bool
	}{
		{name: "missing credentials"},
		{name: "wrong username", username: "intruder", password: "correct-password", setCredentials: true},
		{name: "wrong password", username: "subscriber", password: "wrong-password", setCredentials: true},
		{name: "valid credentials", username: "subscriber", password: "correct-password", setCredentials: true, wantAuthorized: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/subscription.yaml", nil)
			if tt.setCredentials {
				req.SetBasicAuth(tt.username, tt.password)
			}
			response := httptest.NewRecorder()

			authorized := authorizeStaticSiteBasicAuth(response, req, auth)
			if authorized != tt.wantAuthorized {
				t.Fatalf("authorized = %v, want %v", authorized, tt.wantAuthorized)
			}
			if tt.wantAuthorized {
				if response.Header().Get("WWW-Authenticate") != "" {
					t.Fatal("successful authentication must not return a challenge")
				}
				return
			}
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
			}
			if response.Header().Get("WWW-Authenticate") != staticSiteBasicAuthRealm {
				t.Fatalf("unexpected WWW-Authenticate header: %q", response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestAuthorizeStaticSiteBasicAuthDisabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	response := httptest.NewRecorder()

	if !authorizeStaticSiteBasicAuth(response, req, nil) {
		t.Fatal("nil basic auth config should allow the request")
	}
	if !authorizeStaticSiteBasicAuth(response, req, &config.StaticSiteBasicAuth{}) {
		t.Fatal("disabled basic auth config should allow the request")
	}
}

func TestBuildStaticSiteBasicAuth(t *testing.T) {
	created, err := buildStaticSiteBasicAuth(&staticSiteBasicAuthRequest{
		Enabled:  true,
		Username: " subscriber ",
		Password: "new-password",
	}, nil)
	if err != nil {
		t.Fatalf("build basic auth: %v", err)
	}
	if created.Username != "subscriber" {
		t.Fatalf("username = %q, want subscriber", created.Username)
	}
	if created.PasswordHash == "new-password" {
		t.Fatal("password was stored in plaintext")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(created.PasswordHash), []byte("new-password")); err != nil {
		t.Fatalf("stored hash does not match password: %v", err)
	}

	preserved, err := buildStaticSiteBasicAuth(&staticSiteBasicAuthRequest{
		Enabled:  true,
		Username: "subscriber",
	}, created)
	if err != nil {
		t.Fatalf("preserve basic auth password: %v", err)
	}
	if preserved.PasswordHash != created.PasswordHash {
		t.Fatal("blank update password should preserve the existing hash")
	}

	if _, err := buildStaticSiteBasicAuth(&staticSiteBasicAuthRequest{Enabled: true, Username: "subscriber"}, nil); err == nil {
		t.Fatal("new enabled basic auth config without password should fail")
	}
}

func TestStaticSiteAPIResponseDoesNotExposePasswordHash(t *testing.T) {
	const passwordHash = "$2a$10$sensitive-test-hash"
	response := newStaticSiteAPIResponse(config.StaticSite{
		Domain: "example.com",
		BasicAuth: &config.StaticSiteBasicAuth{
			Enabled:      true,
			Username:     "subscriber",
			PasswordHash: passwordHash,
		},
	})

	payload, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	text := string(payload)
	if strings.Contains(text, passwordHash) || strings.Contains(text, "password_hash") {
		t.Fatalf("API response exposed password hash: %s", text)
	}
	if !strings.Contains(text, `"password_set":true`) {
		t.Fatalf("API response did not report password state: %s", text)
	}
}
