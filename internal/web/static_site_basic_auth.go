package web

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
	"golang.org/x/crypto/bcrypt"
)

const staticSiteBasicAuthRealm = `Basic realm="SSLcat static site", charset="UTF-8"`

type staticSiteBasicAuthRequest struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type staticSiteBasicAuthResponse struct {
	Enabled     bool   `json:"enabled"`
	Username    string `json:"username"`
	PasswordSet bool   `json:"password_set"`
}

type staticSiteAPIResponse struct {
	Domain           string                       `json:"domain"`
	Root             string                       `json:"root"`
	Index            string                       `json:"index"`
	Enabled          bool                         `json:"enabled"`
	BasicAuth        *staticSiteBasicAuthResponse `json:"basic_auth,omitempty"`
	PathPrefixes     []string                     `json:"path_prefixes,omitempty"`
	PathExact        bool                         `json:"path_exact"`
	PathPrefixRules  []config.PathPrefixRule      `json:"path_prefix_rules,omitempty"`
	ResponseHeaders  map[string]string            `json:"response_headers,omitempty"`
	AccessLogEnabled *bool                        `json:"access_log_enabled,omitempty"`
	AccessLogPath    string                       `json:"access_log_path,omitempty"`
	ErrorLogEnabled  *bool                        `json:"error_log_enabled,omitempty"`
	ErrorLogPath     string                       `json:"error_log_path,omitempty"`
	HTTP2Enabled     *bool                        `json:"http2_enabled,omitempty"`
	HTTP3Enabled     *bool                        `json:"http3_enabled,omitempty"`
	TryFiles         bool                         `json:"try_files"`
}

func authorizeStaticSiteBasicAuth(w http.ResponseWriter, r *http.Request, auth *config.StaticSiteBasicAuth) bool {
	if auth == nil || !auth.Enabled {
		return true
	}

	username, password, ok := r.BasicAuth()
	usernameMatches := subtle.ConstantTimeCompare([]byte(username), []byte(auth.Username)) == 1
	passwordMatches := bcrypt.CompareHashAndPassword([]byte(auth.PasswordHash), []byte(password)) == nil
	if ok && usernameMatches && passwordMatches {
		return true
	}

	w.Header().Set("WWW-Authenticate", staticSiteBasicAuthRealm)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	return false
}

func buildStaticSiteBasicAuth(request *staticSiteBasicAuthRequest, existing *config.StaticSiteBasicAuth) (*config.StaticSiteBasicAuth, error) {
	if request == nil {
		if existing == nil {
			return nil, nil
		}
		copy := *existing
		return &copy, nil
	}
	if !request.Enabled {
		return nil, nil
	}

	username := strings.TrimSpace(request.Username)
	if username == "" {
		return nil, fmt.Errorf("basic auth username is required")
	}
	if strings.Contains(username, ":") {
		return nil, fmt.Errorf("basic auth username cannot contain a colon")
	}

	passwordHash := ""
	if existing != nil && existing.Username == username {
		passwordHash = existing.PasswordHash
	}
	if request.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hash basic auth password: %w", err)
		}
		passwordHash = string(hash)
	}
	if passwordHash == "" {
		return nil, fmt.Errorf("basic auth password is required")
	}

	return &config.StaticSiteBasicAuth{
		Enabled:      true,
		Username:     username,
		PasswordHash: passwordHash,
	}, nil
}

func newStaticSiteAPIResponse(site config.StaticSite) staticSiteAPIResponse {
	response := staticSiteAPIResponse{
		Domain:           site.Domain,
		Root:             site.Root,
		Index:            site.Index,
		Enabled:          site.Enabled,
		PathPrefixes:     site.PathPrefixes,
		PathExact:        site.PathExact,
		PathPrefixRules:  site.PathPrefixRules,
		ResponseHeaders:  site.ResponseHeaders,
		AccessLogEnabled: site.AccessLogEnabled,
		AccessLogPath:    site.AccessLogPath,
		ErrorLogEnabled:  site.ErrorLogEnabled,
		ErrorLogPath:     site.ErrorLogPath,
		HTTP2Enabled:     site.HTTP2Enabled,
		HTTP3Enabled:     site.HTTP3Enabled,
		TryFiles:         site.TryFiles,
	}
	if site.BasicAuth != nil {
		response.BasicAuth = &staticSiteBasicAuthResponse{
			Enabled:     site.BasicAuth.Enabled,
			Username:    site.BasicAuth.Username,
			PasswordSet: site.BasicAuth.PasswordHash != "",
		}
	}
	return response
}

func newStaticSiteAPIResponses(sites []config.StaticSite) []staticSiteAPIResponse {
	responses := make([]staticSiteAPIResponse, 0, len(sites))
	for _, site := range sites {
		responses = append(responses, newStaticSiteAPIResponse(site))
	}
	return responses
}
