package web

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

func resolveWebAuthnRelyingParty(cfg config.ServerConfig) (string, string, error) {
	rpID := strings.TrimSpace(cfg.WebAuthnRPID)
	rpOrigin := strings.TrimSpace(cfg.WebAuthnRPOrigin)
	if rpID == "" && rpOrigin == "" {
		return legacyWebAuthnRelyingParty(cfg)
	}
	if rpID == "" || rpOrigin == "" {
		return "", "", fmt.Errorf("server.webauthn_rp_id and server.webauthn_rp_origin must be configured together")
	}
	if net.ParseIP(rpID) != nil || strings.Contains(rpID, "://") || strings.Contains(rpID, ":") {
		return "", "", fmt.Errorf("server.webauthn_rp_id must be a domain name without scheme or port")
	}

	originURL, err := url.Parse(rpOrigin)
	if err != nil || originURL.Scheme == "" || originURL.Host == "" || originURL.User != nil || originURL.Path != "" || originURL.RawQuery != "" || originURL.Fragment != "" {
		return "", "", fmt.Errorf("server.webauthn_rp_origin must be an origin such as https://panel.example.com")
	}
	if originURL.Scheme != "https" && originURL.Scheme != "http" {
		return "", "", fmt.Errorf("server.webauthn_rp_origin must use http or https")
	}

	originHost := strings.ToLower(originURL.Hostname())
	normalizedRPID := strings.ToLower(rpID)
	if originHost != normalizedRPID && !strings.HasSuffix(originHost, "."+normalizedRPID) {
		return "", "", fmt.Errorf("server.webauthn_rp_id must equal the origin host or be its parent domain")
	}
	return normalizedRPID, originURL.String(), nil
}

func legacyWebAuthnRelyingParty(cfg config.ServerConfig) (string, string, error) {
	rpID := cfg.Host
	if rpID == "" || rpID == "0.0.0.0" {
		rpID = "localhost"
	}
	if index := strings.Index(rpID, ":"); index != -1 {
		rpID = rpID[:index]
	}
	if net.ParseIP(rpID) != nil {
		rpID = "localhost"
	}

	port := 8080
	if cfg.PortMode == "custom" && cfg.CustomPort != 0 {
		port = cfg.CustomPort
	}
	protocol := "http"
	if cfg.EnableHTTPS || port == 443 {
		protocol = "https"
	}
	if (protocol == "http" && port == 80) || (protocol == "https" && port == 443) {
		return rpID, fmt.Sprintf("%s://%s", protocol, rpID), nil
	}
	return rpID, fmt.Sprintf("%s://%s:%d", protocol, rpID, port), nil
}
