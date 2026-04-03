package cli

import (
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/ssl"
)

func TestParseSSLDomainFlags(t *testing.T) {
	d, err := parseSSLDomainFlags([]string{"-domain", "a.com", "-d", "b.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 2 || d[0] != "a.com" || d[1] != "b.com" {
		t.Fatalf("got %#v", d)
	}
	_, err = parseSSLDomainFlags([]string{"-domain"})
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = parseSSLDomainFlags(nil)
	if err == nil {
		t.Fatal("expected error for empty")
	}
}

func TestCertNeedsRenewDue(t *testing.T) {
	now := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	if !certNeedsRenewDue(ssl.CertificateInfo{
		SelfSigned: false,
		ExpiresAt:  now.Add(-time.Hour),
	}, now) {
		t.Fatal("expired should need renew")
	}
	if !certNeedsRenewDue(ssl.CertificateInfo{
		SelfSigned: false,
		ExpiresAt:  now.Add(2 * 24 * time.Hour),
	}, now) {
		t.Fatal("expires in 2d should need renew")
	}
	if certNeedsRenewDue(ssl.CertificateInfo{
		SelfSigned: false,
		ExpiresAt:  now.Add(5 * 24 * time.Hour),
	}, now) {
		t.Fatal("expires in 5d should not")
	}
	if certNeedsRenewDue(ssl.CertificateInfo{
		SelfSigned: true,
		ExpiresAt:  now.Add(-time.Hour),
	}, now) {
		t.Fatal("self-signed should skip")
	}
}
