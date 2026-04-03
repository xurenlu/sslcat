package cli

import (
	"testing"
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
