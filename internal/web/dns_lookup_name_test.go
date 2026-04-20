package web

import "testing"

func TestDNSLookupNameForCertDomain(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"*.facev.app", "facev.app"},
		{"facev.app", "facev.app"},
		{"*.example.co.uk", "example.co.uk"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := dnsLookupNameForCertDomain(tt.in); got != tt.want {
			t.Errorf("dnsLookupNameForCertDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
