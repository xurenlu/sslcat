package web

import "testing"

func TestClientIPForwardedHeaderBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		xff    []string
		xreal  []string
		cf     []string
		want   string
	}{
		{name: "invalid nearest hop blocks forged left address", xff: []string{"203.0.113.8, invalid"}, want: "192.0.2.10"},
		{name: "multiple XFF fields retain right boundary", xff: []string{"203.0.113.8", "198.51.100.20"}, want: "198.51.100.20"},
		{name: "unselected single IP headers ignored", xff: []string{"198.51.100.20"}, xreal: []string{"203.0.113.8"}, cf: []string{"203.0.113.9"}, want: "198.51.100.20"},
		{name: "default does not fall back to arbitrary headers", cf: []string{"203.0.113.9"}, want: "192.0.2.10"},
		{name: "explicit header mode", header: "CF-Connecting-IP", cf: []string{"203.0.113.9"}, xff: []string{"198.51.100.20"}, want: "203.0.113.9"},
		{name: "duplicate single address headers rejected", header: "X-Real-IP", xreal: []string{"203.0.113.8", "203.0.113.9"}, want: "192.0.2.10"},
		{name: "unknown selector fails closed", header: "Other-IP", xff: []string{"198.51.100.20"}, want: "192.0.2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newClientIPServer([]string{"192.0.2.10"})
			s.config.Server.TrustedProxyHeader = tc.header
			r := requestWith("192.0.2.10:443", nil)
			for _, value := range tc.xff {
				r.Header.Add("X-Forwarded-For", value)
			}
			for _, value := range tc.xreal {
				r.Header.Add("X-Real-IP", value)
			}
			for _, value := range tc.cf {
				r.Header.Add("CF-Connecting-IP", value)
			}
			if got := s.getClientIP(r); got != tc.want {
				t.Fatalf("client IP %q, want %q", got, tc.want)
			}
		})
	}
}
