package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
)

// newClientIPServer 构造一个仅用于 getClientIP 测试的 Server（不启动网络监听）。
func newClientIPServer(trustedProxies []string) *Server {
	s := &Server{}
	s.config = &config.Config{
		Server: config.ServerConfig{
			TrustedProxies: trustedProxies,
		},
	}
	return s
}

func requestWith(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP_DefaultNoProxyTrusted(t *testing.T) {
	s := newClientIPServer(nil) // 默认不信任任何代理

	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "no forwarded headers returns peer",
			remoteAddr: "203.0.113.1:5678",
			want:       "203.0.113.1",
		},
		{
			name:       "private peer with forged XFF is ignored",
			remoteAddr: "10.0.0.5:9999",
			headers:    map[string]string{"X-Forwarded-For": "6.6.6.6"},
			want:       "10.0.0.5",
		},
		{
			name:       "IPv6 peer with forged X-Real-IP is ignored",
			remoteAddr: "[2001:db8::1]:443",
			headers:    map[string]string{"X-Real-IP": "7.7.7.7"},
			want:       "2001:db8::1",
		},
		{
			name:       "private peer with forged CF-Connecting-IP is ignored",
			remoteAddr: "192.168.1.10:1234",
			headers:    map[string]string{"CF-Connecting-IP": "8.8.8.8"},
			want:       "192.168.1.10",
		},
		{
			name:       "no port remote addr",
			remoteAddr: "198.51.100.77",
			want:       "198.51.100.77",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.getClientIP(requestWith(tc.remoteAddr, tc.headers))
			if got != tc.want {
				t.Errorf("getClientIP(%q) = %q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}
}

func TestClientIP_TrustSingleProxyCIDR(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		header     string
		headers    map[string]string
		want       string
	}{
		{
			name:       "trusted proxy returns XFF rightmost untrusted",
			remoteAddr: "172.16.0.3:8080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.9, 172.16.0.3"},
			want:       "203.0.113.9",
		},
		{
			name:       "XFF with leftmost forged IP is rejected (peel from right)",
			remoteAddr: "172.16.0.3:8080",
			headers:    map[string]string{"X-Forwarded-For": "6.6.6.6, 203.0.113.9, 172.16.0.3"},
			want:       "203.0.113.9",
		},
		{
			name:       "X-Real-IP used when proxy trusted",
			remoteAddr: "172.20.1.1:443",
			header:     "X-Real-IP",
			headers:    map[string]string{"X-Real-IP": "198.51.100.30"},
			want:       "198.51.100.30",
		},
		{
			name:       "CF-Connecting-IP used when proxy trusted",
			remoteAddr: "172.31.9.9:80",
			header:     "CF-Connecting-IP",
			headers:    map[string]string{"CF-Connecting-IP": "198.51.100.44"},
			want:       "198.51.100.44",
		},
		{
			name:       "untrusted peer ignores XFF even matching trusted list value",
			remoteAddr: "198.51.100.99:8080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			want:       "198.51.100.99",
		},
		{
			name:       "XFF with only trusted proxies falls back to peer",
			remoteAddr: "172.16.0.4:8080",
			headers:    map[string]string{"X-Forwarded-For": "172.16.0.2, 172.16.0.3"},
			want:       "172.16.0.4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newClientIPServer([]string{"172.16.0.0/12"})
			s.config.Server.TrustedProxyHeader = tc.header
			got := s.getClientIP(requestWith(tc.remoteAddr, tc.headers))
			if got != tc.want {
				t.Errorf("getClientIP(%q, headers=%v) = %q, want %q", tc.remoteAddr, tc.headers, got, tc.want)
			}
		})
	}
}

func TestClientIP_InvalidIPRejected(t *testing.T) {
	s := newClientIPServer([]string{"127.0.0.1", "10.0.0.0/8"})

	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "invalid XFF entries are skipped",
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Forwarded-For": "not-an-ip, 203.0.113.5"},
			want:       "203.0.113.5",
		},
		{
			name:       "invalid X-Real-IP ignored, falls back to peer",
			remoteAddr: "10.1.2.3:8080",
			headers:    map[string]string{"X-Real-IP": "garbage"},
			want:       "10.1.2.3",
		},
		{
			name:       "invalid RemoteAddr passed through unchanged",
			remoteAddr: "not-a-host",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.5"},
			want:       "not-a-host",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.getClientIP(requestWith(tc.remoteAddr, tc.headers))
			if got != tc.want {
				t.Errorf("getClientIP(%q, headers=%v) = %q, want %q", tc.remoteAddr, tc.headers, got, tc.want)
			}
		})
	}
}

func TestClientIP_IPv6PeerAndAddresses(t *testing.T) {
	s := newClientIPServer([]string{"2001:db8::10", "fd00::1", "10.0.0.0/8"})

	cases := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "IPv6 peer trusted, XFF returns real IPv6 client",
			remoteAddr: "[2001:db8::10]:443",
			headers:    map[string]string{"X-Forwarded-For": "2001:db8:aaaa::5, 2001:db8::10"},
			want:       "2001:db8:aaaa::5",
		},
		{
			name:       "IPv6 untrusted peer ignores XFF",
			remoteAddr: "[2001:db9::1]:80",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.2"},
			want:       "2001:db9::1",
		},
		{
			name:       "IPv4-mapped IPv6 peer matches IPv4 CIDR trusted list",
			remoteAddr: "[::ffff:10.2.3.4]:8080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.8"},
			want:       "203.0.113.8",
		},
		{
			name:       "bare IPv6 remote addr (no brackets/port)",
			remoteAddr: "2001:db8:abcd::1",
			want:       "2001:db8:abcd::1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.getClientIP(requestWith(tc.remoteAddr, tc.headers))
			if got != tc.want {
				t.Errorf("getClientIP(%q, headers=%v) = %q, want %q", tc.remoteAddr, tc.headers, got, tc.want)
			}
		})
	}
}

func TestIsTrustedProxy(t *testing.T) {
	s := newClientIPServer([]string{"10.0.0.0/8", "192.0.2.55", "2001:db8::/32"})

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"10.255.0.1", true},
		{"192.0.2.55", true},
		{"192.0.2.56", false},
		{"11.0.0.1", false},
		{"2001:db8:dead::1", true},
		{"2001:db9::1", false},
		{"invalid", false},
	}
	for _, tc := range cases {
		if got := s.isTrustedProxy(tc.ip); got != tc.want {
			t.Errorf("isTrustedProxy(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}
