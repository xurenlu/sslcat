package profiling

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateAddrOnlyAllowsLoopback(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "ipv4 loopback", addr: "127.0.0.1:6060"},
		{name: "ipv6 loopback", addr: "[::1]:6060"},
		{name: "localhost", addr: "localhost:6060"},
		{name: "wildcard ipv4", addr: "0.0.0.0:6060", wantErr: true},
		{name: "wildcard ipv6", addr: "[::]:6060", wantErr: true},
		{name: "private network", addr: "192.168.1.20:6060", wantErr: true},
		{name: "public network", addr: "8.8.8.8:6060", wantErr: true},
		{name: "missing port", addr: "127.0.0.1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateAddr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestHandlerServesPprofIndex(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	response := httptest.NewRecorder()

	newHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "Types of profiles available") {
		t.Fatalf("pprof index did not contain profile listing")
	}
}
