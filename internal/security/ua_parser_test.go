package security

import (
	"testing"
)

func TestParseUAVersion(t *testing.T) {
	tests := []struct {
		name           string
		ua             string
		wantBrowser    UABrowserType
		wantVeryOld    bool
		wantOutdated   bool
	}{
		{
			name:         "Chrome 120 正常",
			ua:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantBrowser:  UABrowserChrome,
			wantVeryOld:  false,
			wantOutdated: false,
		},
		{
			name:         "Chrome 85 较老",
			ua:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4472.124 Safari/537.36",
			wantBrowser:  UABrowserChrome,
			wantVeryOld:  false,
			wantOutdated: true,
		},
		{
			name:         "Chrome 49 极老",
			ua:           "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36",
			wantBrowser:  UABrowserChrome,
			wantVeryOld:  true,
			wantOutdated: true,
		},
		{
			name:         "Edge 120 正常",
			ua:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			wantBrowser:  UABrowserEdge,
			wantVeryOld:  false,
			wantOutdated: false,
		},
		{
			name:         "Edge 79 极老边界",
			ua:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.0.0 Safari/537.36 Edg/79.0.0.0",
			wantBrowser:  UABrowserEdge,
			wantVeryOld:  false, // 79 刚好等于阈值
			wantOutdated: true,
		},
		{
			name:         "Edge 78 极老",
			ua:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.0.0 Safari/537.36 Edg/78.0.0.0",
			wantBrowser:  UABrowserEdge,
			wantVeryOld:  true,
			wantOutdated: true,
		},
		{
			name:         "Firefox 121 正常",
			ua:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			wantBrowser:  UABrowserFirefox,
			wantVeryOld:  false,
			wantOutdated: false,
		},
		{
			name:         "Firefox 60 极老",
			ua:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0",
			wantBrowser:  UABrowserFirefox,
			wantVeryOld:  true,
			wantOutdated: true,
		},
		{
			name:         "Safari 17 正常",
			ua:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			wantBrowser:  UABrowserSafari,
			wantVeryOld:  false,
			wantOutdated: false,
		},
		{
			name:         "Safari 11 极老",
			ua:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15",
			wantBrowser:  UABrowserSafari,
			wantVeryOld:  true,
			wantOutdated: true,
		},
		{
			name:         "空 UA",
			ua:           "",
			wantBrowser:  UABrowserUnknown,
			wantVeryOld:  false,
			wantOutdated: false,
		},
		{
			name:         "curl 非浏览器",
			ua:           "curl/7.68.0",
			wantBrowser:  UABrowserUnknown,
			wantVeryOld:  false,
			wantOutdated: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ParseUAVersion(tt.ua)
			if r.Browser != tt.wantBrowser {
				t.Errorf("Browser = %v, want %v", r.Browser, tt.wantBrowser)
			}
			if r.IsVeryOutdated != tt.wantVeryOld {
				t.Errorf("IsVeryOutdated = %v, want %v", r.IsVeryOutdated, tt.wantVeryOld)
			}
			if r.IsOutdated != tt.wantOutdated {
				t.Errorf("IsOutdated = %v, want %v", r.IsOutdated, tt.wantOutdated)
			}
		})
	}
}

func TestIsVeryOutdatedBrowser(t *testing.T) {
	if !IsVeryOutdatedBrowser("Chrome/49.0") {
		t.Error("Chrome 49 should be very outdated")
	}
	if IsVeryOutdatedBrowser("Chrome/120.0") {
		t.Error("Chrome 120 should not be very outdated")
	}
}

func TestIsOutdatedBrowser(t *testing.T) {
	if !IsOutdatedBrowser("Chrome/85.0") {
		t.Error("Chrome 85 should be outdated")
	}
	if IsOutdatedBrowser("Chrome/120.0") {
		t.Error("Chrome 120 should not be outdated")
	}
}
