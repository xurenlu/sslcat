package ssl

import "testing"

func TestDNSLookupHostForResolution_WildcardUsesApex(t *testing.T) {
	tests := []struct {
		domain   string
		wantHost string
		wild     bool
	}{
		{"*.17push.com", "17push.com", true},
		{"*.example.com", "example.com", true},
		{"aigc.17push.com", "aigc.17push.com", false},
		{"example.com", "example.com", false},
	}
	for _, tt := range tests {
		host, wild := dnsLookupHostForResolution(tt.domain)
		if host != tt.wantHost || wild != tt.wild {
			t.Errorf("dnsLookupHostForResolution(%q) = (%q, %v), want (%q, %v)", tt.domain, host, wild, tt.wantHost, tt.wild)
		}
	}
}

func TestRuleDomainMatchesHost_WildcardCertVsSubdomainRule(t *testing.T) {
	// 通配符证书身份 *.facev.app 应被代理规则里的具体子域覆盖
	if !ruleDomainMatchesHost("*.facev.app", "gemini.facev.app") {
		t.Fatal("*.facev.app should match rule gemini.facev.app")
	}
	// 原有：配置为通配符、host 为子域
	if !ruleDomainMatchesHost("gemini.facev.app", "*.facev.app") {
		t.Fatal("gemini.facev.app should match *.facev.app rule")
	}
	if ruleDomainMatchesHost("*.facev.app", "other.com") {
		t.Fatal("unrelated domain should not match")
	}
}
