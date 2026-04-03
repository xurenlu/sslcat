package ssl

import "testing"

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
