package ssl

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Only provider discovery is needed. Any unexpected DNS mutation through the
// embedded nil interface fails the test rather than contacting a real service.
type offlineDNSProvider struct{ DNSProviderInterface }

func (offlineDNSProvider) ListDomains(context.Context) ([]DomainInfo, error) {
	return []DomainInfo{{Name: "example.com", Type: "domain"}}, nil
}

func configureOfflineACME(m *Manager, dns bool) {
	m.acmeMgr = &autocert.Manager{}
	if dns {
		m.dnsManager.RegisterProvider("offline", offlineDNSProvider{})
	}
}

func TestRenewalWindowIncludesExpiredCerts(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for _, tc := range []struct {
		name      string
		remaining time.Duration
		want      int
	}{
		{"expired", -48 * time.Hour, 1},
		{"inside", certificateRenewalWindow - time.Hour, 1},
		{"outside", certificateRenewalWindow + time.Hour, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			configureOfflineACME(m, false)
			m.config.SSL.Domains = []string{"api.example.com"}
			cert := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-90*24*time.Hour), now.Add(tc.remaining))
			fresh := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
			putFixture(t, m, "api.example.com", cert)
			calls := 0
			m.requestHTTP = func(domain string) (*tls.Certificate, error) { calls++; return fresh, nil }
			m.renewExpiringCerts()
			if calls != tc.want {
				t.Fatalf("background requests=%d, want %d", calls, tc.want)
			}
		})
	}
	boundary := &x509.Certificate{NotAfter: now.Add(certificateRenewalWindow)}
	if certificateNeedsRenewal(boundary, now) {
		t.Fatal("exact 30-day boundary must be outside the window")
	}
	if !certificateNeedsRenewal(boundary, now.Add(time.Nanosecond)) {
		t.Fatal("just inside boundary must renew")
	}
}

func TestBackgroundRenewalChallengeDispatchAndRetention(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name              string
		san               string
		dns               bool
		allowed           bool
		methods           []string
		fail              bool
		wantDNS, wantHTTP int
	}{
		{"wildcard DNS expired", "*.example.com", true, true, nil, false, 1, 0},
		{"exact DNS preferred", "api.example.com", true, true, nil, false, 1, 0},
		{"exact HTTP", "api.example.com", false, true, nil, false, 0, 1},
		{"wildcard no provider", "*.example.com", false, true, nil, false, 0, 0},
		{"wildcard DNS disabled", "*.example.com", true, true, []string{"http-01"}, false, 0, 0},
		{"wildcard DNS failure", "*.example.com", true, true, nil, true, 1, 0},
		{"exact DNS failure no fallback", "api.example.com", true, true, nil, true, 1, 0},
		{"public CA HTTP failure no self signing", "api.example.com", false, true, nil, true, 0, 1},
		{"unconfigured wildcard file", "*.example.com", true, false, nil, false, 0, 0},
		{"unconfigured exact file", "api.example.com", false, false, nil, false, 0, 0},
		{"DNS only exact no provider", "api.example.com", false, true, []string{"dns-01"}, false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			configureOfflineACME(m, tc.dns)
			m.config.SSL.DisableSelfSigned = false
			m.config.SSL.ChallengeMethods = tc.methods
			if tc.allowed {
				m.config.SSL.Domains = []string{tc.san}
			}
			old := fixtureCertificate(t, []string{tc.san}, now.Add(-90*24*time.Hour), now.Add(-time.Hour))
			fresh := fixtureCertificate(t, []string{tc.san}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
			// The filename must never become an application identity or grant.
			putFixture(t, m, "historical-alias", old)
			dnsCalls, httpCalls := 0, 0
			m.requestDNS = func(domain, provider string) error {
				dnsCalls++
				if domain != tc.san || provider != "offline" {
					t.Fatalf("DNS request %s/%s", domain, provider)
				}
				if tc.fail {
					return fmt.Errorf("offline DNS failure")
				}
				return m.persistIssuedCertificate(domain, fresh)
			}
			m.requestHTTP = func(domain string) (*tls.Certificate, error) {
				httpCalls++
				if domain != tc.san {
					t.Fatalf("HTTP identity=%s, want SAN %s", domain, tc.san)
				}
				if tc.fail {
					return nil, fmt.Errorf("offline HTTP failure")
				}
				return fresh, nil
			}
			m.renewExpiringCerts()
			if dnsCalls != tc.wantDNS || httpCalls != tc.wantHTTP {
				t.Fatalf("DNS/HTTP requests=%d/%d, want %d/%d", dnsCalls, httpCalls, tc.wantDNS, tc.wantHTTP)
			}
			leaf, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, "historical-alias.crt"))
			if err != nil {
				t.Fatal(err)
			}
			want := old
			if !tc.fail && tc.wantDNS+tc.wantHTTP > 0 {
				want = fresh
			}
			if !bytes.Equal(leaf.Raw, want.Certificate[0]) {
				t.Fatal("renewal failed to preserve/update the original alias as expected")
			}
			if !tc.allowed {
				m.tempAllowedMutex.RLock()
				grants := len(m.tempAllowedDomains)
				m.tempAllowedMutex.RUnlock()
				if grants != 0 {
					t.Fatal("background scan granted temporary authorization")
				}
			}
		})
	}
}

func TestBackgroundRenewalDeduplicatesAliasesAndConcurrentScans(t *testing.T) {
	m := newTestManager(t)
	configureOfflineACME(m, true)
	m.config.SSL.Domains = []string{"api.example.com"}
	now := time.Now()
	old := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-90*24*time.Hour), now.Add(time.Hour))
	fresh := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
	putFixture(t, m, "alias-one", old)
	putFixture(t, m, "alias-two", old)
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	m.requestDNS = func(domain, provider string) error {
		if domain != "*.example.com" {
			t.Errorf("request identity %s", domain)
		}
		calls.Add(1)
		close(started)
		<-release
		return m.persistIssuedCertificate(domain, fresh)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); m.renewExpiringCerts() }()
	<-started
	wg.Add(1)
	go func() { defer wg.Done(); m.renewExpiringCerts() }()
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate background issuance: %d", calls.Load())
	}
	for _, alias := range []string{"alias-one", "alias-two", "*.example.com"} {
		leaf, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, alias+".crt"))
		if err != nil || !bytes.Equal(leaf.Raw, fresh.Certificate[0]) {
			t.Fatalf("alias %s not updated: %v", alias, err)
		}
	}
}

func TestBackgroundRenewalRechecksDiskAfterRequestLock(t *testing.T) {
	m := newTestManager(t)
	configureOfflineACME(m, false)
	m.config.SSL.Domains = []string{"api.example.com"}
	now := time.Now()
	old := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-90*24*time.Hour), now.Add(time.Hour))
	fresh := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
	putFixture(t, m, "alias", old)
	unlock := m.lockCertRequest("api.example.com")
	calls := 0
	m.requestHTTP = func(string) (*tls.Certificate, error) { calls++; return fresh, nil }
	finished := make(chan struct{})
	go func() { defer close(finished); m.renewExpiringCerts() }()
	// Simulate a CLI process completing renewal while background waits.
	putFixture(t, m, "api.example.com", fresh)
	unlock()
	<-finished
	if calls != 0 {
		t.Fatal("background issued again after a fresh certificate appeared on disk")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(m.config.SSL.CertDir, "alias.crt"), filepath.Join(m.config.SSL.KeyDir, "alias.key"))
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, &pair, fresh)
	got, err := m.GetCertificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, fresh)
}

func TestBackgroundRenewalFailureCooldownAndKeepsMemory(t *testing.T) {
	m := newTestManager(t)
	configureOfflineACME(m, true)
	m.config.SSL.Domains = []string{"*.example.com"}
	now := time.Now()
	old := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-90*24*time.Hour), now.Add(time.Hour))
	putFixture(t, m, "*.example.com", old)
	if err := m.LoadCertificateFromDisk("*.example.com"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	m.requestDNS = func(string, string) error { calls++; return fmt.Errorf("offline failure") }
	m.requestHTTP = func(string) (*tls.Certificate, error) { t.Fatal("HTTP fallback must not run"); return nil, nil }
	m.renewExpiringCerts()
	m.renewExpiringCerts()
	if calls != 1 {
		t.Fatalf("failed renewal not cooled down: %d", calls)
	}
	assertSameCertificate(t, m.getCertificateFromCache("*.example.com"), old)
	m.renewalFailures["*.example.com"] = time.Now().Add(-time.Second)
	m.renewExpiringCerts()
	if calls != 2 {
		t.Fatal("renewal did not resume after cooldown")
	}
}

func TestMultiSANRenewalExplicitlyFailsWithoutShrinkingOrSelfSigning(t *testing.T) {
	for _, acmeEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("ACME=%v", acmeEnabled), func(t *testing.T) {
			m := newTestManager(t)
			if acmeEnabled {
				configureOfflineACME(m, true)
			}
			m.config.SSL.DisableSelfSigned = false
			m.config.SSL.Domains = []string{"*.example.com", "example.com"}
			old := fixtureCertificate(t, []string{"*.example.com", "example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			putFixture(t, m, "legacy", old)
			if err := m.LoadCertificateFromDisk("legacy"); err != nil {
				t.Fatal(err)
			}
			m.requestDNS = func(string, string) error { t.Fatal("multi-SAN was silently reduced to single SAN"); return nil }
			m.requestHTTP = func(string) (*tls.Certificate, error) {
				t.Fatal("multi-SAN was silently reduced to HTTP single SAN")
				return nil, nil
			}
			m.renewExpiringCerts()
			if acmeEnabled {
				if err := m.EnsureDomainCert("legacy"); err == nil || !strings.Contains(err.Error(), "multi-SAN") {
					t.Fatalf("expected explicit multi-SAN error, got %v", err)
				}
			}
			leaf, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, "legacy.crt"))
			if err != nil || !bytes.Equal(leaf.Raw, old.Certificate[0]) {
				t.Fatalf("multi-SAN disk certificate changed: %v", err)
			}
			assertSameCertificate(t, m.getCertificateFromCache("legacy"), old)
		})
	}
}

func TestCLIAndBackgroundShareWildcardDispatch(t *testing.T) {
	m := newTestManager(t)
	configureOfflineACME(m, true)
	old := fixtureCertificate(t, []string{"*.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	putFixture(t, m, "api.example.com", old)
	calls := 0
	m.requestDNS = func(domain, provider string) error {
		calls++
		if domain != "*.example.com" {
			t.Fatalf("CLI requested filename alias instead of SAN: %s", domain)
		}
		return fmt.Errorf("offline DNS failure")
	}
	m.requestHTTP = func(string) (*tls.Certificate, error) { t.Fatal("CLI wildcard HTTP fallback"); return nil, nil }
	if err := m.EnsureDomainCert("api.example.com"); err == nil {
		t.Fatal("expected DNS error")
	}
	if calls != 1 {
		t.Fatal("CLI did not dispatch DNS request")
	}
	m.dnsManager.ClearProviders()
	if err := m.EnsureDomainCert("*.example.com"); err == nil {
		t.Fatal("wildcard without provider should fail")
	}
}

func TestBackgroundHTTPRejectsInvalidIssuedLeaf(t *testing.T) {
	now := time.Now()
	for _, bad := range []*tls.Certificate{
		nil,
		{Certificate: [][]byte{[]byte("bad DER")}},
		fixtureCertificate(t, []string{"other.example.com"}, now.Add(-time.Hour), now.Add(time.Hour)),
		fixtureCertificate(t, []string{"api.example.com"}, now.Add(time.Hour), now.Add(2*time.Hour)),
	} {
		m := newTestManager(t)
		configureOfflineACME(m, false)
		m.config.SSL.Domains = []string{"api.example.com"}
		old := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
		putFixture(t, m, "api.example.com", old)
		if err := m.LoadCertificateFromDisk("api.example.com"); err != nil {
			t.Fatal(err)
		}
		m.requestHTTP = func(string) (*tls.Certificate, error) { return bad, nil }
		m.renewExpiringCerts()
		data, err := os.ReadFile(filepath.Join(m.config.SSL.CertDir, "api.example.com.crt"))
		if err != nil || len(data) == 0 {
			t.Fatal("old disk certificate lost")
		}
		leaf, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, "api.example.com.crt"))
		if err != nil || !bytes.Equal(leaf.Raw, old.Certificate[0]) {
			t.Fatalf("invalid issued cert overwrote disk: %v", err)
		}
		assertSameCertificate(t, m.getCertificateFromCache("api.example.com"), old)
	}
}
