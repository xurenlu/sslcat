package ssl

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHotReloadCorrectsPreviouslyUnrelatedSANAtHostnameKey(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	unrelated := fixtureCertificate(t, []string{"other.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	correct := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	putFixture(t, m, "api.example.com", unrelated)
	if err := m.LoadCertificateFromDisk("api.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCertificate("api.example.com"); err == nil {
		t.Fatal("filename must not authorize an unrelated SAN")
	}
	putFixture(t, m, "api.example.com", correct)
	got, err := m.GetCertificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, correct)
}

func TestHotReloadCanReplaceWildcardWithExactSANAtHostnameKey(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	wild := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	exact := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(40*24*time.Hour))
	putFixture(t, m, "api.example.com", wild)
	if err := m.LoadCertificateFromDisk("api.example.com"); err != nil {
		t.Fatal(err)
	}
	putFixture(t, m, "api.example.com", exact)
	got, err := m.GetCertificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, exact)
}

func TestMismatchedDiskKeyPreservesMemoryAndRecovers(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	old := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	next := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(40*24*time.Hour))
	putFixture(t, m, "api.example.com", old)
	if err := m.LoadCertificateFromDisk("api.example.com"); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := encodeCertificatePair(next)
	if err != nil {
		t.Fatal(err)
	}
	// Model an external writer replacing the certificate before its key.
	if err := os.WriteFile(filepath.Join(m.config.SSL.CertDir, "api.example.com.crt"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetCertificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, old)
	// The key change alone must trigger a fresh validated load.
	if err := os.WriteFile(filepath.Join(m.config.SSL.KeyDir, "api.example.com.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = m.GetCertificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, next)
}

func TestMalformedCachedChainIsRejected(t *testing.T) {
	m := newTestManager(t)
	cert := fixtureCertificate(t, []string{"api.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	cert.Certificate = append(cert.Certificate, []byte("malformed intermediate DER"))
	m.certCache["api.example.com"] = cert
	if _, err := m.GetCertificate("api.example.com"); err == nil {
		t.Fatal("malformed chain must not be selected from memory")
	}
}

func TestCLIColdAliasRenewsSANAndSynchronizesAliases(t *testing.T) {
	m := newTestManager(t)
	configureOfflineACME(m, true)
	now := time.Now()
	old := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	fresh := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
	putFixture(t, m, "opaque-upload", old)
	calls := 0
	m.requestDNS = func(domain, provider string) error {
		calls++
		if domain != "*.example.com" {
			t.Fatalf("CLI ordered %s instead of existing wildcard SAN", domain)
		}
		return m.persistIssuedCertificate(domain, fresh)
	}
	m.requestHTTP = func(string) (*tls.Certificate, error) {
		t.Fatal("wildcard CLI request used HTTP")
		return nil, nil
	}
	if err := m.EnsureDomainCert("api.example.com"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("CLI DNS issuance count = %d, want 1", calls)
	}
	assertSameCertificate(t, m.getCertificateFromCache("opaque-upload"), fresh)
}

func TestHotReloadUpdatesMemoryOnlyMultiDomainAliases(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	names := []string{"z.example.com", "a.example.com"}
	old := fixtureCertificate(t, names, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	next := fixtureCertificate(t, names, now.Add(-time.Minute), now.Add(40*24*time.Hour))
	putFixture(t, m, "z.example.com", old)
	// GenerateMultiDomainCert stores all SANs in memory but writes only its
	// primary SAN file. Model that state without expensive RSA generation.
	m.certCache["z.example.com"] = old
	m.certCache["a.example.com"] = old
	if err := m.LoadCertificateFromDisk("z.example.com"); err != nil {
		t.Fatal(err)
	}
	putFixture(t, m, "z.example.com", next)
	got, err := m.GetCertificate("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, next)
}

func TestCLIColdMultiSANAliasCannotBeShrunk(t *testing.T) {
	m := newTestManager(t)
	configureOfflineACME(m, true)
	cert := fixtureCertificate(t, []string{"api.example.com", "other.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	putFixture(t, m, "opaque-upload", cert)
	m.requestDNS = func(string, string) error { t.Fatal("multi-SAN was reduced to one DNS identifier"); return nil }
	m.requestHTTP = func(string) (*tls.Certificate, error) {
		t.Fatal("multi-SAN was reduced to one HTTP identifier")
		return nil, nil
	}
	if err := m.EnsureDomainCert("api.example.com"); err == nil || !strings.Contains(err.Error(), "multi-SAN") {
		t.Fatalf("expected explicit multi-SAN limitation, got %v", err)
	}
}
