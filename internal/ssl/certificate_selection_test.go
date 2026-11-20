package ssl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Fixtures are entirely ephemeral; no real credentials, DNS or CA are used.
func fixtureCertificate(t *testing.T, names []string, before, after time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "fixture.invalid"},
		NotBefore: before, NotAfter: after, DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: "Offline test CA"}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func putFixture(t *testing.T, m *Manager, key string, cert *tls.Certificate) {
	t.Helper()
	if err := m.saveCertificateToDisk(key, cert); err != nil {
		t.Fatal(err)
	}
}

func assertSameCertificate(t *testing.T, got, want *tls.Certificate) {
	t.Helper()
	if got == nil || !bytes.Equal(got.Certificate[0], want.Certificate[0]) {
		t.Fatal("selected a different certificate")
	}
}

func TestCertificateSelectionExactBeforeWildcard(t *testing.T) {
	now := time.Now()
	for _, expiredWildcard := range []bool{false, true} {
		for _, warm := range []bool{false, true} {
			t.Run(map[bool]string{false: "valid", true: "expired"}[expiredWildcard]+map[bool]string{false: "cold", true: "warm"}[warm], func(t *testing.T) {
				m := newTestManager(t)
				deadline := now.Add(80 * 24 * time.Hour)
				if expiredWildcard {
					deadline = now.Add(-time.Hour)
				}
				wild := fixtureCertificate(t, []string{"*.niuwoai.com"}, now.Add(-90*24*time.Hour), deadline)
				exact := fixtureCertificate(t, []string{"api.niuwoai.com"}, now.Add(-time.Hour), now.Add(60*24*time.Hour))
				putFixture(t, m, "qlite", wild)
				// An exact filename containing only a wildcard earns no exact rank.
				putFixture(t, m, "api.niuwoai.com", wild)
				if warm {
					m.certCache["qlite"] = wild
					m.certCache["api.niuwoai.com"] = wild
				}
				putFixture(t, m, "z-independent", exact)
				for i := 0; i < 10; i++ {
					got, err := m.GetCertificate("API.NIUWOAI.COM.")
					if err != nil {
						t.Fatal(err)
					}
					assertSameCertificate(t, got, exact)
				}
			})
		}
	}
}

func TestCertificateSelectionStableTie(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	first := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	second := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(2*time.Hour))
	putFixture(t, m, "a", first)
	putFixture(t, m, "z", second)
	for i := 0; i < 20; i++ {
		got, err := m.GetCertificate("api.example.com")
		if err != nil {
			t.Fatal(err)
		}
		assertSameCertificate(t, got, first)
	}
}

func TestCertificateSANAndValidityValidation(t *testing.T) {
	m := newTestManager(t)
	now := time.Now().Truncate(time.Second)
	wild := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	exact := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	cnOnly := fixtureCertificate(t, nil, now.Add(-time.Hour), now.Add(time.Hour))
	cases := []struct {
		name   string
		domain string
		cert   *tls.Certificate
		want   bool
	}{
		{"wildcard", "api.example.com", wild, true},
		{"apex", "example.com", wild, false},
		{"deep", "a.b.example.com", wild, false},
		{"literal wildcard management", "*.example.com", wild, true},
		{"different literal wildcard", "*.other.com", wild, false},
		{"exact", "API.EXAMPLE.COM.", exact, true},
		{"wrong SAN", "other.example.com", exact, false},
		{"CN only", "fixture.invalid", cnOnly, false},
		{"nil", "api.example.com", nil, false},
		{"empty", "api.example.com", &tls.Certificate{}, false},
		{"malformed DER", "api.example.com", &tls.Certificate{Certificate: [][]byte{[]byte("invalid")}, Leaf: &x509.Certificate{DNSNames: []string{"api.example.com"}}}, false},
		{"expired", "api.example.com", fixtureCertificate(t, []string{"api.example.com"}, now.Add(-2*time.Hour), now.Add(-time.Second)), false},
		{"future", "api.example.com", fixtureCertificate(t, []string{"api.example.com"}, now.Add(time.Hour), now.Add(2*time.Hour)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.domainMatchesCert(tc.domain, tc.cert); got != tc.want {
				t.Fatalf("match = %v, want %v", got, tc.want)
			}
		})
	}
	boundary := &x509.Certificate{NotBefore: now, NotAfter: now.Add(time.Hour)}
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{
		{now.Add(-time.Nanosecond), false}, {now, true}, {now.Add(time.Hour), true}, {now.Add(time.Hour + time.Nanosecond), false},
	} {
		if got := certificateValidAt(boundary, tc.at); got != tc.want {
			t.Fatalf("valid at %v = %v, want %v", tc.at, got, tc.want)
		}
	}
	if !certificateMatchesDomain("192.0.2.1", &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}}) {
		t.Fatal("IP SAN must use VerifyHostname semantics")
	}
}

func TestHotReloadAcceptsShorterValidityAndPreservesGoodMemory(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	old := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	next := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(45*24*time.Hour))
	putFixture(t, m, "api.example.com", old)
	if err := m.LoadCertificateFromDisk("api.example.com"); err != nil {
		t.Fatal(err)
	}
	putFixture(t, m, "api.example.com", next)
	// Detect replacement even if a copier preserved the mtime.
	st, err := os.Stat(filepath.Join(m.config.SSL.CertDir, "api.example.com.crt"))
	if err != nil {
		t.Fatal(err)
	}
	m.reloadAllCachedCertsIfCertFilesStale()
	assertSameCertificate(t, m.getCertificateFromCache("api.example.com"), next)
	bad := []*tls.Certificate{
		fixtureCertificate(t, []string{"other.example.com"}, now.Add(-time.Hour), now.Add(time.Hour)),
		fixtureCertificate(t, []string{"api.example.com"}, now.Add(time.Hour), now.Add(2*time.Hour)),
		fixtureCertificate(t, []string{"api.example.com"}, now.Add(-2*time.Hour), now.Add(-time.Hour)),
	}
	for _, cert := range bad {
		putFixture(t, m, "api.example.com", cert)
		if err := m.LoadCertificateFromDisk("api.example.com"); err == nil {
			t.Fatal("bad replacement should fail validation")
		}
		got, err := m.GetCertificate("api.example.com")
		if err != nil {
			t.Fatal(err)
		}
		assertSameCertificate(t, got, next)
	}
	path := filepath.Join(m.config.SSL.CertDir, "api.example.com.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}), 0644); err != nil {
		t.Fatal(err)
	}
	m.maybeReloadCertIfStale("api.example.com")
	assertSameCertificate(t, m.getCertificateFromCache("api.example.com"), next)
	putFixture(t, m, "api.example.com", next)
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	m.maybeReloadCertIfStale("api.example.com")
	assertSameCertificate(t, m.getCertificateFromCache("api.example.com"), next)
}

func TestNewCertificateBypassesNegativeCaches(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.GetCertificate("pub.example.com"); err == nil {
		t.Fatal("expected initial miss")
	}
	m.failedDomainCache["pub.example.com"] = time.Now().Add(15 * time.Minute)
	m.certMetadataCache["pub.example.com"] = &certMetadata{exists: false, lastChecked: time.Now()}
	cert := fixtureCertificate(t, []string{"*.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	putFixture(t, m, "historical-alias", cert)
	got, err := m.GetCertificate("pub.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, cert)
}

func TestConcurrentLocalCertificateReload(t *testing.T) {
	m := newTestManager(t)
	start := time.Now()
	certs := []*tls.Certificate{
		fixtureCertificate(t, []string{"api.example.com"}, start.Add(-time.Hour), start.Add(90*24*time.Hour)),
		fixtureCertificate(t, []string{"api.example.com"}, start.Add(-time.Minute), start.Add(45*24*time.Hour)),
	}
	putFixture(t, m, "api.example.com", certs[0])
	if err := m.LoadCertificateFromDisk("api.example.com"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				if cert, err := m.GetCertificate("api.example.com"); err != nil || !m.domainMatchesCert("api.example.com", cert) {
					t.Errorf("concurrent lookup failed: %v", err)
				}
				m.reloadAllCachedCertsIfCertFilesStale()
			}
		}()
	}
	for i := 0; i < 20; i++ {
		putFixture(t, m, "api.example.com", certs[i%2])
	}
	wg.Wait()
	// Queued loaders must read the latest disk generation after obtaining the
	// store lock, rather than publishing a snapshot read before the lock.
	m.certStoreMu.Lock()
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.LoadCertificateFromDisk("api.example.com"); err != nil {
				t.Error(err)
			}
		}()
	}
	err := m.writeCertificateLocked("api.example.com", certs[1])
	m.certStoreMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	assertSameCertificate(t, m.getCertificateFromCache("api.example.com"), certs[1])
}

func TestTLSHandshakeLookupDoesNotIssueOrServeWrongSAN(t *testing.T) {
	m := newTestManager(t)
	calls := 0
	m.requestHTTP = func(string) (*tls.Certificate, error) { calls++; return nil, nil }
	m.requestDNS = func(string, string) error { calls++; return nil }
	m.defaultCert = fixtureCertificate(t, []string{"localhost"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if _, err := m.GetTLSConfig().GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); err == nil {
		t.Fatal("wrong-SAN default certificate must not be served")
	}
	if calls != 0 {
		t.Fatal("handshake triggered issuance")
	}
}
