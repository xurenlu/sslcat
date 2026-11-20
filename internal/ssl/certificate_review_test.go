package ssl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func TestCertificatePairRestoresOriginalWhenKeyPublishFails(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%v", existing), func(t *testing.T) {
			m := newTestManager(t)
			now := time.Now()
			old := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
			fresh := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
			if existing {
				putFixture(t, m, "api.example.com", old)
				if err := m.LoadCertificateFromDisk("api.example.com"); err != nil {
					t.Fatal(err)
				}
			}
			certPEM, keyPEM, err := encodeCertificatePair(fresh)
			if err != nil {
				t.Fatal(err)
			}
			certPath := filepath.Join(m.config.SSL.CertDir, "api.example.com.crt")
			keyPath := filepath.Join(m.config.SSL.KeyDir, "api.example.com.key")
			keyFailure := errors.New("injected key rename failure")
			renamedCertificate := false
			err = writeCertificatePair(certPath, keyPath, certPEM, keyPEM, func(from, to string) error {
				if to == keyPath {
					if !renamedCertificate {
						t.Fatal("test must fail after the new certificate was published")
					}
					return keyFailure
				}
				if err := os.Rename(from, to); err != nil {
					return err
				}
				renamedCertificate = true
				return nil
			})
			if !errors.Is(err, keyFailure) {
				t.Fatalf("key failure not returned: %v", err)
			}
			if existing {
				pair, err := tls.LoadX509KeyPair(certPath, keyPath)
				if err != nil {
					t.Fatalf("old disk pair was destroyed: %v", err)
				}
				assertSameCertificate(t, &pair, old)
				assertSameCertificate(t, m.getCertificateFromCache("api.example.com"), old)
			} else if _, err := os.Stat(certPath); !os.IsNotExist(err) {
				t.Fatalf("failed first installation left a certificate: %v", err)
			}
			for _, dir := range []string{m.config.SSL.CertDir, m.config.SSL.KeyDir} {
				leftovers, err := filepath.Glob(filepath.Join(dir, ".sslcat-*.tmp"))
				if err != nil || len(leftovers) != 0 {
					t.Fatalf("temporary files left after rollback: %v, %v", leftovers, err)
				}
			}
		})
	}
}

func TestColdPersistenceCannotShrinkDiskSANs(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	old := fixtureCertificate(t, []string{"api.example.com", "other.example.com"}, now.Add(-90*24*time.Hour), now.Add(-time.Hour))
	putFixture(t, m, "api.example.com", old)
	fresh := fixtureRSACertificate(t, "api.example.com", 90*24*time.Hour)
	// Exercise the actual saveCertificate entry used directly by DNS/MCP,
	// without EnsureDomainCert or a loaded cache, including an expired leaf.
	if err := m.saveCertificate("api.example.com", fresh.Certificate, fresh.PrivateKey.(*rsa.PrivateKey)); err == nil || !strings.Contains(err.Error(), "SAN coverage") {
		t.Fatalf("cold persistence accepted SAN shrinkage: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(m.config.SSL.CertDir, "api.example.com.crt"), filepath.Join(m.config.SSL.KeyDir, "api.example.com.key"))
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, &pair, old)
}

func TestBackgroundReusesOnlyCompleteFreshPairsAndRepairsAliases(t *testing.T) {
	for _, state := range []string{"valid", "missing key", "mismatched key", "malformed chain"} {
		t.Run(state, func(t *testing.T) {
			m := newTestManager(t)
			configureOfflineACME(m, false)
			m.config.SSL.Domains = []string{"api.example.com"}
			now := time.Now()
			old := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-90*24*time.Hour), now.Add(-time.Hour))
			fresh := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
			reissued := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(80*24*time.Hour))
			putFixture(t, m, "a-upload", old)
			putFixture(t, m, "z-canonical", fresh)
			keyPath := filepath.Join(m.config.SSL.KeyDir, "z-canonical.key")
			switch state {
			case "missing key":
				if err := os.Remove(keyPath); err != nil {
					t.Fatal(err)
				}
			case "mismatched key":
				_, wrongKey, err := encodeCertificatePair(reissued)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyPath, wrongKey, 0600); err != nil {
					t.Fatal(err)
				}
			case "malformed chain":
				certPEM, _, err := encodeCertificatePair(fresh)
				if err != nil {
					t.Fatal(err)
				}
				certPEM = append(certPEM, []byte("\n-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----\n")...)
				if err := os.WriteFile(filepath.Join(m.config.SSL.CertDir, "z-canonical.crt"), certPEM, 0644); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			m.requestHTTP = func(string) (*tls.Certificate, error) { calls++; return reissued, nil }
			m.renewExpiringCerts()
			wantCalls, want := 1, reissued
			if state == "valid" {
				wantCalls, want = 0, fresh
			}
			if calls != wantCalls {
				t.Fatalf("HTTP requests=%d, want %d", calls, wantCalls)
			}
			for _, alias := range []string{"a-upload", "z-canonical"} {
				pair, err := tls.LoadX509KeyPair(filepath.Join(m.config.SSL.CertDir, alias+".crt"), filepath.Join(m.config.SSL.KeyDir, alias+".key"))
				if err != nil {
					t.Fatalf("alias %s not repaired: %v", alias, err)
				}
				assertSameCertificate(t, &pair, want)
			}
			got, err := m.GetCertificate("api.example.com")
			if err != nil {
				t.Fatal(err)
			}
			assertSameCertificate(t, got, want)
		})
	}
}

func TestAliasSynchronizationAggregatesWriteFailures(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	old := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	fresh := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
	for _, alias := range []string{"alias-one", "alias-two"} {
		putFixture(t, m, alias, old)
		// A directory destination deterministically fails the key rename even
		// when tests run as root; the certificate half must be rolled back.
		keyPath := filepath.Join(m.config.SSL.KeyDir, alias+".key")
		if err := os.Remove(keyPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(keyPath, 0700); err != nil {
			t.Fatal(err)
		}
	}
	aliases := m.renewalCandidates()
	if err := m.persistIssuedCertificate("api.example.com", fresh); err != nil {
		t.Fatal(err)
	}
	err := m.syncRenewedAliases("api.example.com", aliases)
	if err == nil || !strings.Contains(err.Error(), "alias-one") || !strings.Contains(err.Error(), "alias-two") {
		t.Fatalf("missing aggregate alias failures: %v", err)
	}
	for _, alias := range aliases {
		leaf, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, alias.key+".crt"))
		if err != nil || !bytes.Equal(leaf.Raw, old.Certificate[0]) {
			t.Fatalf("failed alias write changed original %s: %v", alias.key, err)
		}
	}
}

func fixtureRSACertificate(t *testing.T, domain string, lifetime time.Duration) *tls.Certificate {
	t.Helper()
	fixture := fixtureCertificate(t, []string{domain}, time.Now().Add(-time.Hour), time.Now().Add(lifetime))
	leaf, err := certificateLeaf(fixture)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf.SignatureAlgorithm = x509.SHA256WithRSA
	leaf.PublicKey, leaf.PublicKeyAlgorithm = &key.PublicKey, x509.RSA
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type offlineACMETransport struct{ calls atomic.Int32 }

func (tr *offlineACMETransport) RoundTrip(*http.Request) (*http.Response, error) {
	tr.calls.Add(1)
	return nil, errors.New("ACME network forbidden in offline regression")
}

func configureRealOfflineAutocert(t *testing.T, m *Manager, cert *tls.Certificate) (*offlineACMETransport, autocert.DirCache) {
	t.Helper()
	cache := autocert.DirCache(t.TempDir())
	certPEM, keyPEM, err := encodeCertificatePair(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Put(context.Background(), "api.example.com+rsa", append(keyPEM, certPEM...)); err != nil {
		t.Fatal(err)
	}
	transport := &offlineACMETransport{}
	m.config.SSL.Domains = []string{"api.example.com"}
	m.acmeMgr = &autocert.Manager{
		Prompt: autocert.AcceptTOS, Cache: cache,
		// Keep autocert's own timer away from this short, offline test. Its
		// normal production renewal scheduling and HTTPHandler are untouched.
		RenewBefore: time.Second,
		Client:      &acme.Client{HTTPClient: &http.Client{Transport: transport}},
	}
	return transport, cache
}

func TestHTTPRealAutocertDiskAndMemoryCacheCannotClaimRenewal(t *testing.T) {
	m := newTestManager(t)
	old := fixtureRSACertificate(t, "api.example.com", 10*24*time.Hour)
	putFixture(t, m, "api.example.com", old)
	transport, cache := configureRealOfflineAutocert(t, m, old)
	for attempt := 0; attempt < 2; attempt++ {
		if attempt == 1 {
			// Deleting the actual RSA disk key still leaves autocert's in-memory
			// leaf. Both paths must produce an explicit renewal failure.
			if err := cache.Delete(context.Background(), "api.example.com+rsa"); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.EnsureDomainCert("api.example.com"); err == nil || !strings.Contains(err.Error(), "expiring autocert leaf") {
			t.Fatalf("cached autocert leaf reported success: %v", err)
		}
		leaf, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, "api.example.com.crt"))
		if err != nil || !bytes.Equal(leaf.Raw, old.Certificate[0]) {
			t.Fatalf("cached HTTP result replaced original: %v", err)
		}
	}
	if transport.calls.Load() != 0 {
		t.Fatal("real autocert cache regression attempted an ACME network request")
	}
}

func TestHTTPRealAutocertFreshLeafCanBePublished(t *testing.T) {
	m := newTestManager(t)
	old := fixtureCertificate(t, []string{"api.example.com"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	putFixture(t, m, "api.example.com", old)
	fresh := fixtureRSACertificate(t, "api.example.com", 90*24*time.Hour)
	transport, _ := configureRealOfflineAutocert(t, m, fresh)
	if err := m.EnsureDomainCert("api.example.com"); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetCertificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, fresh)
	// Even a long-lived cached leaf cannot be called a new issuance again.
	if err := m.EnsureDomainCert("api.example.com"); err == nil || !strings.Contains(err.Error(), "existing certificate") {
		t.Fatalf("unchanged long-lived leaf reported a new issuance: %v", err)
	}
	if transport.calls.Load() != 0 {
		t.Fatal("fresh cache retrieval attempted an ACME network request")
	}
}

func TestAliasProgressKeepsRequestIdentityAndFinalOutcome(t *testing.T) {
	for _, failAliasWrite := range []bool{false, true} {
		t.Run(fmt.Sprintf("failAliasWrite=%v", failAliasWrite), func(t *testing.T) {
			m := newTestManager(t)
			configureOfflineACME(m, true)
			now := time.Now()
			old := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
			fresh := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-time.Minute), now.Add(90*24*time.Hour))
			putFixture(t, m, "opaque-upload", old)
			ch := m.CreateProgressChannel("api.example.com")
			m.requestDNS = func(domain, provider string) error {
				if domain != "*.example.com" || provider != "offline" {
					t.Fatalf("unexpected DNS identity %s/%s", domain, provider)
				}
				m.sendProgressEvent(domain, CertProgressEvent{Status: "dns_init"})
				if err := m.persistIssuedCertificate(domain, fresh); err != nil {
					return err
				}
				if failAliasWrite {
					keyPath := filepath.Join(m.config.SSL.KeyDir, "opaque-upload.key")
					if err := os.Remove(keyPath); err != nil {
						return err
					}
					return os.Mkdir(keyPath, 0700)
				}
				return nil
			}
			err := m.EnsureDomainCert("api.example.com")
			if (err != nil) != failAliasWrite {
				t.Fatalf("request result=%v, want alias failure=%v", err, failAliasWrite)
			}
			seen := make(map[string]int)
			var last CertProgressEvent
			for len(ch) > 0 {
				last = <-ch
				if last.Domain != "api.example.com" {
					t.Fatalf("SSE used issuance identity: %+v", last)
				}
				seen[last.Status]++
			}
			wantTerminal := "success"
			if failAliasWrite {
				wantTerminal = "failed"
				if seen["success"] != 0 {
					t.Fatal("SSE reported success before alias persistence failed")
				}
			}
			if seen["started"] != 1 || seen["dns_init"] != 1 || seen[wantTerminal] != 1 || last.Status != wantTerminal {
				t.Fatalf("missing request progress or terminal event: %v, last=%+v", seen, last)
			}
		})
	}
}

type recordingDNSProvider struct {
	DNSProviderInterface
	zone          string
	sets, deletes int
	setError      error
}

func (p *recordingDNSProvider) ListDomains(context.Context) ([]DomainInfo, error) {
	return []DomainInfo{{Name: p.zone, Type: "domain"}}, nil
}

func (p *recordingDNSProvider) SetTXTRecord(context.Context, string, string, string, int) error {
	p.sets++
	return p.setError
}

func (p *recordingDNSProvider) DeleteTXTRecord(context.Context, string, string) error {
	p.deletes++
	return nil
}

func TestWildcardDiscoveryAndChallengeStayOnSelectedDNSProvider(t *testing.T) {
	for _, tc := range []struct{ domain, zone string }{
		{"*.example.co.uk", "example.co.uk"},
		{"*.sub.example.com", "sub.example.com"},
		{"api.sub.example.com", "sub.example.com"},
		{"*.SUB.EXAMPLE.COM.", "sub.example.com."},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			m := newTestManager(t)
			unrelated := &recordingDNSProvider{zone: "unrelated.example"}
			target := &recordingDNSProvider{zone: tc.zone}
			m.dnsManager.RegisterProviderWithPriority("unrelated", unrelated, 0)
			m.dnsManager.RegisterProviderWithPriority("target", target, 100)
			selected := m.findDNSProviderForDomain(tc.domain)
			if selected != "target" {
				t.Fatalf("wildcard/delegated zone selected %q", selected)
			}
			cleanup, err := m.dnsManager.presentDNSChallenge(context.Background(), strings.TrimPrefix(normalizedCertName(tc.domain), "*."), "_acme-challenge", "offline-record", selected)
			if err != nil {
				t.Fatal(err)
			}
			// Re-registering the same name must not redirect cleanup elsewhere.
			replacement := &recordingDNSProvider{zone: tc.zone}
			m.dnsManager.RegisterProvider("target", replacement)
			if err := cleanup(); err != nil {
				t.Fatal(err)
			}
			if unrelated.sets+unrelated.deletes+replacement.sets+replacement.deletes != 0 || target.sets != 1 || target.deletes != 1 {
				t.Fatalf("challenge escaped selected instance: unrelated=%+v target=%+v replacement=%+v", unrelated, target, replacement)
			}
		})
	}
}

func TestSelectedDNSProviderFailureDoesNotFailOverToOtherZones(t *testing.T) {
	m := newTestManager(t)
	unrelated := &recordingDNSProvider{zone: "unrelated.example"}
	failure := errors.New("offline provider failure")
	target := &recordingDNSProvider{zone: "example.com", setError: failure}
	m.dnsManager.RegisterProviderWithPriority("unrelated", unrelated, 0)
	m.dnsManager.RegisterProviderWithPriority("target", target, 100)
	cleanup, err := m.dnsManager.presentDNSChallenge(context.Background(), "example.com", "_acme-challenge", "offline-record", "target")
	if !errors.Is(err, failure) || cleanup != nil || unrelated.sets != 0 || target.sets != 1 {
		t.Fatalf("unexpected DNS fallback or failure: cleanup=%v err=%v sets=%d/%d", cleanup != nil, err, unrelated.sets, target.sets)
	}
	if got := m.findDNSProviderForDomain("notexample.com"); got != "" {
		t.Fatalf("zone suffix matched without a label boundary: %s", got)
	}
}

func TestWarmLookupReusesScanAndSANIndexButFindsNewExactImmediately(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	wild := fixtureCertificate(t, []string{"*.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	putFixture(t, m, "wildcard", wild)
	for i := 0; i < 64; i++ {
		cert := fixtureCertificate(t, []string{fmt.Sprintf("host-%d.unrelated.test", i)}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
		putFixture(t, m, fmt.Sprintf("unrelated-%03d", i), cert)
	}
	if _, err := m.GetCertificate("api.example.com"); err != nil {
		t.Fatal(err)
	}
	m.certStoreMu.Lock()
	scanAt := m.certLastScan
	m.certStoreMu.Unlock()
	m.certMutex.RLock()
	indexedLeaf := m.certIndex["*.example.com"][0].leaf
	m.certMutex.RUnlock()
	for i := 0; i < 50; i++ {
		got, err := m.GetCertificate("api.example.com")
		if err != nil {
			t.Fatal(err)
		}
		assertSameCertificate(t, got, wild)
	}
	m.certStoreMu.Lock()
	rescanned := !m.certLastScan.Equal(scanAt)
	m.certStoreMu.Unlock()
	m.certMutex.RLock()
	reparsed := m.certIndex["*.example.com"][0].leaf != indexedLeaf
	m.certMutex.RUnlock()
	if rescanned || reparsed {
		t.Fatalf("warm lookups repeated full scan/DER parsing: scan=%v parse=%v", rescanned, reparsed)
	}
	// An opaque exact-SAN upload changes directory metadata and must beat the
	// warm wildcard on the very next lookup, without waiting for the timer.
	exact := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(80*24*time.Hour))
	putFixture(t, m, "opaque-new-exact", exact)
	got, err := m.GetCertificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, exact)
}

func TestUnchangedBadPairIsNotReparsedAndKeyRepairIsImmediate(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	old := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	fresh := fixtureCertificate(t, []string{"api.example.com"}, now.Add(-time.Minute), now.Add(80*24*time.Hour))
	putFixture(t, m, "api.example.com", old)
	if _, err := m.GetCertificate("api.example.com"); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := encodeCertificatePair(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.config.SSL.CertDir, "api.example.com.crt"), certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCertificate("api.example.com"); err != nil {
		t.Fatal(err)
	}
	m.certStoreMu.Lock()
	failure := m.certLoadFailures["api.example.com"]
	m.certStoreMu.Unlock()
	if failure.err == nil {
		t.Fatal("expected a rejected mismatched pair")
	}
	for i := 0; i < 20; i++ {
		got, err := m.GetCertificate("api.example.com")
		if err != nil {
			t.Fatal(err)
		}
		assertSameCertificate(t, got, old)
	}
	m.certStoreMu.Lock()
	retried := !m.certLoadFailures["api.example.com"].retryAt.Equal(failure.retryAt)
	m.certStoreMu.Unlock()
	if retried {
		t.Fatal("unchanged bad pair was read and parsed again on warm handshakes")
	}
	if err := os.WriteFile(filepath.Join(m.config.SSL.KeyDir, "api.example.com.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetCertificate("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	assertSameCertificate(t, got, fresh)
}
