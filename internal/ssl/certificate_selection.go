package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

func normalizedCertName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// Always parse the DER: a caller-supplied Leaf must not bypass validation.
func certificateLeaf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("empty certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate leaf: %w", err)
	}
	for _, der := range cert.Certificate[1:] {
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("parse certificate chain: %w", err)
		}
	}
	return leaf, nil
}

func certificateValidAt(cert *x509.Certificate, now time.Time) bool {
	return cert != nil && !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
}

// Literal wildcard queries are used by management APIs, never expanded to an
// apex or a deeper subdomain. Ordinary hosts use Go's SAN-only TLS semantics.
func certificateMatchesDomain(domain string, cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	domain = normalizedCertName(domain)
	if strings.Contains(domain, "*") {
		if !strings.HasPrefix(domain, "*.") || strings.Contains(domain[2:], "*") {
			return false
		}
		for _, name := range cert.DNSNames {
			if normalizedCertName(name) == domain && cert.VerifyHostname("probe."+domain[2:]) == nil {
				return true
			}
		}
		return false
	}
	return domain != "" && cert.VerifyHostname(domain) == nil
}

func (m *Manager) domainMatchesCert(domain string, cert *tls.Certificate) bool {
	leaf, err := certificateLeaf(cert)
	return err == nil && certificateValidAt(leaf, time.Now()) && certificateMatchesDomain(domain, leaf)
}

// Rank by SAN contents, not by the storage key. Ties use the storage key so
// selection is stable across warm/cold caches and randomized map iteration.
func certificateRank(domain string, cert *tls.Certificate, now time.Time) int {
	leaf, err := certificateLeaf(cert)
	if err != nil {
		return 0
	}
	return certificateLeafRank(domain, leaf, now)
}

func certificateLeafRank(domain string, leaf *x509.Certificate, now time.Time) int {
	if !certificateValidAt(leaf, now) || !certificateMatchesDomain(domain, leaf) {
		return 0
	}
	for _, name := range leaf.DNSNames {
		if normalizedCertName(name) == normalizedCertName(domain) {
			return 2
		}
	}
	if net.ParseIP(domain) != nil {
		return 2
	}
	return 1
}

type indexedCertificate struct {
	key  string
	cert *tls.Certificate
	leaf *x509.Certificate
}

// Call under certMutex. Parsing and sorting happen once per cache generation,
// never per handshake. The index owns parsed DER leaves, not caller-set Leaf.
func (m *Manager) buildCertificateIndexLocked() {
	m.certIndex = make(map[string][]indexedCertificate)
	keys := make([]string, 0, len(m.certCache))
	for key := range m.certCache {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		cert := m.certCache[key]
		leaf, err := certificateLeaf(cert)
		if err != nil {
			continue
		}
		entry := indexedCertificate{key: key, cert: cert, leaf: leaf}
		for _, name := range leaf.DNSNames {
			name = normalizedCertName(name)
			m.certIndex[name] = append(m.certIndex[name], entry)
		}
		for _, ip := range leaf.IPAddresses {
			name := ip.String()
			m.certIndex[name] = append(m.certIndex[name], entry)
		}
	}
}

func (m *Manager) selectCachedCertificate(domain string, wildcardOnly bool) (*tls.Certificate, string) {
	for {
		m.certMutex.RLock()
		if m.certIndex != nil {
			break
		}
		m.certMutex.RUnlock()
		m.certMutex.Lock()
		if m.certIndex == nil {
			m.buildCertificateIndexLocked()
		}
		m.certMutex.Unlock()
	}
	defer m.certMutex.RUnlock()
	indexName := domain
	if ip := net.ParseIP(domain); ip != nil {
		indexName = ip.String()
	}
	var best *tls.Certificate
	var bestKey string
	bestRank := 0
	now := time.Now()
	consider := func(entries []indexedCertificate) {
		for _, entry := range entries {
			rank := certificateLeafRank(domain, entry.leaf, now)
			if wildcardOnly && rank != 1 {
				continue
			}
			if rank > bestRank || (rank > 0 && rank == bestRank && entry.key < bestKey) {
				best, bestKey, bestRank = entry.cert, entry.key, rank
			}
		}
	}
	consider(m.certIndex[indexName])
	if !strings.Contains(domain, "*") && net.ParseIP(domain) == nil {
		if dot := strings.IndexByte(domain, '.'); dot >= 0 {
			consider(m.certIndex["*"+domain[dot:]])
		}
	}
	return best, bestKey
}

// GetCertificate only examines local state. Directory changes expose new exact
// SANs immediately; in-place updates of the selected pair are checked each time.
// Other in-place updates are discovered within certificateReloadInterval.
func (m *Manager) GetCertificate(domain string) (*tls.Certificate, error) {
	domain = normalizedCertName(domain)
	if domain == "" {
		return nil, fmt.Errorf("empty certificate domain")
	}
	m.refreshLocalCertificates()
	cert, key := m.selectCachedCertificate(domain, false)
	if cert != nil {
		m.maybeReloadCertIfStale(key)
		cert, _ = m.selectCachedCertificate(domain, false)
	}
	if cert == nil {
		return nil, fmt.Errorf("no valid local certificate for %s", domain)
	}
	m.failedCacheMutex.Lock()
	delete(m.failedDomainCache, domain)
	m.failedCacheMutex.Unlock()
	return cert, nil
}

func (m *Manager) findWildcardCert(domain string) *tls.Certificate {
	domain = normalizedCertName(domain)
	m.refreshLocalCertificates()
	cert, key := m.selectCachedCertificate(domain, true)
	if cert != nil {
		m.maybeReloadCertIfStale(key)
		cert, _ = m.selectCachedCertificate(domain, true)
	}
	return cert
}

func (m *Manager) loadWildcardCertFromDisk(domain string) *tls.Certificate {
	return m.findWildcardCert(domain)
}

func (m *Manager) loadMatchingCertFromDisk(domain string) (*tls.Certificate, string) {
	m.refreshLocalCertificates()
	return m.selectCachedCertificate(normalizedCertName(domain), false)
}
