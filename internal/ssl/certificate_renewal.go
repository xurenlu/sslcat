package ssl

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	certificateRenewalWindow   = 30 * 24 * time.Hour
	certificateRenewalCooldown = time.Hour
)

func readDiskCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM in %s", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func certificateNeedsRenewal(cert *x509.Certificate, now time.Time) bool {
	return cert != nil && cert.NotAfter.Before(now.Add(certificateRenewalWindow))
}

func (m *Manager) isCertExpiringSoon(path string) bool {
	cert, err := readDiskCertificate(path)
	return err == nil && certificateNeedsRenewal(cert, time.Now())
}

func renewalNames(cert *x509.Certificate) ([]string, error) {
	if cert == nil || len(cert.DNSNames) == 0 || len(cert.IPAddresses) != 0 {
		return nil, fmt.Errorf("automatic renewal requires DNS SANs without IP SANs")
	}
	names := make([]string, 0, len(cert.DNSNames))
	seen := make(map[string]bool)
	for _, name := range cert.DNSNames {
		name = normalizedCertName(name)
		if !validCertKey(name) || !certificateMatchesDomain(name, cert) {
			return nil, fmt.Errorf("invalid renewal SAN %q", name)
		}
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	sort.Strings(names)
	return names, nil
}

// An empty provider selects HTTP; once DNS is selected failures are terminal.
// Wildcards always require DNS, even when HTTP is enabled in configuration.
func (m *Manager) selectChallenge(domain string) (string, error) {
	if m.acmeMgr == nil {
		return "", fmt.Errorf("ACME not enabled for %s", domain)
	}
	if m.supportsDNSChallenge() && m.hasAvailableDNSProvider() {
		if provider := m.findDNSProviderForDomain(domain); provider != "" {
			return provider, nil
		}
	}
	if strings.Contains(domain, "*") {
		return "", fmt.Errorf("wildcard %s requires DNS-01 and a matching DNS provider", domain)
	}
	if !m.supportsHTTPChallenge() {
		return "", fmt.Errorf("no supported challenge and provider for %s", domain)
	}
	return "", nil
}

func (m *Manager) issueDNSCertificate(domain, provider string) error {
	if m.requestDNS != nil {
		return m.requestDNS(domain, provider)
	}
	return m.RequestCertificateWithDNS(domain, provider)
}

func (m *Manager) issueHTTPCertificate(domain string) (*tls.Certificate, error) {
	var cert *tls.Certificate
	var err error
	if m.requestHTTP != nil {
		cert, err = m.requestHTTP(domain)
	} else {
		// autocert's RSA disk key is domain+"+rsa", and disk eviction cannot
		// evict its in-memory state. Keep its caches intact and reject a cached
		// old leaf explicitly instead of claiming that proactive renewal worked.
		cert, err = m.acmeMgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	}
	if err != nil {
		return nil, err
	}
	if err := validateIssuedCertificate(domain, cert); err != nil {
		return nil, err
	}
	leaf, _ := certificateLeaf(cert)
	if certificateNeedsRenewal(leaf, time.Now()) {
		return nil, fmt.Errorf("HTTP issuance for %s returned an expiring autocert leaf; proactive renewal is unavailable until autocert renews it", domain)
	}
	for _, previous := range m.renewalCandidates() {
		if certificateMatchesDomain(domain, previous.leaf) && bytes.Equal(leaf.Raw, previous.leaf.Raw) {
			return nil, fmt.Errorf("HTTP issuance for %s returned an existing certificate; no new certificate was issued", domain)
		}
	}
	if previous, parseErr := certificateLeaf(m.getCertificateFromCache(domain)); parseErr == nil && bytes.Equal(previous.Raw, leaf.Raw) {
		return nil, fmt.Errorf("HTTP issuance for %s returned the existing cached certificate", domain)
	}
	return cert, nil
}

// EnsureDomainCert remains the explicitly requested/manual entry point. Only
// this entry grants temporary authorization; the background worker never does.
func (m *Manager) EnsureDomainCert(domain string) (resultErr error) {
	if m.acmeMgr == nil {
		return nil
	}
	progressDomain := domain
	start := time.Now()
	defer func() {
		event := CertProgressEvent{Domain: progressDomain, Status: "success", Progress: 100, Timestamp: time.Now(), Message: "证书申请成功"}
		if resultErr != nil {
			event.Status, event.Progress, event.Error = "failed", 0, resultErr.Error()
			event.Message = "证书申请失败"
		} else if m.notificationIntegrator != nil && m.acmeMgr != nil {
			m.notificationIntegrator.SendCertSuccessNotification(progressDomain, 1, time.Since(start))
		}
		m.sendRequestProgressEvent(progressDomain, event)
	}()
	domain = normalizedCertName(domain)
	if !validCertKey(domain) {
		return fmt.Errorf("invalid certificate domain %q", domain)
	}
	// A storage alias does not define the order identity. Preserve all SANs
	// of an existing disk/cache certificate rather than silently shrinking it.
	leaf, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, domain+".crt"))
	if err != nil {
		leaf, _ = certificateLeaf(m.getCertificateFromCache(domain))
	}
	candidates := m.renewalCandidates()
	if leaf == nil {
		// Cold CLI invocations must also find historical upload aliases.
		bestRank := 0
		for _, candidate := range candidates {
			if !certificateMatchesDomain(domain, candidate.leaf) {
				continue
			}
			rank := 1
			for _, name := range candidate.names {
				if name == domain {
					rank = 2
				}
			}
			if rank > bestRank {
				leaf, bestRank = candidate.leaf, rank
			}
		}
	}
	if leaf != nil {
		names, err := renewalNames(leaf)
		if err != nil {
			return err
		}
		if len(names) != 1 {
			return fmt.Errorf("multi-SAN renewal is unsupported; retaining certificate for %v", names)
		}
		domain = names[0]
	}
	unlock := m.lockCertRequest(domain)
	defer unlock()
	// Challenge events use the issued SAN internally; SSE belongs to the
	// original requested alias. Register only while holding its request lock.
	unroute := m.routeProgressIdentity(domain, progressDomain)
	defer unroute()
	m.AllowDomainTemporary(domain, 24*time.Hour)
	if err := m.ensureDomainCertWithRetry(domain, 1); err != nil {
		return err
	}
	var aliases []renewalCandidate
	for _, candidate := range candidates {
		if len(candidate.names) == 1 && candidate.names[0] == domain {
			aliases = append(aliases, candidate)
		}
	}
	return m.syncRenewedAliases(domain, aliases)
}

type renewalCandidate struct {
	key   string
	leaf  *x509.Certificate
	names []string
}

func (m *Manager) renewalCandidates() []renewalCandidate {
	entries, err := os.ReadDir(m.config.SSL.CertDir)
	if err != nil {
		m.log.Debugf("Renewal scan skipped: %v", err)
		return nil
	}
	var candidates []renewalCandidate
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		leaf, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, entry.Name()))
		if err != nil {
			continue
		}
		names, err := renewalNames(leaf)
		if err != nil {
			m.log.Warnf("Certificate %s cannot be automatically renewed: %v", entry.Name(), err)
			continue
		}
		candidates = append(candidates, renewalCandidate{key: strings.TrimSuffix(entry.Name(), ".crt"), leaf: leaf, names: names})
	}
	return candidates
}

func (m *Manager) renewExpiringCerts() {
	// Serialize scans, then re-read disk while holding the per-identity request
	// lock. A queued background scan must not issue again after a CLI renewal.
	m.renewalMu.Lock()
	defer m.renewalMu.Unlock()
	seen := make(map[string]bool)
	for _, candidate := range m.renewalCandidates() {
		identity := strings.Join(candidate.names, ",")
		if seen[identity] || !certificateNeedsRenewal(candidate.leaf, time.Now()) {
			continue
		}
		seen[identity] = true
		m.renewCandidate(candidate, identity)
	}
}

func (m *Manager) renewCandidate(candidate renewalCandidate, identity string) {
	unlock := m.lockCertRequest(identity)
	defer unlock()
	current := m.renewalCandidates()
	var aliases []renewalCandidate
	var reusable *tls.Certificate
	for _, other := range current {
		if strings.Join(other.names, ",") != identity {
			continue
		}
		aliases = append(aliases, other)
		if reusable != nil || certificateNeedsRenewal(other.leaf, time.Now()) || !certificateValidAt(other.leaf, time.Now()) {
			continue
		}
		// A fresh .crt alone cannot satisfy renewal: its private key may be
		// missing, mismatched, or its chain malformed. Validate the pair under
		// the same store lock used by issuance and hot reload before reusing it.
		m.certStoreMu.Lock()
		if err := m.loadCertificateLocked(other.key, true); err == nil {
			cert := m.getCertificateFromCache(other.key)
			leaf, err := certificateLeaf(cert)
			if err == nil && strings.Join(other.names, ",") == identity && bytes.Equal(leaf.Raw, other.leaf.Raw) {
				reusable = cert
			}
		}
		m.certStoreMu.Unlock()
	}
	if len(aliases) == 0 {
		return
	}
	if reusable != nil {
		if err := m.syncCertificateAliases(reusable, aliases); err != nil {
			m.reportRenewalFailure(identity, err)
		}
		return
	}
	for _, name := range candidate.names {
		if !m.isAllowedDomain(name) {
			m.log.Warnf("Automatic renewal denied for unconfigured SAN %s (file %s)", name, candidate.key)
			return
		}
	}
	if until := m.renewalFailures[identity]; time.Now().Before(until) {
		return
	}
	if m.renewalFailures == nil {
		m.renewalFailures = make(map[string]time.Time)
	}
	m.renewalFailures[identity] = time.Now().Add(certificateRenewalCooldown)
	// The current issuer accepts a single SAN. Fail explicitly for multi-SAN
	// certificates; never order just the filename or first SAN.
	if len(candidate.names) != 1 {
		m.reportRenewalFailure(identity, fmt.Errorf("multi-SAN automatic renewal is unsupported; retaining coverage %v", candidate.names))
		return
	}
	domain := candidate.names[0]
	// Self-signed leaves alone may use the existing self-signed renewal path.
	// A failed public-CA renewal must never replace its leaf with self-signing.
	selfSigned := true
	for _, alias := range aliases {
		leaf := alias.leaf
		if !bytes.Equal(leaf.RawSubject, leaf.RawIssuer) || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
			selfSigned = false
			break
		}
	}
	var err error
	if m.acmeMgr != nil {
		err = m.ensureDomainCertWithRetry(domain, 1)
	} else if selfSigned && !m.config.SSL.DisableSelfSigned {
		_, err = m.generateSelfSignedCert(domain)
	} else {
		err = fmt.Errorf("ACME unavailable for %s", domain)
	}
	if err != nil {
		m.reportRenewalFailure(domain, err)
		return
	}
	if err := m.syncRenewedAliases(domain, aliases); err != nil {
		m.reportRenewalFailure(domain, err)
		return
	}
	if m.notificationIntegrator != nil {
		m.notificationIntegrator.SendCertSuccessNotification(domain, 1, 0)
	}
}

func (m *Manager) syncRenewedAliases(domain string, aliases []renewalCandidate) error {
	cert := m.getCertificateFromCache(domain)
	if err := validateIssuedCertificate(domain, cert); err != nil {
		return err
	}
	return m.syncCertificateAliases(cert, aliases)
}

func (m *Manager) syncCertificateAliases(cert *tls.Certificate, aliases []renewalCandidate) error {
	leaf, err := certificateLeaf(cert)
	if err != nil {
		return fmt.Errorf("parse renewed certificate for alias synchronization: %w", err)
	}
	if !certificateValidAt(leaf, time.Now()) {
		return fmt.Errorf("renewed certificate is outside its validity period during alias synchronization")
	}
	var failures []error
	// Keep historical aliases in sync so an old exact-SAN alias cannot win
	// deterministic selection over the renewed certificate's canonical file.
	for _, alias := range aliases {
		if err := m.syncCertificateAlias(cert, leaf, alias); err != nil {
			failures = append(failures, fmt.Errorf("synchronize certificate alias %s: %w", alias.key, err))
		}
	}
	return errors.Join(failures...)
}

func (m *Manager) syncCertificateAlias(cert *tls.Certificate, leaf *x509.Certificate, alias renewalCandidate) error {
	m.certStoreMu.Lock()
	defer m.certStoreMu.Unlock()
	latest, err := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, alias.key+".crt"))
	if err != nil {
		return fmt.Errorf("read current alias: %w", err)
	}
	if !certificateCoversPrevious(leaf, latest) {
		return fmt.Errorf("renewed certificate removes current alias SAN coverage")
	}
	if bytes.Equal(latest.Raw, leaf.Raw) {
		if err := m.loadCertificateLocked(alias.key, true); err == nil {
			return nil
		}
	} else if !bytes.Equal(latest.Raw, alias.leaf.Raw) {
		return fmt.Errorf("alias changed during renewal; retaining external update")
	}
	if err := m.writeCertificateLocked(alias.key, cert); err != nil {
		return fmt.Errorf("save alias: %w", err)
	}
	if err := m.loadCertificateLocked(alias.key, true); err != nil {
		return fmt.Errorf("load alias: %w", err)
	}
	return nil
}

func (m *Manager) reportRenewalFailure(domain string, err error) {
	m.log.Errorf("Automatic certificate renewal failed for %s: %v", domain, err)
	if m.notificationIntegrator != nil {
		m.notificationIntegrator.SendCertFailedNotification(domain, err.Error())
	}
}
