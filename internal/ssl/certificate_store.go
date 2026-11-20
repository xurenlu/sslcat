package ssl

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const certificateReloadInterval = 45 * time.Second

type certDiskState struct {
	cert os.FileInfo
	key  os.FileInfo
}

type certLoadFailure struct {
	state   certDiskState
	retryAt time.Time
	err     error
}

func sameCertFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

func (s certDiskState) equal(other certDiskState) bool {
	return sameCertFile(s.cert, other.cert) && sameCertFile(s.key, other.key)
}

func validCertKey(key string) bool {
	return key != "" && key != "." && key != ".." && !strings.ContainsAny(key, "/\\\x00")
}

func (m *Manager) diskState(key string) (certDiskState, error) {
	if !validCertKey(key) {
		return certDiskState{}, fmt.Errorf("invalid certificate storage key %q", key)
	}
	cert, err := os.Stat(filepath.Join(m.config.SSL.CertDir, key+".crt"))
	if err != nil {
		return certDiskState{}, fmt.Errorf("stat certificate %s: %w", key, err)
	}
	privateKey, err := os.Stat(filepath.Join(m.config.SSL.KeyDir, key+".key"))
	if err != nil {
		return certDiskState{}, fmt.Errorf("stat certificate key %s: %w", key, err)
	}
	return certDiskState{cert: cert, key: privateKey}, nil
}

func certificateCoversPrevious(next, previous *x509.Certificate) bool {
	for _, name := range previous.DNSNames {
		if !certificateMatchesDomain(name, next) {
			return false
		}
	}
	for _, ip := range previous.IPAddresses {
		if next.VerifyHostname(ip.String()) != nil {
			return false
		}
	}
	return true
}

// Call with certStoreMu held. A separate lock from certRequestLocks avoids a
// deadlock when issuance saves and immediately reloads its own certificate.
func (m *Manager) loadCertificateLocked(key string, force bool) (resultErr error) {
	before, err := m.diskState(key)
	if err != nil {
		return err
	}
	if !force {
		if m.certDiskState[key].equal(before) {
			return nil
		}
		if failed, ok := m.certLoadFailures[key]; ok && failed.state.equal(before) && time.Now().Before(failed.retryAt) {
			return failed.err
		}
	}
	defer func() {
		if resultErr != nil {
			if m.certLoadFailures == nil {
				m.certLoadFailures = make(map[string]certLoadFailure)
			}
			m.certLoadFailures[key] = certLoadFailure{state: before, retryAt: time.Now().Add(certificateReloadInterval), err: resultErr}
		} else {
			delete(m.certLoadFailures, key)
		}
	}()
	cert, err := tls.LoadX509KeyPair(filepath.Join(m.config.SSL.CertDir, key+".crt"), filepath.Join(m.config.SSL.KeyDir, key+".key"))
	if err != nil {
		return fmt.Errorf("load certificate %s: %w", key, err)
	}
	leaf, err := certificateLeaf(&cert)
	if err != nil {
		return err
	}
	if !certificateValidAt(leaf, time.Now()) || (len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0) {
		return fmt.Errorf("certificate %s is outside its validity period or has no SAN", key)
	}
	for _, der := range cert.Certificate[1:] {
		if _, err := x509.ParseCertificate(der); err != nil {
			return fmt.Errorf("parse certificate %s chain: %w", key, err)
		}
	}
	after, err := m.diskState(key)
	if err != nil || !before.equal(after) {
		return fmt.Errorf("certificate %s changed while loading", key)
	}
	m.certMutex.Lock()
	previousTLS := m.certCache[key]
	previous, parseErr := certificateLeaf(previousTLS)
	if parseErr == nil && certificateValidAt(previous, time.Now()) {
		// A hostname storage key must remain usable for that hostname. For
		// opaque upload aliases, retain the previous certificate's identities.
		matchesKey := certificateMatchesDomain(key, previous)
		nextMatchesKey := certificateMatchesDomain(key, leaf)
		if (matchesKey && !nextMatchesKey) || (!matchesKey && !nextMatchesKey && !certificateCoversPrevious(leaf, previous)) {
			m.certMutex.Unlock()
			return fmt.Errorf("certificate %s replacement does not cover its existing identity", key)
		}
	}
	// Publish only after the entire pair has been validated. NotAfter is not a
	// generation counter: a newer certificate may intentionally expire sooner.
	m.certCache[key] = &cert
	m.certDiskModTime[key] = after.cert.ModTime()
	// GenerateMultiDomainCert also creates aliases that have no backing file.
	// Move these references together or a lexically earlier alias could keep
	// serving the old leaf after the primary file was successfully reloaded.
	if parseErr == nil {
		for alias, cached := range m.certCache {
			_, diskBacked := m.certDiskModTime[alias]
			if diskBacked || cached == nil || len(cached.Certificate) == 0 {
				continue
			}
			if bytes.Equal(cached.Certificate[0], previousTLS.Certificate[0]) && (certificateMatchesDomain(alias, leaf) || certificateCoversPrevious(leaf, previous)) {
				m.certCache[alias] = &cert
			}
		}
	}
	m.certIndex = nil
	m.certMutex.Unlock()
	if m.certDiskState == nil {
		m.certDiskState = make(map[string]certDiskState)
	}
	m.certDiskState[key] = after
	m.updateCertMetadata(key, &cert)
	m.failedCacheMutex.Lock()
	clear(m.failedDomainCache)
	m.failedCacheMutex.Unlock()
	return nil
}

func (m *Manager) LoadCertificateFromDisk(key string) error {
	m.certStoreMu.Lock()
	defer m.certStoreMu.Unlock()
	return m.loadCertificateLocked(key, true)
}

func (m *Manager) maybeReloadCertIfStale(key string) {
	m.certStoreMu.Lock()
	defer m.certStoreMu.Unlock()
	if err := m.loadCertificateLocked(key, false); err != nil {
		m.log.Debugf("Certificate hot reload skipped for %s: %v", key, err)
	}
}

func (m *Manager) refreshLocalCertificates() {
	m.certStoreMu.Lock()
	defer m.certStoreMu.Unlock()
	m.refreshLocalCertificatesLocked(false)
}

// Directory metadata exposes newly installed exact certificates on the next
// lookup, including opaque upload aliases. Full in-place scans are coalesced
// and bounded, while the selected pair is checked independently each lookup.
func (m *Manager) refreshLocalCertificatesLocked(force bool) {
	certDir, _ := os.Stat(m.config.SSL.CertDir)
	keyDir, _ := os.Stat(m.config.SSL.KeyDir)
	directories := certDiskState{cert: certDir, key: keyDir}
	sameDirectory := func(a, b os.FileInfo) bool {
		return (a == nil && b == nil) || sameCertFile(a, b)
	}
	unchanged := sameDirectory(certDir, m.certDirectoryState.cert) && sameDirectory(keyDir, m.certDirectoryState.key)
	if !force && unchanged && time.Since(m.certLastScan) < certificateReloadInterval {
		return
	}
	entries, err := os.ReadDir(m.config.SSL.CertDir)
	m.certDirectoryState = directories
	m.certLastScan = time.Now()
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
			key := strings.TrimSuffix(entry.Name(), ".crt")
			if err := m.loadCertificateLocked(key, false); err != nil {
				m.log.Debugf("Certificate hot reload skipped for %s: %v", key, err)
			}
		}
	}
}

func (m *Manager) periodicReloadCertsFromDiskIfChanged() {
	ticker := time.NewTicker(certificateReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.reloadAllCachedCertsIfCertFilesStale()
		case <-m.stopChan:
			return
		}
	}
}

func (m *Manager) reloadAllCachedCertsIfCertFilesStale() {
	m.certStoreMu.Lock()
	defer m.certStoreMu.Unlock()
	m.refreshLocalCertificatesLocked(true)
}
