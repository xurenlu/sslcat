package ssl

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Encode and check the entire key pair before touching either disk file.
func encodeCertificatePair(cert *tls.Certificate) ([]byte, []byte, error) {
	if _, err := certificateLeaf(cert); err != nil {
		return nil, nil, err
	}
	var certPEM []byte
	for _, der := range cert.Certificate {
		if _, err := x509.ParseCertificate(der); err != nil {
			return nil, nil, fmt.Errorf("parse certificate chain: %w", err)
		}
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal certificate private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, nil, fmt.Errorf("validate certificate key pair: %w", err)
	}
	return certPEM, keyPEM, nil
}

func (m *Manager) writeCertificateLocked(key string, cert *tls.Certificate) error {
	if !validCertKey(key) {
		return fmt.Errorf("invalid certificate storage key %q", key)
	}
	certPEM, keyPEM, err := encodeCertificatePair(cert)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.config.SSL.CertDir, 0755); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	if err := os.MkdirAll(m.config.SSL.KeyDir, 0755); err != nil {
		return fmt.Errorf("create private key directory: %w", err)
	}
	return writeCertificatePair(filepath.Join(m.config.SSL.CertDir, key+".crt"), filepath.Join(m.config.SSL.KeyDir, key+".key"), certPEM, keyPEM, os.Rename)
}

// Prepare both files and a rollback copy before publishing either half. The
// store lock excludes local readers during the two renames. Filesystem crashes
// across separate directories still require external recovery; a failed key
// rename in this process restores the original certificate and leaves its key.
func writeCertificatePair(certPath, keyPath string, certPEM, keyPEM []byte, rename func(string, string) error) error {
	certTemp, err := prepareAtomicFile(certPath, certPEM, 0644)
	if err != nil {
		return fmt.Errorf("prepare certificate: %w", err)
	}
	defer os.Remove(certTemp)
	keyTemp, err := prepareAtomicFile(keyPath, keyPEM, 0600)
	if err != nil {
		return fmt.Errorf("prepare private key: %w", err)
	}
	defer os.Remove(keyTemp)
	var backup string
	previous, err := os.ReadFile(certPath)
	if err == nil {
		backup, err = prepareAtomicFile(certPath, previous, 0644)
		if err != nil {
			return fmt.Errorf("prepare certificate rollback: %w", err)
		}
		defer func() {
			if backup != "" {
				_ = os.Remove(backup)
			}
		}()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read previous certificate: %w", err)
	}
	if err := rename(certTemp, certPath); err != nil {
		return fmt.Errorf("replace certificate: %w", err)
	}
	if err := rename(keyTemp, keyPath); err != nil {
		var rollbackErr error
		if backup != "" {
			rollbackErr = rename(backup, certPath)
		} else {
			rollbackErr = os.Remove(certPath)
		}
		if rollbackErr != nil {
			// Preserve the rollback file for recovery if restoration itself fails.
			recoveryPath := backup
			backup = ""
			return errors.Join(fmt.Errorf("replace private key: %w", err), fmt.Errorf("restore certificate (backup %s): %w", recoveryPath, rollbackErr))
		}
		syncCertificateDirectory(certPath)
		return fmt.Errorf("replace private key; original certificate restored: %w", err)
	}
	syncCertificateDirectory(certPath)
	syncCertificateDirectory(keyPath)
	return nil
}

func (m *Manager) saveCertificateToDisk(key string, cert *tls.Certificate) error {
	m.certStoreMu.Lock()
	defer m.certStoreMu.Unlock()
	return m.writeCertificateLocked(key, cert)
}

func validateIssuedCertificate(domain string, cert *tls.Certificate) error {
	leaf, err := certificateLeaf(cert)
	if err != nil {
		return err
	}
	if !certificateValidAt(leaf, time.Now()) || !certificateMatchesDomain(domain, leaf) {
		return fmt.Errorf("issued certificate is not valid for %s", domain)
	}
	return nil
}

func (m *Manager) persistIssuedCertificate(domain string, cert *tls.Certificate) error {
	if err := validateIssuedCertificate(domain, cert); err != nil {
		return err
	}
	m.certStoreMu.Lock()
	defer m.certStoreMu.Unlock()
	// Reject SAN shrinkage before overwriting any part of the previous pair.
	m.certMutex.RLock()
	previous, err := certificateLeaf(m.certCache[domain])
	m.certMutex.RUnlock()
	leaf, _ := certificateLeaf(cert)
	if err == nil && !certificateCoversPrevious(leaf, previous) {
		return fmt.Errorf("issued certificate for %s removes previous SAN coverage", domain)
	}
	// Direct DNS/MCP callers need the same protection on a cold cache. An
	// expired or unpaired old leaf still defines the coverage to preserve.
	if diskLeaf, diskErr := readDiskCertificate(filepath.Join(m.config.SSL.CertDir, domain+".crt")); diskErr == nil {
		if !certificateCoversPrevious(leaf, diskLeaf) {
			return fmt.Errorf("issued certificate for %s removes previous disk SAN coverage", domain)
		}
	} else if os.IsPermission(diskErr) {
		return fmt.Errorf("check previous certificate coverage for %s: %w", domain, diskErr)
	}
	if err := m.writeCertificateLocked(domain, cert); err != nil {
		return err
	}
	return m.loadCertificateLocked(domain, true)
}

func (m *Manager) saveCertificate(domain string, certDER [][]byte, privateKey *rsa.PrivateKey) error {
	return m.persistIssuedCertificate(domain, &tls.Certificate{Certificate: certDER, PrivateKey: privateKey})
}
