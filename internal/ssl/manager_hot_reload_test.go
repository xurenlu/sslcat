package ssl

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func TestHotReloadModTimeTracking(t *testing.T) {
	tmp := t.TempDir()
	certDir := filepath.Join(tmp, "certs")
	keyDir := filepath.Join(tmp, "keys")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.SSL.CertDir = certDir
	cfg.SSL.KeyDir = keyDir
	cfg.SSL.DisableSelfSigned = true

	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tlsCert, err := m.generateSelfSignedCert("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.saveCertificateToDisk("example.com", tlsCert); err != nil {
		t.Fatal(err)
	}

	if err := m.LoadCertificateFromDisk("example.com"); err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(certDir, "example.com.crt")
	st1, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}

	m.certMutex.RLock()
	got := m.certDiskModTime["example.com"]
	m.certMutex.RUnlock()
	if got.Unix() != st1.ModTime().Unix() {
		t.Fatalf("certDiskModTime %v want same second as file %v", got, st1.ModTime())
	}

	m.maybeReloadCertIfStale("example.com")
	m.certMutex.RLock()
	got2 := m.certDiskModTime["example.com"]
	m.certMutex.RUnlock()
	if got2.Unix() != got.Unix() {
		t.Fatalf("mtime should not change when file unchanged, got %v was %v", got2, got)
	}

	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.com.key")
	if err := os.Chtimes(keyPath, future, future); err != nil {
		t.Fatal(err)
	}

	m.maybeReloadCertIfStale("example.com")
	st3, err := os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	m.certMutex.RLock()
	got3 := m.certDiskModTime["example.com"]
	m.certMutex.RUnlock()
	if got3.Unix() != st3.ModTime().Unix() {
		t.Fatalf("certDiskModTime %v want %v after touch", got3, st3.ModTime())
	}
}

func TestGetCertificateColdStartScansDiskSAN(t *testing.T) {
	tmp := t.TempDir()
	certDir := filepath.Join(tmp, "certs")
	keyDir := filepath.Join(tmp, "keys")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.SSL.CertDir = certDir
	cfg.SSL.KeyDir = keyDir
	cfg.SSL.DisableSelfSigned = true

	writer, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert, err := writer.generateSelfSignedCert("*.niuwoai.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.saveCertificateToDisk("api.niuwoai.com", tlsCert); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(certDir, "*.niuwoai.com.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(keyDir, "*.niuwoai.com.key")); err != nil {
		t.Fatal(err)
	}

	cold, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := cold.GetCertificate("pub.niuwoai.com")
	if err != nil {
		t.Fatalf("GetCertificate should find matching SAN from api.niuwoai.com.crt: %v", err)
	}
	if cert == nil || !cold.domainMatchesCert("pub.niuwoai.com", cert) {
		t.Fatal("loaded certificate should match pub.niuwoai.com")
	}

	cold.certMutex.RLock()
	_, cached := cold.certCache["api.niuwoai.com"]
	cold.certMutex.RUnlock()
	if !cached {
		t.Fatal("matching disk certificate should be cached under its file key")
	}
}
