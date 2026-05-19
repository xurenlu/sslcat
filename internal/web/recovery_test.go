package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

func newRecoveryTestServer(t *testing.T) *Server {
	t.Helper()
	tmpDir := t.TempDir()
	log := logrus.New()
	log.SetOutput(os.Stderr)
	cfg := &config.Config{
		ConfigFile: filepath.Join(tmpDir, "sslcat.conf"),
		Admin: config.AdminConfig{
			Username:     "admin",
			PasswordFile: filepath.Join(tmpDir, "admin.pass"),
		},
		Server: config.ServerConfig{
			Host:    "127.0.0.1",
			Port:    18080,
			DataDir: tmpDir,
		},
		SSL: config.SSLConfig{
			DisableSelfSigned: true,
			CertDir:           filepath.Join(tmpDir, "certs"),
			KeyDir:            filepath.Join(tmpDir, "keys"),
		},
	}
	return &Server{
		config: cfg,
		log:    logrus.NewEntry(log),
	}
}

func TestAdminRecoveryCodeResetRotatesCodeAndPassword(t *testing.T) {
	s := newRecoveryTestServer(t)
	if err := s.ensureAdminRecoveryCode(); err != nil {
		t.Fatalf("ensure recovery code failed: %v", err)
	}

	firstCode := readRecoveryCodeFromPlaintext(t, s.recoveryCodePlaintextFile())
	if firstCode == "" {
		t.Fatal("expected bootstrap recovery code")
	}

	if err := s.resetAdminPasswordWithRecoveryCode(firstCode, "NewStrong123!"); err != nil {
		t.Fatalf("reset password with recovery code failed: %v", err)
	}
	if !s.verifyAdminPassword("NewStrong123!") {
		t.Fatal("expected new admin password to verify")
	}

	if err := s.resetAdminPasswordWithRecoveryCode(firstCode, "AnotherStrong123!"); err == nil {
		t.Fatal("expected used recovery code to be rejected")
	}

	secondCode := readRecoveryCodeFromPlaintext(t, s.recoveryCodePlaintextFile())
	if secondCode == "" {
		t.Fatal("expected rotated recovery code")
	}
	if secondCode == firstCode {
		t.Fatal("expected recovery code to rotate after successful reset")
	}
}

func readRecoveryCodeFromPlaintext(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read recovery code file failed: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Code:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Code:"))
		}
	}
	return ""
}
