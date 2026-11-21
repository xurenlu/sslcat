package ssl

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
	"golang.org/x/crypto/acme/autocert"
)

func TestACMEReloadPreservesStateOnCacheDirectoryFailure(t *testing.T) {
	oldCfg := &config.Config{SSL: config.SSLConfig{Email: "old@example.invalid"}}
	oldACME := &autocert.Manager{Email: oldCfg.SSL.Email}
	m := &Manager{config: oldCfg, acmeMgr: oldACME, log: logrus.NewEntry(logrus.New())}
	blocked := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	requested := &config.Config{SSL: config.SSLConfig{
		Email: "new@example.invalid", CertDir: filepath.Join(blocked, "certs"),
	}}
	if err := m.Reload(requested); err == nil {
		t.Fatal("cache directory failure was hidden")
	}
	if m.config != oldCfg || m.acmeMgr != oldACME {
		t.Fatal("failed ACME preparation replaced active configuration")
	}
}

func TestACMEReloadAppliesPreparedManagerAndDisablesWithoutEmail(t *testing.T) {
	m := &Manager{log: logrus.NewEntry(logrus.New())}
	requested := &config.Config{SSL: config.SSLConfig{
		Email: "new@example.invalid", CertDir: filepath.Join(t.TempDir(), "certs"), Staging: true,
	}}
	if err := m.Reload(requested); err != nil {
		t.Fatal(err)
	}
	if m.config != requested || m.acmeMgr == nil || m.acmeMgr.Email != requested.SSL.Email {
		t.Fatal("prepared ACME configuration was not applied")
	}
	if m.acmeMgr.Client.DirectoryURL != "https://acme-staging-v02.api.letsencrypt.org/directory" {
		t.Fatal("staging selection was lost")
	}
	disabled := &config.Config{}
	if err := m.Reload(disabled); err != nil {
		t.Fatal(err)
	}
	if m.config != disabled || m.acmeMgr != nil {
		t.Fatal("empty email left old ACME manager active")
	}
}
