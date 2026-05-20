package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigSaveUsesTemporaryFileCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sslcat.conf")
	cfg := getDefaultConfig()
	cfg.Server.Port = 18080

	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	tmpFiles, err := filepath.Glob(filepath.Join(dir, ".config-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpFiles) != 0 {
		t.Fatalf("temporary config files should be cleaned up, got %v", tmpFiles)
	}
}
