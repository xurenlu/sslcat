package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigSaveRestrictsExistingBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslcat.conf")
	paths := []string{path, path + ".backup.v1", path + ".backup." + time.Now().Format("2006-01-02")}
	for _, file := range paths {
		if err := os.WriteFile(file, []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, 0644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := getDefaultConfig()
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	for _, file := range paths {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("existing config or backup remains accessible to other users: %s %o", file, info.Mode().Perm())
		}
	}
}
