package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func secureConfigBackups(configFile string) error {
	backups, err := filepath.Glob(configFile + ".backup.*")
	if err != nil {
		return err
	}
	for _, path := range backups {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("backup is not a regular file: %s", path)
		}
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("restrict backup permissions: %w", err)
		}
	}
	return nil
}
