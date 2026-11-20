package ssl

import (
	"fmt"
	"os"
	"path/filepath"
)

// prepareAtomicFile writes and syncs a sibling temporary file without publishing it.
// The caller owns removing the returned path, including after a failed rename.
func prepareAtomicFile(targetPath string, data []byte, perm os.FileMode) (string, error) {
	if targetPath == "" {
		return "", fmt.Errorf("target path is empty")
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create directory failed: %w", err)
	}
	tmpFile, err := os.CreateTemp(dir, ".sslcat-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp file failed: %w", err)
	}
	tmpPath := tmpFile.Name()
	success := false
	defer func() {
		if !success {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmpFile.Chmod(perm); err != nil {
		return "", fmt.Errorf("chmod temp file failed: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		return "", fmt.Errorf("write temp file failed: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return "", fmt.Errorf("sync temp file failed: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("close temp file failed: %w", err)
	}
	success = true
	return tmpPath, nil
}

func syncCertificateDirectory(path string) {
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
}

func writeFileAtomically(targetPath string, data []byte, perm os.FileMode) error {
	tmpPath, err := prepareAtomicFile(targetPath, data, perm)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("replace file failed: %w", err)
	}
	syncCertificateDirectory(targetPath)
	return nil
}
