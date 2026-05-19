package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type cacheKeyLock struct {
	mu   sync.Mutex
	refs int
}

func (uc *UpstreamCache) lockCacheKey(key string) func() {
	uc.keyLocksMu.Lock()
	lock, ok := uc.keyLocks[key]
	if !ok {
		lock = &cacheKeyLock{}
		uc.keyLocks[key] = lock
	}
	lock.refs++
	uc.keyLocksMu.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()

		uc.keyLocksMu.Lock()
		defer uc.keyLocksMu.Unlock()
		lock.refs--
		if lock.refs == 0 && uc.keyLocks[key] == lock {
			delete(uc.keyLocks, key)
		}
	}
}

func writeCacheFileAtomically(targetPath string, data []byte, perm os.FileMode) error {
	if targetPath == "" {
		return fmt.Errorf("target path is empty")
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory failed: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".sslcat-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file failed: %w", err)
	}
	tmpPath := tmpFile.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp file failed: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp file failed: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp file failed: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file failed: %w", err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("replace file failed: %w", err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	success = true
	return nil
}
