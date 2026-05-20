package web

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileSessionStorageCloseIsIdempotent(t *testing.T) {
	storage, err := NewFileSessionStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileSessionStorageRejectsInvalidKey(t *testing.T) {
	storage, err := NewFileSessionStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	err = storage.Set("../escape", &Session{
		SessionID: "escape",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("expected invalid session key to be rejected")
	}
}

func TestFileSessionStorageWritesPrivateSessionFile(t *testing.T) {
	dir := t.TempDir()
	storage, err := NewFileSessionStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	if err := storage.Set("session-id", &Session{
		SessionID: "session-id",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, "session-id.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("session file mode = %v, want 0600", got)
	}
}
