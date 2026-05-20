package security

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTokenStoreDeleteDoesNotDeadlock(t *testing.T) {
	store := NewTokenStore(filepath.Join(t.TempDir(), "tokens.json"))
	token, err := store.Generate(TokenRoleWrite, "test")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan bool, 1)
	go func() {
		done <- store.Delete(token.Token)
	}()

	select {
	case deleted := <-done:
		if !deleted {
			t.Fatal("token should be deleted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Delete deadlocked while persisting token store")
	}
}
