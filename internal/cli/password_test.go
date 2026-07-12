package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xurenlu/sslcat/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestResetAdminPasswordRequiresRoot(t *testing.T) {
	passwordPath := filepath.Join(t.TempDir(), "admin.pass")
	manager := &Manager{config: &config.Config{Admin: config.AdminConfig{PasswordFile: passwordPath}}}

	err := manager.resetAdminPasswordWith(nil, 1000, func(string) (string, error) {
		return "UnusedPassword1!", nil
	})
	if err == nil || err.Error() != "reset-password must be run as root (use sudo sslcat reset-password)" {
		t.Fatalf("expected root requirement error, got %v", err)
	}
	if _, statErr := os.Stat(passwordPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("password file should not be written, got %v", statErr)
	}
}

func TestResetAdminPasswordWritesVerifiedBcryptHash(t *testing.T) {
	passwordPath := filepath.Join(t.TempDir(), "admin.pass")
	manager := &Manager{config: &config.Config{Admin: config.AdminConfig{PasswordFile: passwordPath}}}
	passwords := []string{"StrongPassword1!", "StrongPassword1!"}

	err := manager.resetAdminPasswordWith(nil, 0, func(string) (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	})
	if err != nil {
		t.Fatalf("reset password: %v", err)
	}

	hash, err := os.ReadFile(passwordPath)
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("StrongPassword1!")); err != nil {
		t.Fatalf("stored hash did not verify: %v", err)
	}
	info, err := os.Stat(passwordPath)
	if err != nil {
		t.Fatalf("stat password file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("password file permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestResetAdminPasswordRejectsMismatchedConfirmation(t *testing.T) {
	manager := &Manager{config: &config.Config{}}
	passwords := []string{"StrongPassword1!", "DifferentPassword1!"}

	err := manager.resetAdminPasswordWith(nil, 0, func(string) (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	})
	if err == nil || err.Error() != "passwords do not match" {
		t.Fatalf("expected mismatched password error, got %v", err)
	}
}

func TestResetAdminPasswordHelpDoesNotRequireRoot(t *testing.T) {
	manager := &Manager{}

	err := manager.resetAdminPasswordWith([]string{"--help"}, 1000, func(string) (string, error) {
		t.Fatal("password reader should not be called for help")
		return "", nil
	})
	if err != nil {
		t.Fatalf("show help: %v", err)
	}
}
