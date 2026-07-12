package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const minimumAdminPasswordLength = 10

// RegisterPasswordCommands registers local administrator credential recovery commands.
func (m *Manager) RegisterPasswordCommands() {
	m.RegisterCommand(&Command{
		Name:        "reset-password",
		Description: "Reset the administrator password (root only)",
		Handler: func(args []string) error {
			return m.resetAdminPassword(args)
		},
	})
}

func (m *Manager) resetAdminPassword(args []string) error {
	return m.resetAdminPasswordWith(args, os.Geteuid(), readPasswordFromTerminal)
}

func (m *Manager) resetAdminPasswordWith(args []string, effectiveUserID int, readPassword func(string) (string, error)) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Println("Usage: sudo sslcat reset-password")
		fmt.Println("Resets the administrator password through two hidden terminal prompts. Root privileges are required.")
		return nil
	}
	if len(args) > 0 {
		return fmt.Errorf("usage: sslcat reset-password")
	}
	if effectiveUserID != 0 {
		return fmt.Errorf("reset-password must be run as root (use sudo sslcat reset-password)")
	}
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	password, err := readPassword("New administrator password: ")
	if err != nil {
		return fmt.Errorf("read new password: %w", err)
	}
	confirmation, err := readPassword("Confirm new administrator password: ")
	if err != nil {
		return fmt.Errorf("read password confirmation: %w", err)
	}
	if password != confirmation {
		return fmt.Errorf("passwords do not match")
	}
	if err := validateAdministratorPassword(password); err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash administrator password: %w", err)
	}
	if err := writePasswordFile(m.administratorPasswordFile(), hash); err != nil {
		return fmt.Errorf("write administrator password file: %w", err)
	}

	fmt.Println("Administrator password reset successfully. No service restart is required.")
	return nil
}

func readPasswordFromTerminal(prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stdout)
	if err != nil {
		return "", err
	}
	return string(password), nil
}

func (m *Manager) administratorPasswordFile() string {
	if configuredPath := strings.TrimSpace(m.config.Admin.PasswordFile); configuredPath != "" {
		return configuredPath
	}
	dataDirectory := strings.TrimSpace(m.config.Server.DataDir)
	if dataDirectory == "" {
		dataDirectory = "./data"
	}
	return filepath.Join(dataDirectory, "admin.pass")
}

func validateAdministratorPassword(password string) error {
	if len(password) < minimumAdminPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minimumAdminPasswordLength)
	}

	classes := 0
	for _, matched := range []bool{
		containsCharacterClass(password, unicode.IsUpper),
		containsCharacterClass(password, unicode.IsLower),
		containsCharacterClass(password, unicode.IsDigit),
		containsCharacterClass(password, func(value rune) bool { return unicode.IsPunct(value) || unicode.IsSymbol(value) }),
	} {
		if matched {
			classes++
		}
	}
	if classes < 3 {
		return fmt.Errorf("password must contain at least three character classes")
	}
	return nil
}

func containsCharacterClass(value string, matcher func(rune) bool) bool {
	for _, character := range value {
		if matcher(character) {
			return true
		}
	}
	return false
}

func writePasswordFile(path string, hash []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0750); err != nil {
		return err
	}

	temporaryFile, err := os.CreateTemp(directory, ".admin.pass-")
	if err != nil {
		return err
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	if err := temporaryFile.Chmod(0600); err != nil {
		temporaryFile.Close()
		return err
	}
	if _, err := temporaryFile.Write(append(hash, '\n')); err != nil {
		temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
