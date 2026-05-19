package web

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

type adminRecoveryCodeRecord struct {
	ID        string     `json:"id"`
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

type recoverPageData struct {
	Title           string
	Intro           string
	Step1           string
	Step2           string
	Step3           string
	Step4           string
	Paths           string
	Commands        string
	CodeFile        string
	CodeLabel       string
	NewPassword     string
	ConfirmPassword string
	ResetSubmit     string
	BackToLogin     string
	AdminPrefix     string
}

const recoveryCodePrefix = "sslcat-"

var errInvalidRecoveryCode = errors.New("invalid recovery code")

var recoverPageTemplate = template.Must(template.New("recover").Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f6f7f9;color:#1f2937;margin:0}
    main{max-width:760px;margin:40px auto;padding:28px;background:#fff;border:1px solid #e5e7eb;border-radius:8px}
    h1{font-size:24px;margin:0 0 12px}
    p,li{line-height:1.65}
    label{display:block;font-weight:600;margin:14px 0 6px}
    input{width:100%;box-sizing:border-box;border:1px solid #cbd5e1;border-radius:6px;padding:10px;font-size:15px}
    button,a.button{display:inline-block;border:0;border-radius:6px;padding:10px 14px;font-size:15px;text-decoration:none;cursor:pointer}
    button{background:#2563eb;color:#fff}
    a.button{background:#e5e7eb;color:#111827;margin-left:8px}
    .note{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px;margin:16px 0}
    .actions{margin-top:18px}
  </style>
</head>
<body>
  <main>
    <h1>{{.Title}}</h1>
    <p>{{.Intro}}</p>
    <ol>
      <li>{{.Step1}}</li>
      <li>{{.Step2}}</li>
      <li>{{.Step3}}</li>
      <li>{{.Step4}}</li>
    </ol>
    <div class="note">{{.Paths}}<br>{{.Commands}}<br>{{.CodeFile}}</div>
    <form method="POST" action="{{.AdminPrefix}}/api/auth/recover-password">
      <label for="recovery_code">{{.CodeLabel}}</label>
      <input id="recovery_code" name="recovery_code" autocomplete="one-time-code" required>
      <label for="new_password">{{.NewPassword}}</label>
      <input id="new_password" name="new_password" type="password" autocomplete="new-password" required>
      <label for="confirm_password">{{.ConfirmPassword}}</label>
      <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
      <div class="actions">
        <button type="submit">{{.ResetSubmit}}</button>
        <a class="button" href="{{.AdminPrefix}}/login">{{.BackToLogin}}</a>
      </div>
    </form>
  </main>
</body>
</html>`))

func (s *Server) ensureAdminRecoveryCode() error {
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()

	records, err := s.loadAdminRecoveryCodes()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.UsedAt == nil && record.Hash != "" {
			return nil
		}
	}

	_, err = s.appendNewAdminRecoveryCode(records)
	return err
}

func (s *Server) handleAPIRecoverPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, wantsJSON, err := parseRecoveryPasswordRequest(r)
	if err != nil {
		s.writeRecoveryError(w, wantsJSON, http.StatusBadRequest, err.Error())
		return
	}

	if req.NewPassword != req.ConfirmPassword {
		s.writeRecoveryError(w, wantsJSON, http.StatusBadRequest, "passwords do not match")
		return
	}
	if err := validateAdminRecoveryPassword(req.NewPassword); err != nil {
		s.writeRecoveryError(w, wantsJSON, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.resetAdminPasswordWithRecoveryCode(req.RecoveryCode, req.NewPassword); err != nil {
		clientIP := s.getClientIP(r)
		if errors.Is(err, errInvalidRecoveryCode) {
			if s.securityManager != nil {
				s.securityManager.LogAccess(clientIP, r.Header.Get("User-Agent"), r.URL.Path, false)
			}
			s.audit("admin_recovery_failed", clientIP)
			s.writeRecoveryError(w, wantsJSON, http.StatusUnauthorized, "invalid recovery code")
			return
		}

		s.log.Errorf("Admin password recovery failed: %v", err)
		s.audit("admin_recovery_error", clientIP)
		s.writeRecoveryError(w, wantsJSON, http.StatusInternalServerError, "password recovery failed")
		return
	}

	if s.sessionManager != nil {
		s.sessionManager.DeleteUserSessions(s.config.Admin.Username)
	}
	s.audit("admin_password_recovered", s.getClientIP(r))

	if wantsJSON {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message":            "password reset successfully",
			"recovery_code_file": s.recoveryCodePlaintextFile(),
		})
		return
	}

	http.Redirect(w, r, s.config.AdminPrefix+"/login?recovered=1", http.StatusFound)
}

func (s *Server) resetAdminPasswordWithRecoveryCode(code, newPassword string) error {
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()

	normalizedCode := normalizeRecoveryCode(code)
	if normalizedCode == "" {
		return errInvalidRecoveryCode
	}

	records, err := s.loadAdminRecoveryCodes()
	if err != nil {
		return err
	}

	matchedIndex := -1
	for i, record := range records {
		if record.UsedAt != nil || record.Hash == "" {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(record.Hash), []byte(normalizedCode)) == nil {
			matchedIndex = i
			break
		}
	}
	if matchedIndex < 0 {
		return errInvalidRecoveryCode
	}

	now := time.Now().UTC()
	records[matchedIndex].UsedAt = &now
	if _, err := s.appendNewAdminRecoveryCode(records); err != nil {
		return err
	}
	if err := s.updateAdminPassword(newPassword); err != nil {
		return err
	}
	return nil
}

type recoveryPasswordRequest struct {
	RecoveryCode    string
	NewPassword     string
	ConfirmPassword string
}

func parseRecoveryPasswordRequest(r *http.Request) (recoveryPasswordRequest, bool, error) {
	contentType := r.Header.Get("Content-Type")
	wantsJSON := strings.Contains(contentType, "application/json")
	if wantsJSON {
		var payload struct {
			RecoveryCode    string `json:"recoveryCode"`
			NewPassword     string `json:"newPassword"`
			ConfirmPassword string `json:"confirmPassword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return recoveryPasswordRequest{}, true, fmt.Errorf("invalid JSON")
		}
		return recoveryPasswordRequest{
			RecoveryCode:    payload.RecoveryCode,
			NewPassword:     payload.NewPassword,
			ConfirmPassword: payload.ConfirmPassword,
		}, true, nil
	}

	if err := r.ParseForm(); err != nil {
		return recoveryPasswordRequest{}, false, fmt.Errorf("invalid form")
	}
	return recoveryPasswordRequest{
		RecoveryCode:    r.FormValue("recovery_code"),
		NewPassword:     r.FormValue("new_password"),
		ConfirmPassword: r.FormValue("confirm_password"),
	}, false, nil
}

func (s *Server) writeRecoveryError(w http.ResponseWriter, wantsJSON bool, status int, message string) {
	if wantsJSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
		return
	}
	http.Error(w, message, status)
}

func (s *Server) renderRecoverHelp(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := recoverPageData{
		Title:           s.translator.T("recover.title"),
		Intro:           s.translator.T("recover.intro"),
		Step1:           s.translator.T("recover.step1"),
		Step2:           s.translator.T("recover.step2"),
		Step3:           s.translator.T("recover.step3"),
		Step4:           s.translator.T("recover.step4"),
		Paths:           s.translator.T("recover.paths"),
		Commands:        s.translator.T("recover.commands"),
		CodeFile:        s.translator.T("recover.code_file", s.recoveryCodePlaintextFile()),
		CodeLabel:       s.translator.T("recover.code_label"),
		NewPassword:     s.translator.T("recover.new_password"),
		ConfirmPassword: s.translator.T("recover.confirm_password"),
		ResetSubmit:     s.translator.T("recover.reset_submit"),
		BackToLogin:     s.translator.T("recover.back_to_login"),
		AdminPrefix:     s.config.AdminPrefix,
	}
	if err := recoverPageTemplate.Execute(w, data); err != nil {
		s.log.Errorf("Failed to render recovery page: %v", err)
	}
}

func (s *Server) appendNewAdminRecoveryCode(records []adminRecoveryCodeRecord) (string, error) {
	code, err := generateAdminRecoveryCode()
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(normalizeRecoveryCode(code)), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash recovery code failed: %w", err)
	}

	records = append(records, adminRecoveryCodeRecord{
		ID:        newRecoveryRecordID(),
		Hash:      string(hash),
		CreatedAt: time.Now().UTC(),
	})
	if err := s.saveAdminRecoveryCodes(records); err != nil {
		return "", err
	}
	if err := s.writeRecoveryPlaintextFile(code); err != nil {
		return "", err
	}
	return code, nil
}

func generateAdminRecoveryCode() (string, error) {
	randomBytes := make([]byte, 24)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate recovery code failed: %w", err)
	}
	raw := strings.ToLower(hex.EncodeToString(randomBytes))
	return fmt.Sprintf("%s%s-%s-%s-%s-%s-%s",
		recoveryCodePrefix,
		raw[0:8],
		raw[8:16],
		raw[16:24],
		raw[24:32],
		raw[32:40],
		raw[40:48],
	), nil
}

func newRecoveryRecordID() string {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Sprintf("recovery-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(randomBytes)
}

func normalizeRecoveryCode(code string) string {
	code = strings.TrimSpace(strings.ToLower(code))
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "\t", "")
	return code
}

func validateAdminRecoveryPassword(password string) error {
	if len(password) < 10 {
		return fmt.Errorf("password must be at least 10 characters")
	}
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasUpper, hasLower, hasDigit, hasSpecial} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return fmt.Errorf("password must contain at least three character classes")
	}
	return nil
}

func (s *Server) loadAdminRecoveryCodes() ([]adminRecoveryCodeRecord, error) {
	path := s.recoveryCodeHashFile()
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open recovery code file failed: %w", err)
	}
	defer file.Close()

	var records []adminRecoveryCodeRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record adminRecoveryCodeRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, fmt.Errorf("parse recovery code file failed: %w", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read recovery code file failed: %w", err)
	}
	return records, nil
}

func (s *Server) saveAdminRecoveryCodes(records []adminRecoveryCodeRecord) error {
	lines := make([]byte, 0, len(records)*128)
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("serialize recovery code failed: %w", err)
		}
		lines = append(lines, data...)
		lines = append(lines, '\n')
	}
	return writeSensitiveFileAtomically(s.recoveryCodeHashFile(), lines, 0600)
}

func (s *Server) writeRecoveryPlaintextFile(code string) error {
	body := fmt.Sprintf(`SSLcat administrator recovery code
Generated at: %s
Code: %s

This file contains a one-time secret. Store it safely. After it is used, SSLcat will invalidate it and generate a new recovery code file.
Recovery URL: %s/help/recover
`, time.Now().UTC().Format(time.RFC3339), code, s.config.AdminPrefix)
	return writeSensitiveFileAtomically(s.recoveryCodePlaintextFile(), []byte(body), 0600)
}

func (s *Server) recoveryCodeHashFile() string {
	return filepath.Join(s.adminSecretDir(), "admin.recovery.codes")
}

func (s *Server) recoveryCodePlaintextFile() string {
	return filepath.Join(s.adminSecretDir(), "admin.recovery-code.txt")
}

func (s *Server) adminSecretDir() string {
	if s.config != nil && s.config.Admin.PasswordFile != "" {
		return filepath.Dir(s.config.Admin.PasswordFile)
	}
	if s.config != nil && s.config.Server.DataDir != "" {
		return s.config.Server.DataDir
	}
	return "./data"
}

func (s *Server) writeAdminPassword(newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码加密失败: %w", err)
	}

	if s.config.Admin.PasswordFile == "" {
		s.config.Admin.PasswordFile = filepath.Join(s.adminSecretDir(), "admin.pass")
	}
	if err := writeSensitiveFileAtomically(s.config.Admin.PasswordFile, append(hashedPassword, '\n'), 0600); err != nil {
		return fmt.Errorf("写入密码文件失败: %w", err)
	}
	s.config.Admin.Password = ""
	return nil
}

func writeSensitiveFileAtomically(targetPath string, data []byte, perm os.FileMode) error {
	if targetPath == "" {
		return fmt.Errorf("target path is empty")
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create directory failed: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".secret-*.tmp")
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
