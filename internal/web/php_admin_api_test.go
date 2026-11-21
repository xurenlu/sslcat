package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/security"
)

func TestPHPAdminIniAPI(t *testing.T) {
	logger := logrus.New()
	configPath := filepath.Join(t.TempDir(), "sslcat.conf")
	if err := os.WriteFile(configPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		config:         cfg,
		log:            logrus.NewEntry(logger),
		sessionManager: &SessionManager{log: logger},
		tokenStore:     security.NewTokenStore(filepath.Join(t.TempDir(), "tokens.json")),
	}
	token, err := s.tokenStore.Generate(security.TokenRoleWrite, "php ini test")
	if err != nil {
		t.Fatal(err)
	}
	request := func(method string, ini map[string]string) int {
		t.Helper()
		body, err := json.Marshal(map[string]interface{}{
			"domain": "example.test", "root": "/var/www/example", "enabled": true,
			"php_admin_ini": ini,
		})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "/sslcat-panel/api/php-sites", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token.Token)
		w := httptest.NewRecorder()
		s.handleAPIPHPSites(w, r)
		return w.Code
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		if got := request(method, map[string]string{" Memory_Limit ": " 128M "}); got != http.StatusOK {
			t.Fatalf("%s status=%d", method, got)
		}
		if len(cfg.PHPSites) != 1 || cfg.PHPSites[0].PHPAdminIni["memory_limit"] != "128M" {
			t.Fatalf("%s did not normalize site directives", method)
		}
		persisted, err := os.ReadFile(cfg.ConfigFile)
		if err != nil {
			t.Fatal(err)
		}
		var saved config.Config
		if err := json.Unmarshal(persisted, &saved); err != nil {
			t.Fatal(err)
		}
		if len(saved.PHPSites) != 1 || saved.PHPSites[0].PHPAdminIni["memory_limit"] != "128M" {
			t.Fatalf("%s did not persist site directives", method)
		}
		for _, invalid := range []map[string]string{
			{"auto_prepend_file": "/tmp/rejected.php"},
			{"memory_limit": "128M\nauto_prepend_file=/tmp/rejected.php"},
		} {
			if got := request(method, invalid); got != http.StatusBadRequest {
				t.Fatalf("%s accepted invalid directives: status=%d", method, got)
			}
			if cfg.PHPSites[0].PHPAdminIni["memory_limit"] != "128M" {
				t.Fatal("rejected request changed in-memory site")
			}
			after, err := os.ReadFile(cfg.ConfigFile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(persisted, after) {
				t.Fatal("rejected request changed persisted site")
			}
		}
	}
}
