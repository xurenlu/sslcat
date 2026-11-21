package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// captureLogrus 将标准 logrus 输出的消息重定向到缓冲区并返回恢复函数。
// 注意：本包测试均未使用 t.Parallel，顺序执行期间安全。
func captureLogrus(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	std := logrus.StandardLogger()
	prevOut := std.Out

	var buf bytes.Buffer
	std.SetOutput(&buf)

	restore := func() {
		std.SetOutput(prevOut)
	}
	return &buf, restore
}

// TestConfigSecurityReloadLogDoesNotLeakSecrets 验证配置热重载日志
// 不会输出配置值或凭据（管理员密码、TOTP、集群密钥、API Key 等）。
func TestConfigSecurityReloadLogDoesNotLeakSecrets(t *testing.T) {
	buf, restore := captureLogrus(t)
	defer restore()

	secretPassword := "super-secret-admin-password-9f4a"
	secretTOTP := "super-secret-totp-secret-7c21"
	secretClusterKey := "super-secret-cluster-key-3b8d"
	secretAPIKey := "super-secret-dns-api-key-5e12"

	oldCfg := getDefaultConfig()
	oldCfg.Admin.Password = "old-hash"
	oldCfg.Admin.TOTPSecret = "old-totp"
	oldCfg.Cluster.AuthKey = "old-cluster-key"
	oldCfg.SSL.DNSProviders = []DNSProvider{{Name: "cf", APIKey: "old-api-key"}}

	newCfg := getDefaultConfig()
	newCfg.Admin.Password = secretPassword
	newCfg.Admin.TOTPSecret = secretTOTP
	newCfg.Cluster.AuthKey = secretClusterKey
	newCfg.SSL.DNSProviders = []DNSProvider{
		{Name: "cf", Type: "cloudflare", APIKey: secretAPIKey},
	}

	rm := NewReloadManager()
	rm.RegisterComponent(&testReloadableComponent{name: "noop"})

	_ = rm.ReloadAll(oldCfg, newCfg)

	logOutput := buf.String()

	for _, secret := range []string{
		secretPassword,
		secretTOTP,
		secretClusterKey,
		secretAPIKey,
	} {
		if strings.Contains(logOutput, secret) {
			t.Fatalf("reload log leaked secret value %q:\n%s", secret, logOutput)
		}
	}

	// 同时确保旧的敏感哈希也未被输出。
	for _, secret := range []string{"old-hash", "old-totp", "old-cluster-key", "old-api-key"} {
		if strings.Contains(logOutput, secret) {
			t.Fatalf("reload log leaked old config value %q:\n%s", secret, logOutput)
		}
	}
}

// TestConfigSavePermissionsOwnerOnly 验证配置文件及备份文件均以 0600 权限落盘。
func TestConfigSavePermissionsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sslcat.conf")

	cfg := getDefaultConfig()
	cfg.Server.Port = 18080
	cfg.Server.PortMode = "custom"

	// 第一次保存：创建主配置（无备份）
	if err := cfg.Save(path); err != nil {
		t.Fatalf("first Save failed: %v", err)
	}
	assertPerm(t, path)

	// 第二次保存：此时已存在配置文件，会触发版本备份与按天备份
	if err := cfg.Save(path); err != nil {
		t.Fatalf("second Save failed: %v", err)
	}
	assertPerm(t, path)

	// 版本备份
	versionBackups, err := filepath.Glob(filepath.Join(dir, "*.backup.v*"))
	if err != nil {
		t.Fatalf("glob version backups failed: %v", err)
	}
	for _, b := range versionBackups {
		assertPerm(t, b)
	}

	// 按天备份
	dailyBackups, err := filepath.Glob(filepath.Join(dir, "*.backup.????-??-??"))
	if err != nil {
		t.Fatalf("glob daily backups failed: %v", err)
	}
	for _, b := range dailyBackups {
		assertPerm(t, b)
	}
}

// assertPerm 断言文件权限为 0600（仅所有者可读写）。
func assertPerm(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s failed: %v", path, err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected %s mode 0600, got %04o", path, got)
	}
}
