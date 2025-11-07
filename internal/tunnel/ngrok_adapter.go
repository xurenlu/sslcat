package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
	"gopkg.in/yaml.v3"
)

type ngrokAdapter struct {
	log *logrus.Entry
}

func newNgrokAdapter(logger *logrus.Entry) ProviderAdapter {
	var log *logrus.Entry
	if logger != nil {
		log = logger.WithField("adapter", "ngrok")
	}
	return &ngrokAdapter{log: log}
}

func (a *ngrokAdapter) Prepare(provider config.TunnelProviderConfig, tunnel config.TunnelDefinition, runtimeDir string) (*CommandSpec, error) {
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("ngrok: 创建运行目录失败: %w", err)
	}

	binary := strings.TrimSpace(provider.Options["binary"])
	if binary == "" {
		binary = "ngrok"
	}

	authtoken := strings.TrimSpace(provider.Credentials["authtoken"])
	region := strings.TrimSpace(provider.Options["region"])
	configVersion := strings.TrimSpace(provider.Options["config_version"])
	if configVersion == "" {
		configVersion = "2"
	}

	ngrokConfig := map[string]interface{}{
		"version": configVersion,
		"tunnels": make(map[string]interface{}),
	}

	if authtoken != "" {
		ngrokConfig["authtoken"] = authtoken
	}
	if region != "" {
		ngrokConfig["region"] = region
	}

	tunnelConfig := make(map[string]interface{})
	tunnelConfig["proto"] = tunnel.Protocol
	addr := fmt.Sprintf("%s:%d", firstNonEmpty(tunnel.LocalAddress, "127.0.0.1"), tunnel.LocalPort)
	tunnelConfig["addr"] = addr

	if host := strings.TrimSpace(tunnel.PublicHostname); host != "" {
		if tunnel.Protocol == "http" || tunnel.Protocol == "https" {
			tunnelConfig["hostname"] = host
			tunnelConfig["domain"] = host
		} else {
			if tunnel.PublicPort > 0 {
				tunnelConfig["remote_addr"] = fmt.Sprintf("%s:%d", host, tunnel.PublicPort)
			} else {
				tunnelConfig["remote_addr"] = host
			}
		}
	} else if tunnel.PublicPort > 0 {
		tunnelConfig["remote_addr"] = fmt.Sprintf(":%d", tunnel.PublicPort)
	}

	if tunnel.EdgeRegion != "" {
		tunnelConfig["region"] = tunnel.EdgeRegion
	}

	if len(tunnel.Metadata) > 0 {
		tunnelConfig["metadata"] = tunnel.Metadata
	}

	for key, value := range tunnel.Parameters {
		key = sanitizeKey(key)
		if key == "" || strings.TrimSpace(value) == "" {
			continue
		}
		tunnelConfig[key] = strings.TrimSpace(value)
	}

	ngrokConfig["tunnels"].(map[string]interface{})[tunnel.ID] = tunnelConfig

	configPath := filepath.Join(runtimeDir, "ngrok.yml")
	data, err := yaml.Marshal(ngrokConfig)
	if err != nil {
		return nil, fmt.Errorf("ngrok: 生成配置失败: %w", err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return nil, fmt.Errorf("ngrok: 写入配置失败: %w", err)
	}

	env := make([]string, 0, len(provider.Credentials))
	for key, value := range provider.Credentials {
		if key == "authtoken" {
			continue
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		envKey := fmt.Sprintf("NGROK_%s", strings.ToUpper(sanitizeKey(key)))
		env = append(env, fmt.Sprintf("%s=%s", envKey, value))
	}

	return &CommandSpec{
		Executable: binary,
		Args:       []string{"start", "--config", configPath, tunnel.ID},
		Env:        env,
		WorkDir:    runtimeDir,
	}, nil
}

