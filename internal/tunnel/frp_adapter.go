package tunnel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

type frpAdapter struct {
	log *logrus.Entry
}

func newFRPAdapter(logger *logrus.Entry) ProviderAdapter {
	var log *logrus.Entry
	if logger != nil {
		log = logger.WithField("adapter", "frp")
	}
	return &frpAdapter{log: log}
}

func (a *frpAdapter) Prepare(provider config.TunnelProviderConfig, tunnel config.TunnelDefinition, runtimeDir string) (*CommandSpec, error) {
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return nil, fmt.Errorf("frp: 创建运行目录失败: %w", err)
	}

	// 默认可执行文件
	binary := strings.TrimSpace(provider.Options["binary"])
	if binary == "" {
		binary = "frpc"
	}

	common := mergeMaps(provider.Credentials, provider.Options)
	delete(common, "binary")

	if _, ok := common["server_addr"]; !ok {
		return nil, fmt.Errorf("frp: 缺少 server_addr 配置")
	}
	if _, ok := common["server_port"]; !ok {
		return nil, fmt.Errorf("frp: 缺少 server_port 配置")
	}

	buf := &bytes.Buffer{}
	buf.WriteString("[common]\n")

	commonKeys := sortedKeys(common)
	for _, key := range commonKeys {
		value := strings.TrimSpace(common[key])
		if value == "" {
			continue
		}
		fmt.Fprintf(buf, "%s = %s\n", key, value)
	}
	buf.WriteString("\n")

	sectionName := tunnel.ID
	if strings.TrimSpace(tunnel.Name) != "" {
		sectionName = tunnel.Name
	}
	sectionName = sanitizeSectionName(sectionName)

	buf.WriteString(fmt.Sprintf("[%s]\n", sectionName))
	buf.WriteString(fmt.Sprintf("type = %s\n", tunnel.Protocol))
	buf.WriteString(fmt.Sprintf("local_ip = %s\n", firstNonEmpty(tunnel.LocalAddress, "127.0.0.1")))
	buf.WriteString(fmt.Sprintf("local_port = %d\n", tunnel.LocalPort))

	if tunnel.PublicPort > 0 {
		fmt.Fprintf(buf, "remote_port = %d\n", tunnel.PublicPort)
	}

	if host := strings.TrimSpace(tunnel.PublicHostname); host != "" {
		if tunnel.Protocol == "http" || tunnel.Protocol == "https" {
			fmt.Fprintf(buf, "custom_domains = %s\n", host)
		} else {
			fmt.Fprintf(buf, "remote_addr = %s\n", host)
		}
	}

	parameterKeys := sortedKeys(tunnel.Parameters)
	for _, key := range parameterKeys {
		value := strings.TrimSpace(tunnel.Parameters[key])
		if value == "" {
			continue
		}
		fmt.Fprintf(buf, "%s = %s\n", sanitizeKey(key), value)
	}

	metadataKeys := sortedKeys(tunnel.Metadata)
	for _, key := range metadataKeys {
		value := strings.TrimSpace(tunnel.Metadata[key])
		if value == "" {
			continue
		}
		fmt.Fprintf(buf, "meta_%s = %s\n", sanitizeKey(key), value)
	}

	configPath := filepath.Join(runtimeDir, "frpc.ini")
	if err := os.WriteFile(configPath, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("frp: 写入配置文件失败: %w", err)
	}

	return &CommandSpec{
		Executable: binary,
		Args:       []string{"-c", configPath},
		WorkDir:    runtimeDir,
	}, nil
}

func mergeMaps(primary map[string]string, secondary map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range secondary {
		result[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	for k, v := range primary {
		result[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return result
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sanitizeKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.ReplaceAll(key, " ", "_")
	key = strings.ReplaceAll(key, "-", "_")
	return key
}

func sanitizeSectionName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "tunnel"
	}
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	return name
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
