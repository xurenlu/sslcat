package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDiffConfig(t *testing.T) {
	// 创建默认配置
	defaultConfig := getDefaultConfig()

	// 创建测试配置，只修改少量字段
	testConfig := getDefaultConfig()
	testConfig.Server.Port = 8080
	testConfig.Server.Host = "127.0.0.1"
	testConfig.SSL.Email = "test@example.com"
	testConfig.Proxy.Rules = []ProxyRule{
		{
			Domain:  "example.com",
			Target:  "localhost",
			Port:    3000,
			Enabled: true,
		},
	}

	// 比较配置
	diffMap, err := diffConfig(testConfig, defaultConfig)
	if err != nil {
		t.Fatalf("diffConfig 失败: %v", err)
	}

	// 验证结果
	if len(diffMap) == 0 {
		t.Fatal("差异配置不应该为空")
	}

	// 验证 server.port
	if serverMap, ok := diffMap["server"].(map[string]interface{}); ok {
		if port, ok := serverMap["port"].(float64); !ok || port != 8080 {
			t.Errorf("期望 server.port = 8080，实际 = %v", serverMap["port"])
		}
		if host, ok := serverMap["host"].(string); !ok || host != "127.0.0.1" {
			t.Errorf("期望 server.host = 127.0.0.1，实际 = %v", serverMap["host"])
		}
		// 验证默认值没有被包含
		if _, ok := serverMap["debug"]; ok {
			t.Error("server.debug 应该被排除（与默认值相同）")
		}
	} else {
		t.Error("差异配置中应该包含 server 字段")
	}

	// 验证 ssl.email
	if sslMap, ok := diffMap["ssl"].(map[string]interface{}); ok {
		if email, ok := sslMap["email"].(string); !ok || email != "test@example.com" {
			t.Errorf("期望 ssl.email = test@example.com，实际 = %v", sslMap["email"])
		}
	} else {
		t.Error("差异配置中应该包含 ssl 字段")
	}

	// 验证 proxy.rules
	if proxyMap, ok := diffMap["proxy"].(map[string]interface{}); ok {
		if rules, ok := proxyMap["rules"].([]interface{}); ok {
			if len(rules) != 1 {
				t.Errorf("期望 proxy.rules 长度为 1，实际 = %d", len(rules))
			}
		} else {
			t.Error("差异配置中应该包含 proxy.rules")
		}
	} else {
		t.Error("差异配置中应该包含 proxy 字段")
	}
}

func TestSaveConfigOnlyDiff(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "sslcat.conf")

	// 创建测试配置，只修改少量字段
	testConfig := getDefaultConfig()
	testConfig.Server.Port = 8080
	testConfig.SSL.Email = "test@example.com"
	testConfig.Proxy.Rules = []ProxyRule{
		{
			Domain:  "example.com",
			Target:  "localhost",
			Port:    3000,
			Enabled: true,
		},
	}

	// 保存配置
	if err := testConfig.Save(configFile); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}

	// 读取保存的配置
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("读取配置文件失败: %v", err)
	}

	var savedConfig map[string]interface{}
	if err := json.Unmarshal(data, &savedConfig); err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	// 验证只保存了不同的字段
	if serverMap, ok := savedConfig["server"].(map[string]interface{}); ok {
		if port, ok := serverMap["port"].(float64); !ok || port != 8080 {
			t.Errorf("期望 server.port = 8080，实际 = %v", serverMap["port"])
		}
		// 验证默认值没有被包含
		if _, ok := serverMap["debug"]; ok {
			t.Error("server.debug 应该被排除（与默认值相同）")
		}
		if _, ok := serverMap["log_level"]; ok {
			t.Error("server.log_level 应该被排除（与默认值相同）")
		}
	} else {
		t.Error("保存的配置中应该包含 server 字段")
	}

	// 验证 ssl.email
	if sslMap, ok := savedConfig["ssl"].(map[string]interface{}); ok {
		if email, ok := sslMap["email"].(string); !ok || email != "test@example.com" {
			t.Errorf("期望 ssl.email = test@example.com，实际 = %v", sslMap["email"])
		}
		// 验证默认值没有被包含
		if _, ok := sslMap["staging"]; ok {
			t.Error("ssl.staging 应该被排除（与默认值相同）")
		}
	} else {
		t.Error("保存的配置中应该包含 ssl 字段")
	}

	// 验证 proxy.rules
	if proxyMap, ok := savedConfig["proxy"].(map[string]interface{}); ok {
		if rules, ok := proxyMap["rules"].([]interface{}); ok {
			if len(rules) != 1 {
				t.Errorf("期望 proxy.rules 长度为 1，实际 = %d", len(rules))
			}
		} else {
			t.Error("保存的配置中应该包含 proxy.rules")
		}
	} else {
		t.Error("保存的配置中应该包含 proxy 字段")
	}

	// 验证空数组不会被保存（如果默认也是空数组）
	defaultConfig := getDefaultConfig()
	if len(defaultConfig.StaticSites) == 0 {
		if _, ok := savedConfig["static_sites"]; ok {
			t.Error("static_sites 应该被排除（与默认值相同，都是空数组）")
		}
	}

	t.Logf("保存的配置文件内容:\n%s", string(data))
}

func TestSaveConfigEmpty(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "sslcat.conf")

	// 创建完全使用默认值的配置
	defaultConfig := getDefaultConfig()

	// 保存配置
	if err := defaultConfig.Save(configFile); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}

	// 读取保存的配置
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("读取配置文件失败: %v", err)
	}

	var savedConfig map[string]interface{}
	if err := json.Unmarshal(data, &savedConfig); err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	// 验证保存的是空对象或只有必要的字段
	if len(savedConfig) > 0 {
		t.Logf("保存的配置不为空，但应该只包含与默认值不同的字段: %v", savedConfig)
	}
}

func TestLoadAndSaveRoundTrip(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "sslcat.conf")

	// 创建测试配置
	testConfig := getDefaultConfig()
	testConfig.Server.Port = 8080
	testConfig.SSL.Email = "test@example.com"
	testConfig.Proxy.Rules = []ProxyRule{
		{
			Domain:  "example.com",
			Target:  "localhost",
			Port:    3000,
			Enabled: true,
		},
	}

	// 保存配置
	if err := testConfig.Save(configFile); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}

	// 重新加载配置
	loadedConfig, err := Load(configFile)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}

	// 验证加载的配置与原始配置一致
	if loadedConfig.Server.Port != testConfig.Server.Port {
		t.Errorf("期望 Port = %d，实际 = %d", testConfig.Server.Port, loadedConfig.Server.Port)
	}

	if loadedConfig.SSL.Email != testConfig.SSL.Email {
		t.Errorf("期望 Email = %s，实际 = %s", testConfig.SSL.Email, loadedConfig.SSL.Email)
	}

	if len(loadedConfig.Proxy.Rules) != len(testConfig.Proxy.Rules) {
		t.Errorf("期望 Proxy.Rules 长度为 %d，实际 = %d", len(testConfig.Proxy.Rules), len(loadedConfig.Proxy.Rules))
	}

	// 验证默认值被正确应用
	if loadedConfig.Server.Debug != false {
		t.Errorf("期望 Server.Debug = false（默认值），实际 = %v", loadedConfig.Server.Debug)
	}

	if loadedConfig.SSL.Staging != false {
		t.Errorf("期望 SSL.Staging = false（默认值），实际 = %v", loadedConfig.SSL.Staging)
	}
}

func TestDeepEqual(t *testing.T) {
	tests := []struct {
		name string
		a    interface{}
		b    interface{}
		want bool
	}{
		{"nil == nil", nil, nil, true},
		{"nil != value", nil, "test", false},
		{"value != nil", "test", nil, false},
		{"equal strings", "test", "test", true},
		{"different strings", "test", "test2", false},
		{"equal numbers", 42, 42, true},
		{"different numbers", 42, 43, false},
		{"equal bools", true, true, true},
		{"different bools", true, false, false},
		{"empty maps", map[string]interface{}{}, map[string]interface{}{}, true},
		{"equal maps", map[string]interface{}{"a": 1}, map[string]interface{}{"a": 1}, true},
		{"different maps", map[string]interface{}{"a": 1}, map[string]interface{}{"a": 2}, false},
		{"equal slices", []interface{}{1, 2}, []interface{}{1, 2}, true},
		{"different slices", []interface{}{1, 2}, []interface{}{1, 3}, false},
		{"nested maps equal", map[string]interface{}{"a": map[string]interface{}{"b": 1}}, map[string]interface{}{"a": map[string]interface{}{"b": 1}}, true},
		{"nested maps different", map[string]interface{}{"a": map[string]interface{}{"b": 1}}, map[string]interface{}{"a": map[string]interface{}{"b": 2}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deepEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("deepEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSaveConfigWithZeroValues(t *testing.T) {
	// 创建临时目录
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "sslcat.conf")

	// 创建测试配置，包含一个 ProxyRule，其中有很多零值字段
	testConfig := getDefaultConfig()
	testConfig.Proxy.Rules = []ProxyRule{
		{
			Domain:  "example.com",
			Target:  "localhost",
			Port:    3000,
			Enabled: true,
			SSLOnly: true,
			// 以下字段都是零值（默认值），不应该被保存
			// auth_enabled: false (零值)
			// cdn_enabled: false (零值)
			// health_check_enabled: false (零值)
			// failover_enabled: false (零值)
			// session_affinity_enabled: false (零值)
			// 等等...
		},
	}

	// 保存配置
	if err := testConfig.Save(configFile); err != nil {
		t.Fatalf("保存配置失败: %v", err)
	}

	// 读取保存的配置
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("读取配置文件失败: %v", err)
	}

	var savedConfig map[string]interface{}
	if err := json.Unmarshal(data, &savedConfig); err != nil {
		t.Fatalf("解析配置文件失败: %v", err)
	}

	// 验证 proxy.rules 存在
	proxyMap, ok := savedConfig["proxy"].(map[string]interface{})
	if !ok {
		t.Fatal("保存的配置中应该包含 proxy 字段")
	}

	rules, ok := proxyMap["rules"].([]interface{})
	if !ok || len(rules) != 1 {
		t.Fatal("保存的配置中应该包含一个 proxy rule")
	}

	ruleMap, ok := rules[0].(map[string]interface{})
	if !ok {
		t.Fatal("proxy rule 应该是 map")
	}

	// 验证必要的字段存在
	if ruleMap["domain"] != "example.com" {
		t.Error("domain 字段应该存在")
	}
	if ruleMap["enabled"] != true {
		t.Error("enabled 字段应该存在且为 true")
	}
	if ruleMap["ssl_only"] != true {
		t.Error("ssl_only 字段应该存在且为 true")
	}

	// 验证零值字段不应该存在（如果默认值也是零值）
	zeroValueFields := []string{
		"auth_enabled",
		"cdn_enabled",
		"health_check_enabled",
		"failover_enabled",
		"session_affinity_enabled",
		"auth_cookie_domain",
		"auth_session_timeout",
		"cdn_preset",
		"cdn_ttl_seconds",
		"connect_timeout_sec",
		"expect_continue_timeout_sec",
		"expected_status_code",
		"failure_threshold",
		"max_retries",
		"retry_interval",
		"recovery_threshold",
		"health_check_interval",
		"health_check_timeout",
		"health_check_method",
		"health_check_path",
		"session_affinity_method",
		"session_affinity_cookie",
		"session_affinity_header",
		"session_affinity_ttl",
	}

	for _, field := range zeroValueFields {
		if _, exists := ruleMap[field]; exists {
			t.Errorf("零值字段 %s 不应该被保存（默认值也是零值）", field)
		}
	}

	t.Logf("保存的配置文件内容:\n%s", string(data))
}

