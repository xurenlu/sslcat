package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigWatcher_Basic(t *testing.T) {
	// 创建临时配置文件
	tempDir, err := ioutil.TempDir("", "sslcat_config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configFile := filepath.Join(tempDir, "test.conf")

	// 创建初始配置
	initialConfig := &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		SSL: SSLConfig{
			Email: "test@example.com",
		},
		Admin: AdminConfig{
			Username: "admin",
		},
		AdminPrefix: "/test-panel",
	}

	// 写入初始配置文件
	configData, err := json.MarshalIndent(initialConfig, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	err = ioutil.WriteFile(configFile, configData, 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// 创建配置监听器
	watcher, err := NewConfigWatcher(configFile, initialConfig)
	if err != nil {
		t.Fatalf("Failed to create config watcher: %v", err)
	}
	defer watcher.Stop()

	// 测试基本功能
	if watcher.GetConfig() == nil {
		t.Error("Config should not be nil")
	}

	if watcher.GetLastHash() == "" {
		t.Error("Last hash should not be empty")
	}

	// 测试配置文件信息
	info, err := watcher.GetConfigFileInfo()
	if err != nil {
		t.Fatalf("Failed to get config file info: %v", err)
	}

	if info["file_path"] != configFile {
		t.Errorf("Expected file path %s, got %v", configFile, info["file_path"])
	}

	if info["hash"] == "" {
		t.Error("Config hash should not be empty")
	}
}

func TestReloadManager_Basic(t *testing.T) {
	rm := NewReloadManager()

	// 测试基本功能
	stats := rm.GetStats()
	if stats["component_count"] != 0 {
		t.Errorf("Expected 0 components, got %v", stats["component_count"])
	}

	// 创建模拟组件
	mockComponent := &MockReloadableComponent{
		name: "test_component",
	}

	// 注册组件
	rm.RegisterComponent(mockComponent)

	stats = rm.GetStats()
	if stats["component_count"] != 1 {
		t.Errorf("Expected 1 component, got %v", stats["component_count"])
	}

	// 检查组件是否注册
	if !rm.IsComponentRegistered("test_component") {
		t.Error("Component should be registered")
	}

	// 注销组件
	rm.UnregisterComponent("test_component")

	stats = rm.GetStats()
	if stats["component_count"] != 0 {
		t.Errorf("Expected 0 components after unregister, got %v", stats["component_count"])
	}
}

func TestReloadManager_ReloadAll(t *testing.T) {
	rm := NewReloadManager()

	// 创建模拟组件
	mockComponent := &MockReloadableComponent{
		name: "test_component",
	}

	rm.RegisterComponent(mockComponent)

	// 创建测试配置
	oldConfig := &Config{
		Server: ServerConfig{Port: 8080},
	}

	newConfig := &Config{
		Server: ServerConfig{Port: 8443},
	}

	// 测试重载
	err := rm.ReloadAll(oldConfig, newConfig)
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// 检查组件是否被调用
	if !mockComponent.validateCalled {
		t.Error("Validate should have been called")
	}

	if !mockComponent.reloadCalled {
		t.Error("Reload should have been called")
	}

	// 检查统计信息
	stats := rm.GetStats()
	if stats["success_count"] != int64(1) {
		t.Errorf("Expected 1 success, got %v", stats["success_count"])
	}
}

func TestReloadManager_ValidationFailure(t *testing.T) {
	rm := NewReloadManager()

	// 创建会验证失败的模拟组件
	mockComponent := &MockReloadableComponent{
		name:          "failing_component",
		validateError: fmt.Errorf("validation failed"),
	}

	rm.RegisterComponent(mockComponent)

	// 测试重载
	err := rm.ReloadAll(&Config{}, &Config{})
	if err == nil {
		t.Error("Expected validation error")
	}

	if !mockComponent.validateCalled {
		t.Error("Validate should have been called")
	}

	if mockComponent.reloadCalled {
		t.Error("Reload should not have been called after validation failure")
	}
}

// MockReloadableComponent 模拟可重载组件
type MockReloadableComponent struct {
	name           string
	validateCalled bool
	reloadCalled   bool
	validateError  error
	reloadError    error
}

func (m *MockReloadableComponent) GetName() string {
	return m.name
}

func (m *MockReloadableComponent) Validate(newConfig *Config) error {
	m.validateCalled = true
	return m.validateError
}

func (m *MockReloadableComponent) Reload(newConfig *Config) error {
	m.reloadCalled = true
	return m.reloadError
}
