package config

import (
	"testing"
)

func TestDetectProxyLoop(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		rule        *ProxyRule
		expectError bool
		description string
	}{
		{
			name: "循环检测 - 代理到自己的80端口",
			config: &Config{
				Server: ServerConfig{
					Port:     443,
					PortMode: "standard", // 会监听 80 和 443
				},
			},
			rule: &ProxyRule{
				Domain: "gg.some.im",
				Target: "127.0.0.1",
				Port:   80,
			},
			expectError: true,
			description: "应该检测到代理到自己的80端口",
		},
		{
			name: "循环检测 - 代理到 localhost",
			config: &Config{
				Server: ServerConfig{
					Port:     443,
					PortMode: "standard",
				},
			},
			rule: &ProxyRule{
				Domain: "test.example.com",
				Target: "localhost",
				Port:   443,
			},
			expectError: true,
			description: "应该检测到代理到 localhost:443",
		},
		{
			name: "循环检测 - 代理到 0.0.0.0",
			config: &Config{
				Server: ServerConfig{
					Port:     8080,
					PortMode: "custom",
					CustomPort: 8080,
				},
			},
			rule: &ProxyRule{
				Domain: "test.example.com",
				Target: "0.0.0.0",
				Port:   8080,
			},
			expectError: true,
			description: "应该检测到代理到 0.0.0.0:8080",
		},
		{
			name: "正常配置 - 代理到外部服务",
			config: &Config{
				Server: ServerConfig{
					Port:     443,
					PortMode: "standard",
				},
			},
			rule: &ProxyRule{
				Domain: "test.example.com",
				Target: "192.168.1.100",
				Port:   8080,
			},
			expectError: false,
			description: "代理到外部IP应该通过",
		},
		{
			name: "正常配置 - 代理到本地不同端口",
			config: &Config{
				Server: ServerConfig{
					Port:     443,
					PortMode: "standard",
				},
			},
			rule: &ProxyRule{
				Domain: "test.example.com",
				Target: "127.0.0.1",
				Port:   3000, // 不是 sslcat 监听的端口
			},
			expectError: false,
			description: "代理到本地不同端口应该通过",
		},
		{
			name: "循环检测 - 127.x.x.x 网段",
			config: &Config{
				Server: ServerConfig{
					Port:     443,
					PortMode: "standard",
				},
			},
			rule: &ProxyRule{
				Domain: "test.example.com",
				Target: "127.0.0.2",
				Port:   80,
			},
			expectError: true,
			description: "应该检测到 127.x.x.x 网段的循环",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := &ConfigWatcher{}
			err := watcher.detectProxyLoop(tt.config, tt.rule)

			if tt.expectError && err == nil {
				t.Errorf("%s: 期望检测到错误，但没有返回错误", tt.description)
			}

			if !tt.expectError && err != nil {
				t.Errorf("%s: 不应该返回错误，但返回了: %v", tt.description, err)
			}

			if err != nil {
				t.Logf("检测到的错误: %v", err)
			}
		})
	}
}

func TestDetectBackendLoop(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		rule        *ProxyRule
		backend     *ProxyBackend
		expectError bool
		description string
	}{
		{
			name: "负载均衡循环检测 - 后端指向自己",
			config: &Config{
				Server: ServerConfig{
					Port:     443,
					PortMode: "standard",
				},
			},
			rule: &ProxyRule{
				Domain:               "lb.example.com",
				LoadBalancerEnabled:  true,
			},
			backend: &ProxyBackend{
				Host: "localhost",
				Port: 80,
			},
			expectError: true,
			description: "负载均衡后端指向自己应该被检测",
		},
		{
			name: "负载均衡正常配置",
			config: &Config{
				Server: ServerConfig{
					Port:     443,
					PortMode: "standard",
				},
			},
			rule: &ProxyRule{
				Domain:               "lb.example.com",
				LoadBalancerEnabled:  true,
			},
			backend: &ProxyBackend{
				Host: "192.168.1.100",
				Port: 8080,
			},
			expectError: false,
			description: "负载均衡后端指向外部服务应该通过",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			watcher := &ConfigWatcher{}
			err := watcher.detectBackendLoop(tt.config, tt.rule, tt.backend)

			if tt.expectError && err == nil {
				t.Errorf("%s: 期望检测到错误，但没有返回错误", tt.description)
			}

			if !tt.expectError && err != nil {
				t.Errorf("%s: 不应该返回错误，但返回了: %v", tt.description, err)
			}

			if err != nil {
				t.Logf("检测到的错误: %v", err)
			}
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	watcher := &ConfigWatcher{}

	tests := []struct {
		host     string
		expected bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"127.255.255.255", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"192.168.1.1", false},
		{"example.com", false},
		{"10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := watcher.isLocalhost(tt.host)
			if result != tt.expected {
				t.Errorf("isLocalhost(%q) = %v, expected %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestGetListeningPorts(t *testing.T) {
	watcher := &ConfigWatcher{}

	tests := []struct {
		name          string
		config        *Config
		expectedPorts []int
	}{
		{
			name: "标准模式",
			config: &Config{
				Server: ServerConfig{
					Port:     443,
					PortMode: "standard",
				},
			},
			expectedPorts: []int{443, 80, 443}, // 主端口 + HTTP + HTTPS
		},
		{
			name: "自定义模式",
			config: &Config{
				Server: ServerConfig{
					Port:       8443,
					PortMode:   "custom",
					CustomPort: 8080,
				},
			},
			expectedPorts: []int{8443, 8080},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := watcher.getListeningPorts(tt.config)
			
			// 检查是否包含所有期望的端口
			for _, expectedPort := range tt.expectedPorts {
				found := false
				for _, port := range ports {
					if port == expectedPort {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("期望端口列表包含 %d，但没有找到。实际端口: %v", expectedPort, ports)
				}
			}
		})
	}
}

