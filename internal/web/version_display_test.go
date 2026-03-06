package web

import (
	"fmt"
	"strings"
	"testing"
)

// formatVersionForDisplay 与 getSystemStats 中版本处理逻辑一致，用于测试
func formatVersionForDisplay(version string) string {
	return "SSLcat v" + strings.TrimPrefix(version, "v")
}

func TestFormatVersionForDisplay(t *testing.T) {
	tests := []struct {
		version  string
		expected string
	}{
		{"v1.7.3", "SSLcat v1.7.3"},
		{"v1.7.3-rc1", "SSLcat v1.7.3-rc1"},
		{"1.7.3", "SSLcat v1.7.3"},
		{"1.7.3-rc1", "SSLcat v1.7.3-rc1"},
		{"", "SSLcat v"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("version=%q", tt.version), func(t *testing.T) {
			got := formatVersionForDisplay(tt.version)
			if got != tt.expected {
				t.Errorf("formatVersionForDisplay(%q) = %q, want %q", tt.version, got, tt.expected)
			}
		})
	}
}
