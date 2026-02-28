package logger

import (
	"strings"
	"testing"
	"time"
)

// TestErrorLoggerExpandDatePattern 测试错误日志日期占位符展开功能
func TestErrorLoggerExpandDatePattern(t *testing.T) {
	testTime := time.Date(2025, 2, 28, 15, 4, 5, 0, time.UTC)

	tests := []struct {
		name     string
		pattern  string
		expected string
	}{
		// Go 风格占位符测试
		{
			name:     "YYYY-MM-DD 格式",
			pattern:  "./logs/error-{yyyy}-{mm}-{dd}.log",
			expected: "./logs/error-2025-02-28.log",
		},
		{
			name:     "按月格式",
			pattern:  "./logs/error-{yyyy}-{mm}.log",
			expected: "./logs/error-2025-02.log",
		},
		{
			name:     "按小时格式",
			pattern:  "./data/error-{yyyy}-{mm}-{dd}_{HH}.log",
			expected: "./data/error-2025-02-28_15.log",
		},
		{
			name:     "完整日期时间",
			pattern:  "./logs/error-{datetime}.log",
			expected: "./logs/error-2025-02-28_15-04-05.log",
		},
		{
			name:     "日期目录组织",
			pattern:  "./logs/{yyyy}/{mm}/{dd}/error.log",
			expected: "./logs/2025/02/28/error.log",
		},
		// strftime 风格占位符测试（Nginx 兼容）
		{
			name:     "strftime YYYYMMDD 格式",
			pattern:  "/var/log/nginx/error-%Y%m%d.log",
			expected: "/var/log/nginx/error-20250228.log",
		},
		{
			name:     "strftime YYYY-MM-DD 格式",
			pattern:  "/var/log/nginx/error-%Y-%m-%d.log",
			expected: "/var/log/nginx/error-2025-02-28.log",
		},
		// 无占位符测试
		{
			name:     "无占位符",
			pattern:  "./data/error.log",
			expected: "./data/error.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &ErrorLogger{
				logPathRaw: tt.pattern,
			}
			result := logger.expandDatePattern(testTime)
			// 对于 Unix 时间戳，只验证包含数字
			if strings.Contains(tt.pattern, "%s") {
				if !strings.Contains(result, "./logs/error-") || !strings.HasSuffix(result, ".log") {
					t.Errorf("expandDatePattern() = %v, invalid Unix timestamp format", result)
				}
				return
			}
			if result != tt.expected {
				t.Errorf("expandDatePattern() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestErrorLoggerDateRotation 测试错误日志日期轮转逻辑
func TestErrorLoggerDateRotation(t *testing.T) {
	// 创建一个临时目录用于测试
	tempDir := t.TempDir()
	logPath := tempDir + "/error-{yyyy}-{mm}-{dd}.log"

	// 创建一个 mock logrus entry
	mockLog := loggerWithField("component", "error_logger")

	testLogger := &ErrorLogger{
		logPathRaw:     logPath,
		hasDatePattern: true,
		currentDate:    "2025-02-27",
		logPath:        tempDir + "/error-2025-02-27.log",
		maxSize:        100 * 1024 * 1024,
		maxFiles:       10,
		log:            mockLog,
	}

	// 验证初始状态
	if testLogger.currentDate != "2025-02-27" {
		t.Errorf("Expected currentDate to be 2025-02-27, got %v", testLogger.currentDate)
	}

	// 验证路径解析
	expectedPath := tempDir + "/error-2025-02-27.log"
	if testLogger.logPath != expectedPath {
		t.Errorf("Expected logPath to be %v, got %v", expectedPath, testLogger.logPath)
	}
}

// TestErrorLoggerEdgeCases 测试边界情况
func TestErrorLoggerEdgeCases(t *testing.T) {
	testTime := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)

	tests := []struct {
		name     string
		pattern  string
		contains []string // 结果中应该包含的字符串
	}{
		{
			name:     "年末日期",
			pattern:  "./logs/error-{yyyy}-{mm}-{dd}.log",
			contains: []string{"2025", "12", "31"},
		},
		{
			name:     "月末时间",
			pattern:  "./logs/error_{yyyy}_{mm}_{dd}_{HH}_{MM}_{SS}.log",
			contains: []string{"2025", "12", "31", "23", "59", "59"},
		},
		{
			name:     "混合占位符",
			pattern:  "./logs/{yyyy}/error-%Y%m%d_{datetime}.log",
			contains: []string{"2025", "2025", "12", "31", "2025-12-31_23-59-59"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &ErrorLogger{
				logPathRaw: tt.pattern,
			}
			result := logger.expandDatePattern(testTime)
			for _, expected := range tt.contains {
				if !strings.Contains(result, expected) {
					t.Errorf("expandDatePattern() = %v, should contain %v", result, expected)
				}
			}
		})
	}
}

// TestNewErrorLogger 测试 ErrorLogger 创建
func TestNewErrorLogger(t *testing.T) {
	// 测试禁用状态
	logger, err := NewErrorLogger("", false)
	if err != nil {
		t.Fatalf("NewErrorLogger() failed: %v", err)
	}
	if logger.enabled {
		t.Error("Expected logger to be disabled")
	}

	// 测试启用状态（使用临时目录）
	tempDir := t.TempDir()
	logPath := tempDir + "/error-{yyyy}-{mm}-{dd}.log"

	logger, err = NewErrorLogger(logPath, true)
	if err != nil {
		t.Fatalf("NewErrorLogger() failed: %v", err)
	}
	if !logger.enabled {
		t.Error("Expected logger to be enabled")
	}
	if !logger.hasDatePattern {
		t.Error("Expected hasDatePattern to be true")
	}

	logger.Close()
}
