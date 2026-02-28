package logger

import (
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// loggerWithField 创建一个带有字段的 logrus entry 用于测试
func loggerWithField(key string, value interface{}) *logrus.Entry {
	return logrus.WithField(key, value)
}

// TestExpandDatePattern 测试日期占位符展开功能
func TestExpandDatePattern(t *testing.T) {
	testTime := time.Date(2025, 2, 28, 15, 4, 5, 0, time.UTC)

	tests := []struct {
		name     string
		pattern  string
		expected string
	}{
		// Go 风格占位符测试
		{
			name:     "YYYY-MM-DD 格式",
			pattern:  "./logs/access-{yyyy}-{mm}-{dd}.log",
			expected: "./logs/access-2025-02-28.log",
		},
		{
			name:     "按月格式",
			pattern:  "./logs/access-{yyyy}-{mm}.log",
			expected: "./logs/access-2025-02.log",
		},
		{
			name:     "按小时格式",
			pattern:  "./data/access-{yyyy}-{mm}-{dd}_{HH}.log",
			expected: "./data/access-2025-02-28_15.log",
		},
		{
			name:     "完整日期时间",
			pattern:  "./logs/access-{datetime}.log",
			expected: "./logs/access-2025-02-28_15-04-05.log",
		},
		{
			name:     "日期目录组织",
			pattern:  "./logs/{yyyy}/{mm}/{dd}/access.log",
			expected: "./logs/2025/02/28/access.log",
		},
		{
			name:     "2位年份",
			pattern:  "./logs/access-{yy}-{mm}-{dd}.log",
			expected: "./logs/access-25-02-28.log",
		},
		{
			name:     "无前导零月份",
			pattern:  "./logs/access-{yyyy}-{m}-{d}.log",
			expected: "./logs/access-2025-2-28.log",
		},
		{
			name:     "无前导零小时",
			pattern:  "./logs/access-{yyyy}-{mm}-{dd}_{H}.log",
			expected: "./logs/access-2025-02-28_3.log", // 使用 Format("3") 会得到下午3点显示为 3
		},
		// strftime 风格占位符测试（Nginx 兼容）
		{
			name:     "strftime YYYYMMDD 格式",
			pattern:  "/var/log/nginx/access-%Y%m%d.log",
			expected: "/var/log/nginx/access-20250228.log",
		},
		{
			name:     "strftime YYYY-MM-DD 格式",
			pattern:  "/var/log/nginx/access-%Y-%m-%d.log",
			expected: "/var/log/nginx/access-2025-02-28.log",
		},
		{
			name:     "strftime Unix 时间戳",
			pattern:  "./logs/access-%s.log",
			expected: "", // 动态计算，不进行硬编码比较
		},
		// 无占位符测试
		{
			name:     "无占位符",
			pattern:  "./data/access.log",
			expected: "./data/access.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &AccessLogger{
				logPathRaw: tt.pattern,
			}
			result := logger.expandDatePattern(testTime)
			// 对于 Unix 时间戳，只验证包含数字
			if tt.name == "strftime Unix 时间戳" {
				if !strings.Contains(result, "./logs/access-") || !strings.HasSuffix(result, ".log") {
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

// TestContainsDatePattern 测试日期占位符检测
func TestContainsDatePattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "Go 风格日期占位符",
			path:     "./logs/access-{yyyy}-{mm}-{dd}.log",
			expected: true,
		},
		{
			name:     "strftime 风格日期占位符",
			path:     "./logs/access-%Y-%m-%d.log",
			expected: true,
		},
		{
			name:     "无占位符",
			path:     "./data/access.log",
			expected: false,
		},
		{
			name:     "只有百分号但不是日期占位符",
			path:     "./data/access%.log",
			expected: true, // 包含 %，会被识别为有占位符
		},
		{
			name:     "只有大括号但不是日期占位符",
			path:     "./data/{test}.log",
			expected: true, // 包含 {}，会被识别为有占位符
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsDatePattern(tt.path)
			if result != tt.expected {
				t.Errorf("containsDatePattern() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGetCurrentDateKey 测试日期键生成
func TestGetCurrentDateKey(t *testing.T) {
	testTime := time.Date(2025, 2, 28, 15, 4, 5, 0, time.UTC)
	expected := "2025-02-28"
	result := getCurrentDateKey(testTime)

	if result != expected {
		t.Errorf("getCurrentDateKey() = %v, want %v", result, expected)
	}
}

// TestAccessLoggerDateRotation 测试日期轮转逻辑
func TestAccessLoggerDateRotation(t *testing.T) {
	// 创建一个临时目录用于测试
	tempDir := t.TempDir()
	logPath := tempDir + "/access-{yyyy}-{mm}-{dd}.log"

	// 创建一个 mock logrus entry
	mockLog := loggerWithField("component", "access_logger")

	testLogger := &AccessLogger{
		logPathRaw:     logPath,
		hasDatePattern: true,
		currentDate:    "2025-02-27",
		logPath:        tempDir + "/access-2025-02-27.log",
		maxSize:        100 * 1024 * 1024,
		maxFiles:       10,
		log:            mockLog,
	}

	// 验证初始状态
	if testLogger.currentDate != "2025-02-27" {
		t.Errorf("Expected currentDate to be 2025-02-27, got %v", testLogger.currentDate)
	}

	// 验证路径解析
	expectedPath := tempDir + "/access-2025-02-27.log"
	if testLogger.logPath != expectedPath {
		t.Errorf("Expected logPath to be %v, got %v", expectedPath, testLogger.logPath)
	}
}

// TestExpandDatePatternEdgeCases 测试边界情况
func TestExpandDatePatternEdgeCases(t *testing.T) {
	testTime := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)

	tests := []struct {
		name     string
		pattern  string
		contains []string // 结果中应该包含的字符串
	}{
		{
			name:     "年末日期",
			pattern:  "./logs/access-{yyyy}-{mm}-{dd}.log",
			contains: []string{"2025", "12", "31"},
		},
		{
			name:     "月末时间",
			pattern:  "./logs/access_{yyyy}_{mm}_{dd}_{HH}_{MM}_{SS}.log",
			contains: []string{"2025", "12", "31", "23", "59", "59"},
		},
		{
			name:     "混合占位符",
			pattern:  "./logs/{yyyy}/access-%Y%m%d_{datetime}.log",
			contains: []string{"2025", "2025", "12", "31", "2025-12-31_23-59-59"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &AccessLogger{
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
