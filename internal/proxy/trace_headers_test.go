package proxy

import (
	"net/http"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestExtractTraceHeaders(t *testing.T) {
	// 创建测试请求
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 添加各种追踪头部
	req.Header.Set("traceparent", "00-92ebd5e4a0c2befcaecd84569501ffab-7e9c28c5fcd62c065fbf1b6aa5b3e62a-01")
	req.Header.Set("tracestate", "congo=t61rcWkgMzE")
	req.Header.Set("X-Trace-ID", "92ebd5e4a0c2befcaecd84569501ffab")
	req.Header.Set("X-Span-ID", "7e9c28c5fcd62c065fbf1b6aa5b3e62a")
	req.Header.Set("X-Request-ID", "92ebd5e4a0c2befc")
	req.Header.Set("X-B3-TraceId", "92ebd5e4a0c2befcaecd84569501ffab")
	req.Header.Set("X-B3-SpanId", "7e9c28c5fcd62c065fbf1b6aa5b3e62a")
	req.Header.Set("X-B3-ParentSpanId", "parent-span-id")
	req.Header.Set("X-Cloud-Trace-Context", "105445aa7843bc8bf206b120001000/0;o=1")
	req.Header.Set("X-Amzn-Trace-Id", "Root=1-5e645f3e-1234567890abcdef")
	req.Header.Set("baggage", "key1=value1,key2=value2")
	req.Header.Set("Baggage-Custom", "custom-value")

	// 创建代理管理器实例
	manager := &Manager{
		log: logrus.NewEntry(logrus.New()),
	}

	// 提取追踪头部
	traceHeaders := manager.ExtractTraceHeaders(req)

	// 验证提取的头部
	expectedHeaders := map[string]string{
		"traceparent":           "00-92ebd5e4a0c2befcaecd84569501ffab-7e9c28c5fcd62c065fbf1b6aa5b3e62a-01",
		"tracestate":            "congo=t61rcWkgMzE",
		"X-Trace-ID":            "92ebd5e4a0c2befcaecd84569501ffab",
		"X-Span-ID":             "7e9c28c5fcd62c065fbf1b6aa5b3e62a",
		"X-Request-ID":          "92ebd5e4a0c2befc",
		"X-B3-TraceId":          "92ebd5e4a0c2befcaecd84569501ffab",
		"X-B3-SpanId":           "7e9c28c5fcd62c065fbf1b6aa5b3e62a",
		"X-B3-ParentSpanId":     "parent-span-id",
		"X-Cloud-Trace-Context": "105445aa7843bc8bf206b120001000/0;o=1",
		"X-Amzn-Trace-Id":       "Root=1-5e645f3e-1234567890abcdef",
		"baggage":               "key1=value1,key2=value2",
		"Baggage-Custom":        "custom-value",
	}

	for key, expectedValue := range expectedHeaders {
		if actualValue, exists := traceHeaders[key]; !exists {
			t.Errorf("Expected header %s not found", key)
		} else if actualValue != expectedValue {
			t.Errorf("Header %s: expected %s, got %s", key, expectedValue, actualValue)
		}
	}

	// 验证没有提取非追踪头部
	nonTraceHeaders := []string{"Authorization", "Cookie", "User-Agent"}
	for _, header := range nonTraceHeaders {
		if _, exists := traceHeaders[header]; exists {
			t.Errorf("Non-trace header %s should not be extracted", header)
		}
	}
}

func TestInjectTraceHeaders(t *testing.T) {
	// 创建测试请求
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 准备追踪头部
	traceHeaders := map[string]string{
		"traceparent":  "00-92ebd5e4a0c2befcaecd84569501ffab-7e9c28c5fcd62c065fbf1b6aa5b3e62a-01",
		"X-Trace-ID":   "92ebd5e4a0c2befcaecd84569501ffab",
		"X-Span-ID":    "7e9c28c5fcd62c065fbf1b6aa5b3e62a",
		"X-Request-ID": "92ebd5e4a0c2befc",
		"X-B3-TraceId": "92ebd5e4a0c2befcaecd84569501ffab",
		"X-B3-SpanId":  "7e9c28c5fcd62c065fbf1b6aa5b3e62a",
	}

	// 创建代理管理器实例
	manager := &Manager{
		log: logrus.NewEntry(logrus.New()),
	}

	// 注入追踪头部
	manager.InjectTraceHeaders(req, traceHeaders)

	// 验证注入的头部
	for key, expectedValue := range traceHeaders {
		actualValue := req.Header.Get(key)
		if actualValue != expectedValue {
			t.Errorf("Header %s: expected %s, got %s", key, expectedValue, actualValue)
		}
	}
}

func TestTraceHeadersPreservation(t *testing.T) {
	// 创建测试请求
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 添加追踪头部
	req.Header.Set("traceparent", "00-92ebd5e4a0c2befcaecd84569501ffab-7e9c28c5fcd62c065fbf1b6aa5b3e62a-01")
	req.Header.Set("X-Trace-ID", "92ebd5e4a0c2befcaecd84569501ffab")
	req.Header.Set("X-Span-ID", "7e9c28c5fcd62c065fbf1b6aa5b3e62a")

	// 添加一些会被清理的代理头部
	req.Header.Set("X-Forwarded-For", "192.168.1.1")
	req.Header.Set("X-Real-IP", "192.168.1.1")

	// 创建代理管理器实例
	manager := &Manager{
		log: logrus.NewEntry(logrus.New()),
	}

	// 提取追踪头部
	traceHeaders := manager.ExtractTraceHeaders(req)

	// 模拟清理代理头部（但不清理追踪头部）
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-IP")

	// 重新注入追踪头部
	manager.InjectTraceHeaders(req, traceHeaders)

	// 验证追踪头部仍然存在
	expectedTraceHeaders := map[string]string{
		"traceparent": "00-92ebd5e4a0c2befcaecd84569501ffab-7e9c28c5fcd62c065fbf1b6aa5b3e62a-01",
		"X-Trace-ID":  "92ebd5e4a0c2befcaecd84569501ffab",
		"X-Span-ID":   "7e9c28c5fcd62c065fbf1b6aa5b3e62a",
	}

	for key, expectedValue := range expectedTraceHeaders {
		actualValue := req.Header.Get(key)
		if actualValue != expectedValue {
			t.Errorf("Trace header %s: expected %s, got %s", key, expectedValue, actualValue)
		}
	}

	// 验证代理头部已被清理
	if req.Header.Get("X-Forwarded-For") != "" {
		t.Error("X-Forwarded-For should be cleaned")
	}
	if req.Header.Get("X-Real-IP") != "" {
		t.Error("X-Real-IP should be cleaned")
	}
}
