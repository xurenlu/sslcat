package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/proxy"
)

func main() {
	fmt.Println("=== SSLcat 追踪头部传递功能演示 ===")

	// 创建日志记录器
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// 创建代理管理器
	manager := &proxy.Manager{}

	// 创建测试请求
	req, err := http.NewRequest("GET", "http://example.com/api/test", nil)
	if err != nil {
		log.Fatal(err)
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

	// 添加一些会被清理的代理头部
	req.Header.Set("X-Forwarded-For", "192.168.1.1")
	req.Header.Set("X-Real-IP", "192.168.1.1")
	req.Header.Set("User-Agent", "Test-Agent/1.0")

	fmt.Println("\n1. 原始请求头部:")
	printHeaders(req.Header)

	// 提取追踪头部
	fmt.Println("\n2. 提取追踪头部:")
	traceHeaders := manager.ExtractTraceHeaders(req)
	for key, value := range traceHeaders {
		fmt.Printf("   %s: %s\n", key, value)
	}

	// 模拟清理代理头部（但不清理追踪头部）
	fmt.Println("\n3. 清理代理头部:")
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-IP")
	fmt.Println("   已清理 X-Forwarded-For 和 X-Real-IP")

	// 重新注入追踪头部
	fmt.Println("\n4. 重新注入追踪头部:")
	manager.InjectTraceHeaders(req, traceHeaders)

	fmt.Println("\n5. 最终请求头部:")
	printHeaders(req.Header)

	fmt.Println("\n=== 演示完成 ===")
	fmt.Println("追踪头部已成功传递到上游服务器！")
}

func printHeaders(headers http.Header) {
	for key, values := range headers {
		for _, value := range values {
			fmt.Printf("   %s: %s\n", key, value)
		}
	}
}
