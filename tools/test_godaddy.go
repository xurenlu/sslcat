package main

import (
	"context"
	"fmt"
	"time"

	"github.com/xurenlu/sslcat/internal/ssl"
)

func main() {
	fmt.Println("=== GoDaddy DNS 提供商测试 ===")
	fmt.Println("测试 GoDaddy DNS 提供商的连接和功能")
	fmt.Println("")

	// 创建日志记录器
	logger := &SimpleLogger{}

	// 测试 GoDaddy DNS
	fmt.Println("🔵 测试 GoDaddy DNS...")
	testGoDaddyDNS(logger)

	fmt.Println("")
	fmt.Println("=== 测试完成 ===")
	fmt.Println("注意：")
	fmt.Println("1. 请确保已配置正确的 GoDaddy API 密钥")
	fmt.Println("2. 确保 API 密钥有足够的权限")
	fmt.Println("3. 如果测试失败，请检查 API 密钥配置")
}

func testGoDaddyDNS(logger *SimpleLogger) {
	// GoDaddy API 密钥 - 需要替换为真实密钥
	apiKey := "YOUR_GODADDY_API_KEY"
	apiSecret := "YOUR_GODADDY_API_SECRET"

	if apiKey == "YOUR_GODADDY_API_KEY" {
		fmt.Println("❌ GoDaddy DNS: 请先配置 API 密钥")
		fmt.Println("   请在代码中替换 YOUR_GODADDY_API_KEY 和 YOUR_GODADDY_API_SECRET")
		fmt.Println("   或者通过环境变量设置:")
		fmt.Println("   export GODADDY_API_KEY=your_api_key")
		fmt.Println("   export GODADDY_API_SECRET=your_api_secret")
		return
	}

	// 创建 GoDaddy DNS 提供商
	provider := ssl.NewGoDaddyProvider(apiKey, apiSecret, logger)

	// 验证配置
	if err := provider.Validate(); err != nil {
		fmt.Printf("❌ GoDaddy DNS: 配置验证失败: %v\n", err)
		return
	}

	fmt.Printf("✓ GoDaddy DNS: 配置验证通过\n")

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 测试获取域名列表
	fmt.Printf("正在获取 GoDaddy 域名列表...\n")
	domains, err := provider.ListDomains(ctx)
	if err != nil {
		fmt.Printf("❌ GoDaddy DNS: 获取域名列表失败: %v\n", err)
		return
	}

	fmt.Printf("✓ GoDaddy DNS: 成功获取到 %d 个域名/DNS记录:\n", len(domains))
	for i, domain := range domains {
		if i >= 5 { // 只显示前5个
			fmt.Printf("... 还有 %d 个记录\n", len(domains)-5)
			break
		}
		fmt.Printf("  - %s (%s) - %s\n", domain.Name, domain.Type, domain.Status)
	}

	// 测试 TXT 记录操作（如果有域名的话）
	if len(domains) > 0 {
		fmt.Println("\n🔵 测试 TXT 记录操作...")
		testTXTRecordOperations(provider, domains[0].Name, ctx)
	}
}

func testTXTRecordOperations(provider ssl.DNSProviderInterface, domain string, ctx context.Context) {
	// 生成测试用的 TXT 记录
	testName := "_acme-challenge-test"
	testValue := "test-value-" + fmt.Sprintf("%d", time.Now().Unix())
	testTTL := 600

	fmt.Printf("测试域名: %s\n", domain)
	fmt.Printf("测试记录名: %s\n", testName)
	fmt.Printf("测试值: %s\n", testValue)

	// 1. 设置 TXT 记录
	fmt.Println("1. 设置 TXT 记录...")
	err := provider.SetTXTRecord(ctx, domain, testName, testValue, testTTL)
	if err != nil {
		fmt.Printf("❌ 设置 TXT 记录失败: %v\n", err)
		return
	}
	fmt.Println("✓ TXT 记录设置成功")

	// 等待一下让记录生效
	fmt.Println("等待 3 秒让记录生效...")
	time.Sleep(3 * time.Second)

	// 2. 获取 TXT 记录
	fmt.Println("2. 获取 TXT 记录...")
	retrievedValue, err := provider.GetTXTRecord(ctx, domain, testName)
	if err != nil {
		fmt.Printf("❌ 获取 TXT 记录失败: %v\n", err)
	} else {
		fmt.Printf("✓ 获取 TXT 记录成功: %s\n", retrievedValue)
		if retrievedValue == testValue {
			fmt.Println("✓ 记录值匹配")
		} else {
			fmt.Printf("⚠️  记录值不匹配，期望: %s，实际: %s\n", testValue, retrievedValue)
		}
	}

	// 3. 删除 TXT 记录
	fmt.Println("3. 删除 TXT 记录...")
	err = provider.DeleteTXTRecord(ctx, domain, testName)
	if err != nil {
		fmt.Printf("❌ 删除 TXT 记录失败: %v\n", err)
		return
	}
	fmt.Println("✓ TXT 记录删除成功")

	fmt.Println("✓ 所有 TXT 记录操作测试完成")
}

// SimpleLogger 简单的日志记录器
type SimpleLogger struct{}

func (l *SimpleLogger) Infof(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func (l *SimpleLogger) Warnf(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func (l *SimpleLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}

func (l *SimpleLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}
