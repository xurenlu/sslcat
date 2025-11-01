package main

import (
	"context"
	"fmt"
	"time"

	"github.com/xurenlu/sslcat/internal/ssl"
)

func main() {
	fmt.Println("=== Cloudflare DNS 提供商测试 ===")
	fmt.Println("测试 Cloudflare DNS 提供商的连接和功能")
	fmt.Println("")

	// 创建日志记录器
	logger := &SimpleLogger{}

	// 测试 Cloudflare DNS
	fmt.Println("🔵 测试 Cloudflare DNS...")
	testCloudflareDNS(logger)

	fmt.Println("")
	fmt.Println("=== 测试完成 ===")
	fmt.Println("注意：")
	fmt.Println("1. 请确保已配置正确的 Cloudflare API Token")
	fmt.Println("2. 确保 API Token 有足够的权限")
	fmt.Println("3. 如果测试失败，请检查 API Token 配置")
}

func testCloudflareDNS(logger *SimpleLogger) {
	// Cloudflare API 凭据 - 需要替换为真实凭据
	apiToken := "YOUR_CLOUDFLARE_API_TOKEN"
	zoneID := "YOUR_CLOUDFLARE_ZONE_ID"

	if apiToken == "YOUR_CLOUDFLARE_API_TOKEN" {
		fmt.Println("❌ Cloudflare DNS: 请先配置 API 凭据")
		fmt.Println("   请在代码中替换以下值:")
		fmt.Println("   - YOUR_CLOUDFLARE_API_TOKEN: 你的 Cloudflare API Token")
		fmt.Println("   - YOUR_CLOUDFLARE_ZONE_ID: 你的 Zone ID（可选）")
		fmt.Println("")
		fmt.Println("   获取方法:")
		fmt.Println("   1. 登录 Cloudflare 控制台")
		fmt.Println("   2. 进入 My Profile -> API Tokens")
		fmt.Println("   3. 创建 Custom Token 或使用 Global API Key")
		fmt.Println("   4. 获取 Zone ID: 在域名概览页面右侧")
		return
	}

	// 创建 Cloudflare DNS 提供商
	provider := ssl.NewCloudflareProvider(apiToken, zoneID, logger)

	// 验证配置
	if err := provider.Validate(); err != nil {
		fmt.Printf("❌ Cloudflare DNS: 配置验证失败: %v\n", err)
		return
	}

	fmt.Printf("✓ Cloudflare DNS: 配置验证通过\n")

	// 创建上下文
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 测试获取域名列表
	fmt.Printf("正在获取 Cloudflare 域名列表...\n")
	domains, err := provider.ListDomains(ctx)
	if err != nil {
		fmt.Printf("❌ Cloudflare DNS: 获取域名列表失败: %v\n", err)
		return
	}

	fmt.Printf("✓ Cloudflare DNS: 成功获取到 %d 个域名/DNS记录:\n", len(domains))
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
