package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/ssl"
)

func main() {
	fmt.Println("=== Cloudflare DNS 交互式测试 ===")
	fmt.Println("请输入你的 Cloudflare API 凭据进行测试")
	fmt.Println("")

	// 获取用户输入
	apiToken := getInput("请输入 Cloudflare API Token: ")
	if apiToken == "" {
		fmt.Println("❌ API Token 不能为空")
		return
	}

	zoneID := getInput("请输入 Zone ID (可选，留空会自动查找): ")

	fmt.Println("")
	fmt.Println("🔵 开始测试 Cloudflare DNS...")
	testCloudflareWithCredentials(apiToken, zoneID)
}

func getInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func testCloudflareWithCredentials(apiToken, zoneID string) {
	// 创建日志记录器
	logger := &SimpleLogger{}

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
		fmt.Println("")
		fmt.Println("可能的解决方案:")
		fmt.Println("1. 检查 API Token 是否正确")
		fmt.Println("2. 检查 API Token 是否有 Zone:Read 权限")
		fmt.Println("3. 检查网络连接是否正常")
		return
	}

	fmt.Printf("✅ Cloudflare DNS: 成功获取到 %d 个域名/DNS记录:\n", len(domains))

	if len(domains) == 0 {
		fmt.Println("⚠️  没有找到域名，可能的原因:")
		fmt.Println("1. 账户中没有域名")
		fmt.Println("2. API Token 权限不足")
		fmt.Println("3. Zone ID 配置错误")
		return
	}

	// 显示域名信息
	for i, domain := range domains {
		if i >= 10 { // 只显示前10个
			fmt.Printf("... 还有 %d 个记录\n", len(domains)-10)
			break
		}
		fmt.Printf("  - %s (%s) - %s\n", domain.Name, domain.Type, domain.Status)
	}

	// 询问是否测试 TXT 记录操作
	fmt.Println("")
	response := getInput("是否测试 TXT 记录操作？(y/n): ")
	if strings.ToLower(response) == "y" || strings.ToLower(response) == "yes" {
		if len(domains) > 0 {
			fmt.Println("\n🔵 测试 TXT 记录操作...")
			testTXTRecordOperations(provider, domains[0].Name, ctx)
		}
	}

	fmt.Println("")
	fmt.Println("✅ Cloudflare DNS 测试完成")
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
	fmt.Println("✅ TXT 记录设置成功")

	// 等待一下让记录生效
	fmt.Println("等待 3 秒让记录生效...")
	time.Sleep(3 * time.Second)

	// 2. 获取 TXT 记录
	fmt.Println("2. 获取 TXT 记录...")
	retrievedValue, err := provider.GetTXTRecord(ctx, domain, testName)
	if err != nil {
		fmt.Printf("❌ 获取 TXT 记录失败: %v\n", err)
	} else {
		fmt.Printf("✅ 获取 TXT 记录成功: %s\n", retrievedValue)
		if retrievedValue == testValue {
			fmt.Println("✅ 记录值匹配")
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
	fmt.Println("✅ TXT 记录删除成功")

	fmt.Println("✅ 所有 TXT 记录操作测试完成")
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
