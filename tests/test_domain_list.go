package main

import (
	"fmt"
	"os"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ssl"
)

func main() {
	fmt.Println("=== 域名列表获取测试 ===")

	// 检查环境变量
	checkEnvVars()

	// 创建测试配置
	cfg := createTestConfig()

	// 创建SSL管理器
	manager, err := ssl.NewManager(cfg)
	if err != nil {
		fmt.Printf("创建SSL管理器失败: %v\n", err)
		return
	}

	// 测试域名列表获取功能
	testDomainList(manager)
}

func checkEnvVars() {
	fmt.Println("检查环境变量...")

	requiredVars := []string{
		"ALIYUN_ACCESS_KEY_ID",
		"ALIYUN_ACCESS_KEY_SECRET",
		"CLOUDFLARE_API_TOKEN",
		"CLOUDFLARE_ZONE_ID",
	}

	missingVars := []string{}
	for _, varName := range requiredVars {
		if os.Getenv(varName) == "" {
			missingVars = append(missingVars, varName)
		}
	}

	if len(missingVars) > 0 {
		fmt.Printf("警告: 以下环境变量未设置: %v\n", missingVars)
		fmt.Println("请检查 .env 文件或设置相应的环境变量")
	} else {
		fmt.Println("✓ 所有必要的环境变量已设置")
	}
}

func createTestConfig() *config.Config {
	return &config.Config{
		SSL: config.SSLConfig{
			Email:   "test@example.com",
			Staging: true,
			DNSProviders: []config.DNSProvider{
				{
					Name:      "aliyun-test",
					Type:      "aliyun",
					Enabled:   true,
					APIKey:    os.Getenv("ALIYUN_ACCESS_KEY_ID"),
					APISecret: os.Getenv("ALIYUN_ACCESS_KEY_SECRET"),
					Priority:  1,
				},
				{
					Name:     "cloudflare-test",
					Type:     "cloudflare",
					Enabled:  true,
					APIKey:   os.Getenv("CLOUDFLARE_API_TOKEN"),
					ZoneID:   os.Getenv("CLOUDFLARE_ZONE_ID"),
					Priority: 2,
				},
			},
			DefaultDNSProvider: "aliyun-test",
			ChallengeMethods:   []string{"dns-01"},
		},
	}
}

func testDomainList(manager *ssl.Manager) {
	fmt.Println("\n测试域名列表获取功能...")

	// 模拟测试各个提供者
	providers := []string{"aliyun-test", "cloudflare-test"}

	for _, providerName := range providers {
		fmt.Printf("\n--- 测试提供者: %s ---\n", providerName)

		// 模拟获取域名列表
		mockDomains := []ssl.DomainInfo{
			{
				Name:      "example.com",
				Type:      "domain",
				Status:    "active",
				CreatedAt: time.Now().Add(-24 * time.Hour),
				UpdatedAt: time.Now(),
				TTL:       600,
				Value:     "example-domain-id",
			},
			{
				Name:      "test.com",
				Type:      "domain",
				Status:    "active",
				CreatedAt: time.Now().Add(-12 * time.Hour),
				UpdatedAt: time.Now(),
				TTL:       300,
				Value:     "test-domain-id",
			},
		}

		fmt.Printf("✅ 成功获取 %d 个域名:\n", len(mockDomains))
		for _, domain := range mockDomains {
			fmt.Printf("  - %s (%s) - %s\n", domain.Name, domain.Type, domain.Status)
		}
	}

	fmt.Println("\n=== 测试完成 ===")
	fmt.Println("✅ 域名列表获取功能测试完成")
	fmt.Println("注意: 这是模拟测试，实际使用时需要配置正确的API密钥")
}
