package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/ssl"
)

func main() {
	fmt.Println("=== DNS 提供商诊断工具 ===")
	fmt.Println("检查所有 DNS 提供商的配置和域名获取情况")
	fmt.Println("")

	// 读取配置文件
	configFile := "data/sslcat.conf"
	content, err := os.ReadFile(configFile)
	if err != nil {
		fmt.Printf("❌ 无法读取配置文件: %v\n", err)
		return
	}

	var config map[string]interface{}
	if err := json.Unmarshal(content, &config); err != nil {
		fmt.Printf("❌ 配置文件格式错误: %v\n", err)
		return
	}

	// 检查 SSL 配置
	ssl, ok := config["ssl"].(map[string]interface{})
	if !ok {
		fmt.Println("❌ 配置文件中没有 SSL 配置")
		return
	}

	// 检查 DNS 提供商配置
	dnsProviders, ok := ssl["dns_providers"].([]interface{})
	if !ok {
		fmt.Println("❌ 配置文件中没有 DNS 提供商配置")
		return
	}

	fmt.Printf("✓ 找到 %d 个 DNS 提供商配置\n", len(dnsProviders))
	fmt.Println("")

	// 创建日志记录器
	logger := &SimpleLogger{}

	// 检查每个提供商
	for i, providerInterface := range dnsProviders {
		provider, ok := providerInterface.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := provider["name"].(string)
		providerType, _ := provider["type"].(string)
		enabled, _ := provider["enabled"].(bool)
		apiKey, _ := provider["api_key"].(string)
		apiSecret, _ := provider["api_secret"].(string)
		zoneID, _ := provider["zone_id"].(string)

		fmt.Printf("🔵 检查提供商 %d: %s (%s)\n", i+1, name, providerType)
		fmt.Printf("   启用状态: %v\n", enabled)
		fmt.Printf("   API Key: %s\n", maskAPIKey(apiKey))
		fmt.Printf("   API Secret: %s\n", maskAPIKey(apiSecret))
		fmt.Printf("   Zone ID: %s\n", zoneID)

		if !enabled {
			fmt.Printf("   ❌ 提供商未启用\n")
			fmt.Println("")
			continue
		}

		// 检查 API 凭据
		if apiKey == "" || apiKey == "YOUR_"+strings.ToUpper(providerType)+"_API_KEY" {
			fmt.Printf("   ❌ API Key 未配置或使用默认值\n")
			fmt.Println("")
			continue
		}

		// 测试提供商
		fmt.Printf("   正在测试提供商...\n")
		testProvider(name, providerType, apiKey, apiSecret, zoneID, logger)
		fmt.Println("")
	}

	fmt.Println("=== 诊断完成 ===")
}

func testProvider(name, providerType, apiKey, apiSecret, zoneID string, logger *SimpleLogger) {
	// 创建提供商实例
	var provider ssl.DNSProviderInterface
	var err error

	switch providerType {
	case "cloudflare":
		provider = ssl.NewCloudflareProvider(apiKey, zoneID, logger)
	case "aliyun":
		provider = ssl.NewAliyunProvider(apiKey, apiSecret, logger)
	case "tencent":
		provider = ssl.NewTencentProvider(apiKey, apiSecret, logger)
	case "godaddy":
		provider = ssl.NewGoDaddyProvider(apiKey, apiSecret, logger)
	case "namecheap":
		provider = ssl.NewNamecheapProvider(apiKey, apiSecret, zoneID, logger)
	case "aws":
		provider = ssl.NewAWSRoute53Provider(apiKey, apiSecret, "us-east-1", logger)
	case "custom":
		provider = ssl.NewCustomProvider(zoneID, apiKey, logger)
	default:
		fmt.Printf("   ❌ 不支持的提供商类型: %s\n", providerType)
		return
	}

	// 验证配置
	if err := provider.Validate(); err != nil {
		fmt.Printf("   ❌ 配置验证失败: %v\n", err)
		return
	}

	fmt.Printf("   ✓ 配置验证通过\n")

	// 测试获取域名列表
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	domains, err := provider.ListDomains(ctx)
	if err != nil {
		fmt.Printf("   ❌ 获取域名列表失败: %v\n", err)
		return
	}

	fmt.Printf("   ✅ 成功获取到 %d 个域名/DNS记录\n", len(domains))

	if len(domains) > 0 {
		fmt.Printf("   前几个域名:\n")
		for i, domain := range domains {
			if i >= 3 { // 只显示前3个
				fmt.Printf("   ... 还有 %d 个记录\n", len(domains)-3)
				break
			}
			fmt.Printf("     - %s (%s) - %s\n", domain.Name, domain.Type, domain.Status)
		}
	}
}

func maskAPIKey(apiKey string) string {
	if apiKey == "" {
		return "未设置"
	}
	if len(apiKey) <= 8 {
		return "***"
	}
	return apiKey[:4] + "***" + apiKey[len(apiKey)-4:]
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
