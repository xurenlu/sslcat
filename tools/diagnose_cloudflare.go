package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	fmt.Println("=== Cloudflare DNS 诊断工具 ===")
	fmt.Println("检查 Cloudflare DNS 提供商配置和连接状态")
	fmt.Println("")

	// 1. 检查配置文件
	fmt.Println("🔵 检查配置文件...")
	checkConfigFile()

	fmt.Println("")
	fmt.Println("🔵 检查 Cloudflare API 连接...")
	checkCloudflareAPI()

	fmt.Println("")
	fmt.Println("=== 诊断完成 ===")
}

func checkConfigFile() {
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

	// 查找 Cloudflare 配置
	var cloudflareConfig map[string]interface{}
	for _, provider := range dnsProviders {
		if p, ok := provider.(map[string]interface{}); ok {
			if name, ok := p["name"].(string); ok && name == "cloudflare-dns" {
				cloudflareConfig = p
				break
			}
		}
	}

	if cloudflareConfig == nil {
		fmt.Println("❌ 未找到 Cloudflare DNS 配置")
		return
	}

	fmt.Println("✓ 找到 Cloudflare DNS 配置")

	// 检查各个配置项
	enabled, _ := cloudflareConfig["enabled"].(bool)
	apiKey, _ := cloudflareConfig["api_key"].(string)
	zoneID, _ := cloudflareConfig["zone_id"].(string)

	fmt.Printf("  启用状态: %v\n", enabled)
	fmt.Printf("  API Key: %s\n", maskAPIKey(apiKey))
	fmt.Printf("  Zone ID: %s\n", zoneID)

	if !enabled {
		fmt.Println("❌ Cloudflare DNS 提供商未启用")
		fmt.Println("   解决方案: 在配置文件中设置 \"enabled\": true")
		return
	}

	if apiKey == "YOUR_CLOUDFLARE_API_TOKEN" || apiKey == "" {
		fmt.Println("❌ Cloudflare API Token 未配置")
		fmt.Println("   解决方案: 在配置文件中设置正确的 API Token")
		return
	}

	fmt.Println("✓ Cloudflare DNS 配置看起来正确")
}

func checkCloudflareAPI() {
	// 这里可以添加实际的 API 测试
	fmt.Println("提示: 要测试 Cloudflare API 连接，请运行:")
	fmt.Println("  go run tools/test_cloudflare.go")
}

func maskAPIKey(apiKey string) string {
	if apiKey == "" || apiKey == "YOUR_CLOUDFLARE_API_TOKEN" {
		return apiKey
	}
	if len(apiKey) <= 8 {
		return "***"
	}
	return apiKey[:4] + "***" + apiKey[len(apiKey)-4:]
}
