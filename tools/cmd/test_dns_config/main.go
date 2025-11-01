package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ssl"
)

// SimpleLogger 简单的日志记录器实现
type SimpleLogger struct{}

func (l *SimpleLogger) Debugf(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}

func (l *SimpleLogger) Infof(format string, args ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func (l *SimpleLogger) Warnf(format string, args ...interface{}) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func (l *SimpleLogger) Errorf(format string, args ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}

func main() {
	fmt.Println("🔧 DNS提供商配置测试工具")
	fmt.Println("================================")
	fmt.Println()

	// 加载配置
	configPath := "./data/sslcat.conf"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	fmt.Printf("📁 加载配置文件: %s\n", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("❌ 配置文件加载失败: %v\n", err)
		return
	}

	// 创建日志记录器
	log := &SimpleLogger{}

	fmt.Println()
	fmt.Println("🔍 检查DNS提供商配置...")
	fmt.Println()

	// 检查每个DNS提供商
	for _, provider := range cfg.SSL.DNSProviders {
		fmt.Printf("🔵 检查 %s (%s)\n", provider.Name, provider.Type)
		fmt.Printf("   启用状态: %v\n", provider.Enabled)

		if !provider.Enabled {
			fmt.Printf("   ⚠️  提供商未启用，跳过测试\n")
			fmt.Println()
			continue
		}

		// 检查API密钥配置
		if provider.APIKey == "" || provider.APIKey == "YOUR_CLOUDFLARE_API_TOKEN" ||
			provider.APIKey == "YOUR_TENCENT_SECRET_ID" || provider.APIKey == "YOUR_GODADDY_API_KEY" ||
			provider.APIKey == "YOUR_NAMECHEAP_API_KEY" {
			fmt.Printf("   ❌ API密钥未配置或为默认值\n")
			fmt.Println()
			continue
		}

		// 创建DNS提供商实例
		var dnsProvider ssl.DNSProviderInterface
		switch provider.Type {
		case "aliyun":
			dnsProvider = ssl.NewAliyunProvider(provider.APIKey, provider.APISecret, log)
		case "cloudflare":
			dnsProvider = ssl.NewCloudflareProvider(provider.APIKey, provider.ZoneID, log)
		case "tencent":
			dnsProvider = ssl.NewTencentProvider(provider.APIKey, provider.APISecret, log)
		default:
			fmt.Printf("   ⚠️  暂不支持测试 %s 类型的提供商\n", provider.Type)
			fmt.Println()
			continue
		}

		// 验证配置
		fmt.Printf("   🔑 验证API密钥配置...")
		if err := dnsProvider.Validate(); err != nil {
			fmt.Printf(" ❌\n")
			fmt.Printf("   错误: %v\n", err)
			fmt.Println()
			continue
		}
		fmt.Printf(" ✅\n")

		// 测试连接和获取域名列表
		fmt.Printf("   🌐 测试连接并获取域名列表...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		domains, err := dnsProvider.ListDomains(ctx)
		cancel()

		if err != nil {
			fmt.Printf(" ❌\n")
			fmt.Printf("   错误: %v\n", err)

			// 提供一些调试建议
			switch provider.Type {
			case "aliyun":
				fmt.Printf("   💡 调试建议:\n")
				fmt.Printf("      - 确认AccessKey ID和AccessKey Secret是否正确\n")
				fmt.Printf("      - 检查账户是否有域名解析服务权限\n")
				fmt.Printf("      - 确认账户中是否有已添加的域名\n")
			case "cloudflare":
				fmt.Printf("   💡 调试建议:\n")
				fmt.Printf("      - 确认API Token是否正确且有足够权限\n")
				fmt.Printf("      - 检查Zone ID是否正确\n")
				fmt.Printf("      - 确认账户中是否有活跃域名\n")
			}
		} else {
			fmt.Printf(" ✅\n")
			fmt.Printf("   🎉 成功获取到 %d 个域名:\n", len(domains))

			if len(domains) == 0 {
				fmt.Printf("      ⚠️  域名列表为空，请检查:\n")
				switch provider.Type {
				case "aliyun":
					fmt.Printf("         - 阿里云控制台是否已添加域名到云解析DNS\n")
					fmt.Printf("         - AccessKey是否有云解析DNS权限\n")
				case "cloudflare":
					fmt.Printf("         - Cloudflare账户是否已添加域名\n")
					fmt.Printf("         - API Token权限是否包括Zone:Read\n")
				}
			} else {
				for i, domain := range domains {
					if i < 5 { // 只显示前5个域名
						fmt.Printf("      - %s\n", domain.Name)
					} else if i == 5 {
						fmt.Printf("      - ... (还有 %d 个域名)\n", len(domains)-5)
						break
					}
				}
			}
		}
		fmt.Println()
	}

	fmt.Println("🏁 测试完成!")
	fmt.Println()
	fmt.Println("📝 配置说明:")
	fmt.Println("  - 阿里云DNS: 需要AccessKey ID和AccessKey Secret")
	fmt.Println("  - Cloudflare: 需要API Token和Zone ID")
	fmt.Println("  - 腾讯云DNS: 需要Secret ID和Secret Key")
	fmt.Println()
	fmt.Println("🔗 获取API密钥:")
	fmt.Println("  - 阿里云: https://ram.console.aliyun.com/manage/ak")
	fmt.Println("  - Cloudflare: https://dash.cloudflare.com/profile/api-tokens")
	fmt.Println("  - 腾讯云: https://console.cloud.tencent.com/cam/capi")
}
