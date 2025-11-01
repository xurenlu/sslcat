package main

import (
	"context"
	"fmt"
	"os"
	"time"

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
	fmt.Println("🌐 Cloudflare自动Zone ID测试工具")
	fmt.Println("==================================")
	fmt.Println()

	if len(os.Args) < 2 {
		fmt.Println("使用方法: go run test_cloudflare_auto.go <API_TOKEN>")
		fmt.Println("例如: go run test_cloudflare_auto.go your_api_token")
		return
	}

	apiToken := os.Args[1]
	log := &SimpleLogger{}

	// 创建Cloudflare提供商（不指定Zone ID）
	provider := ssl.NewCloudflareProvider(apiToken, "", log)

	fmt.Println("🔑 验证API Token...")
	if err := provider.Validate(); err != nil {
		fmt.Printf("❌ API Token验证失败: %v\n", err)
		return
	}
	fmt.Println("✅ API Token验证成功")

	fmt.Println()
	fmt.Println("🌐 获取所有域名和Zone ID...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	domains, err := provider.ListDomains(ctx)
	if err != nil {
		fmt.Printf("❌ 获取域名列表失败: %v\n", err)
		return
	}

	fmt.Printf("✅ 成功获取到 %d 个域名:\n", len(domains))
	fmt.Println()

	for i, domain := range domains {
		fmt.Printf("🔵 域名 %d:\n", i+1)
		fmt.Printf("   域名: %s\n", domain.Name)
		fmt.Printf("   Zone ID: %s\n", domain.Value)
		fmt.Printf("   状态: %s\n", domain.Status)
		fmt.Printf("   创建时间: %s\n", domain.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println()
	}

	if len(domains) == 0 {
		fmt.Println("⚠️  未找到任何域名")
		fmt.Println("💡 可能的原因:")
		fmt.Println("   - API Token权限不足")
		fmt.Println("   - 账户中没有添加域名")
		fmt.Println("   - API Token配置错误")
	} else {
		fmt.Println("🎉 Cloudflare自动Zone ID功能工作正常！")
		fmt.Println()
		fmt.Println("📋 配置说明:")
		fmt.Println("   - 在SSLcat配置中，将zone_id设置为空字符串")
		fmt.Println("   - 系统会自动根据域名查找对应的Zone ID")
		fmt.Println("   - 支持管理多个域名，无需手动配置Zone ID")
	}
}



