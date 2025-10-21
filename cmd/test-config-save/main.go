package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/xurenlu/sslcat/internal/config"
)

func main() {
	var configFile = flag.String("config", "", "配置文件路径")
	var testConfigSave = flag.Bool("test-config-save", false, "测试配置文件保存功能")
	flag.Parse()

	if !*testConfigSave {
		fmt.Println("使用 --test-config-save 参数来测试配置文件保存功能")
		return
	}

	// 创建测试配置
	testConfig := &config.Config{
		Server: config.ServerConfig{
			Host: "0.0.0.0",
			Port: 443,
		},
		Admin: config.AdminConfig{
			Username: "admin",
		},
		SSL: config.SSLConfig{
			Email: "test@example.com",
		},
		Proxy: config.ProxyConfig{
			Rules: []config.ProxyRule{},
		},
	}

	// 测试配置文件保存
	fmt.Printf("🧪 测试配置文件保存到: %s\n", *configFile)

	if err := testConfig.Save(*configFile); err != nil {
		fmt.Printf("❌ 配置文件保存失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ 配置文件保存成功: %s\n", *configFile)

	// 验证文件是否存在
	if _, err := os.Stat(*configFile); err != nil {
		fmt.Printf("❌ 配置文件不存在: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("🎉 配置文件保存测试通过！")
}
