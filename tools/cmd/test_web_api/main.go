package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	fmt.Println("🌐 Web API DNS提供商测试工具")
	fmt.Println("==============================")
	fmt.Println()

	// 默认服务器地址
	serverURL := "http://localhost:9933"
	if len(os.Args) > 1 {
		serverURL = os.Args[1]
	}

	adminPrefix := "/sslcat-panel"
	if len(os.Args) > 2 {
		adminPrefix = os.Args[2]
	}

	apiURL := serverURL + adminPrefix + "/api/dns/providers"
	fmt.Printf("📡 测试API地址: %s\n", apiURL)
	fmt.Println()

	// 发送HTTP请求
	resp, err := http.Get(apiURL)
	if err != nil {
		fmt.Printf("❌ 请求失败: %v\n", err)
		fmt.Println()
		fmt.Println("💡 提示:")
		fmt.Println("   - 确保SSLcat服务器正在运行")
		fmt.Printf("   - 确认服务器地址: %s\n", serverURL)
		fmt.Printf("   - 确认管理面板前缀: %s\n", adminPrefix)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("📊 HTTP状态码: %d\n", resp.StatusCode)

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("❌ 请求失败: %s\n", string(body))
		fmt.Println()
		fmt.Println("💡 可能的原因:")
		fmt.Println("   - 需要先登录管理面板")
		fmt.Println("   - 管理面板前缀不正确")
		fmt.Println("   - 服务器未启动或端口不正确")
		return
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ 读取响应失败: %v\n", err)
		return
	}

	// 解析JSON响应
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Printf("❌ 解析JSON失败: %v\n", err)
		fmt.Printf("原始响应: %s\n", string(body))
		return
	}

	fmt.Println("✅ API响应成功!")
	fmt.Println()

	// 检查configured字段
	if configured, ok := response["configured"]; ok {
		if configuredList, ok := configured.([]interface{}); ok {
			fmt.Printf("📋 已配置的DNS提供商数量: %d\n", len(configuredList))
			fmt.Println()

			for i, provider := range configuredList {
				if providerMap, ok := provider.(map[string]interface{}); ok {
					name := providerMap["name"]
					providerType := providerMap["type"]
					enabled := providerMap["enabled"]
					domains := providerMap["domains"]

					fmt.Printf("🔵 提供商 %d:\n", i+1)
					fmt.Printf("   名称: %v\n", name)
					fmt.Printf("   类型: %v\n", providerType)
					fmt.Printf("   状态: %v\n", enabled)
					fmt.Printf("   域名数量: %v\n", domains)
					fmt.Println()
				}
			}
		}
	}

	// 显示其他信息
	if available, ok := response["available"]; ok {
		if availableList, ok := available.([]interface{}); ok {
			fmt.Printf("📚 可用的DNS提供商类型: %v\n", availableList)
		}
	}

	if defaultProvider, ok := response["default"]; ok {
		fmt.Printf("🎯 默认DNS提供商: %v\n", defaultProvider)
	}

	if methods, ok := response["methods"]; ok {
		fmt.Printf("🔧 支持的验证方式: %v\n", methods)
	}

	fmt.Println()
	fmt.Println("📖 使用说明:")
	fmt.Printf("   %s [服务器地址] [管理前缀]\n", os.Args[0])
	fmt.Println("   例如:")
	fmt.Printf("   %s http://localhost:9933 /sslcat-panel\n", os.Args[0])
}
