package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	fmt.Println("=== GoDaddy API 简单连接测试 ===")

	// 测试基本的网络连接
	fmt.Println("🔵 测试网络连接...")
	testBasicConnection()

	fmt.Println("")
	fmt.Println("🔵 测试 GoDaddy API 认证...")
	testGoDaddyAuth()
}

func testBasicConnection() {
	client := &http.Client{Timeout: 10 * time.Second}

	// 测试一个简单的 HTTP 请求
	resp, err := client.Get("https://httpbin.org/get")
	if err != nil {
		fmt.Printf("❌ 网络连接失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("✅ 网络连接正常，状态码: %d\n", resp.StatusCode)
}

func testGoDaddyAuth() {
	// 你提供的 token
	token := "9ZfgDzGKqGj_6jwuAsdMykaAcZmG3BXT8yKrkG9A5aE2JXtxjWm28rdh"

	client := &http.Client{Timeout: 15 * time.Second}

	// 测试 GoDaddy API 连接
	req, err := http.NewRequest("GET", "https://api.godaddy.com/v1/domains", nil)
	if err != nil {
		fmt.Printf("❌ 创建请求失败: %v\n", err)
		return
	}

	// 尝试不同的认证方式
	authMethods := []string{
		fmt.Sprintf("sso-key %s:", token),            // 只有 Key，空 Secret
		fmt.Sprintf("sso-key %s:%s", token, token),   // Key 和 Secret 相同
		fmt.Sprintf("Bearer %s", token),              // Bearer token
		fmt.Sprintf("sso-key %s:your_secret", token), // Key + 占位符 Secret
	}

	for i, auth := range authMethods {
		fmt.Printf("\n测试认证方式 %d: %s\n", i+1, auth)

		req.Header.Set("Authorization", auth)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("❌ 请求失败: %v\n", err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		fmt.Printf("状态码: %d\n", resp.StatusCode)
		if resp.StatusCode == 200 {
			fmt.Printf("✅ 认证成功！\n")
			fmt.Printf("响应: %s\n", string(body))
			break
		} else if resp.StatusCode == 401 {
			fmt.Printf("❌ 认证失败 (401 Unauthorized)\n")
		} else if resp.StatusCode == 403 {
			fmt.Printf("❌ 权限不足 (403 Forbidden)\n")
		} else {
			fmt.Printf("❌ 其他错误: %s\n", string(body))
		}
	}
}
