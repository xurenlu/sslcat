package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	fmt.Println("=== GoDaddy API Token 测试 ===")
	fmt.Println("测试 GoDaddy API 认证方式")
	fmt.Println("")

	// 你提供的 token
	token := "9ZfgDzGKqGj_6jwuAsdMykaAcZmG3BXT8yKrkG9A5aE2JXtxjWm28rdh"

	// 测试不同的认证方式
	fmt.Println("🔵 测试方式1: 使用 token 作为 API Key，空 Secret")
	testWithTokenAsKey(token, "")

	fmt.Println("")
	fmt.Println("🔵 测试方式2: 使用 token 作为 API Key，token 作为 Secret")
	testWithTokenAsKey(token, token)

	fmt.Println("")
	fmt.Println("🔵 测试方式3: 使用 Bearer token 认证")
	testWithBearerToken(token)

	fmt.Println("")
	fmt.Println("=== 测试完成 ===")
}

func testWithTokenAsKey(apiKey, apiSecret string) {
	fmt.Printf("测试认证方式: sso-key %s:%s\n", apiKey, apiSecret)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 测试获取域名列表
	url := "https://api.godaddy.com/v1/domains"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		fmt.Printf("❌ 创建请求失败: %v\n", err)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", apiKey, apiSecret))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ 请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ 读取响应失败: %v\n", err)
		return
	}

	fmt.Printf("响应状态码: %d\n", resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("✅ 认证成功！\n")
		fmt.Printf("响应内容: %s\n", string(body))
	} else {
		fmt.Printf("❌ 认证失败\n")
		fmt.Printf("错误信息: %s\n", string(body))
	}
}

func testWithBearerToken(token string) {
	fmt.Printf("测试认证方式: Bearer %s\n", token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 测试获取域名列表
	url := "https://api.godaddy.com/v1/domains"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		fmt.Printf("❌ 创建请求失败: %v\n", err)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ 请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ 读取响应失败: %v\n", err)
		return
	}

	fmt.Printf("响应状态码: %d\n", resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		fmt.Printf("✅ 认证成功！\n")
		fmt.Printf("响应内容: %s\n", string(body))
	} else {
		fmt.Printf("❌ 认证失败\n")
		fmt.Printf("错误信息: %s\n", string(body))
	}
}
