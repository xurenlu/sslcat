package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func main() {
	fmt.Println("=== DNS 缓存功能测试（带认证）===")
	fmt.Println("测试 DNS 缓存 API 的响应速度和功能")
	fmt.Println("")

	// 测试 API 端点
	baseURL := "http://localhost:9933/sslcat-panel"

	// 首先登录获取认证
	fmt.Println("🔵 步骤 1: 登录获取认证")
	client, err := loginAndGetClient(baseURL)
	if err != nil {
		fmt.Printf("❌ 登录失败: %v\n", err)
		return
	}
	fmt.Println("✅ 登录成功")

	fmt.Println("")

	// 测试 1: 获取 DNS 提供商列表（应该很快，从缓存读取）
	fmt.Println("🔵 测试 1: 获取 DNS 提供商列表（缓存）")
	testDNSProvidersAPI(client, baseURL)

	fmt.Println("")

	// 测试 2: 手动刷新缓存
	fmt.Println("🔵 测试 2: 手动刷新 DNS 缓存")
	testDNSRefreshAPI(client, baseURL)

	fmt.Println("")

	// 测试 3: 再次获取列表（验证缓存更新）
	fmt.Println("🔵 测试 3: 再次获取 DNS 提供商列表（验证缓存更新）")
	testDNSProvidersAPI(client, baseURL)

	fmt.Println("")
	fmt.Println("=== 测试完成 ===")
}

func loginAndGetClient(baseURL string) (*http.Client, error) {
	// 创建客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 登录请求
	loginData := url.Values{}
	loginData.Set("username", "admin")
	loginData.Set("password", "admin") // 使用默认密码

	resp, err := client.PostForm(baseURL+"/login", loginData)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查登录是否成功
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("登录失败，状态码: %d", resp.StatusCode)
	}

	return client, nil
}

func testDNSProvidersAPI(client *http.Client, baseURL string) {
	start := time.Now()

	req, err := http.NewRequest("GET", baseURL+"/api/dns/providers", nil)
	if err != nil {
		fmt.Printf("❌ 创建请求失败: %v\n", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ 请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ 读取响应失败: %v\n", err)
		return
	}

	if resp.StatusCode != 200 {
		fmt.Printf("❌ API 返回错误状态码: %d\n", resp.StatusCode)
		fmt.Printf("响应内容: %s\n", string(body))
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("❌ 解析 JSON 失败: %v\n", err)
		return
	}

	configured, ok := result["configured"].([]interface{})
	if !ok {
		fmt.Printf("❌ 响应格式错误\n")
		return
	}

	fmt.Printf("✅ API 响应时间: %v\n", duration)
	fmt.Printf("✅ 找到 %d 个 DNS 提供商:\n", len(configured))

	for i, provider := range configured {
		if i >= 3 { // 只显示前3个
			fmt.Printf("... 还有 %d 个提供商\n", len(configured)-3)
			break
		}

		if p, ok := provider.(map[string]interface{}); ok {
			name, _ := p["name"].(string)
			enabled, _ := p["enabled"].(bool)
			domains, _ := p["domains"].(float64)
			status := "禁用"
			if enabled {
				status = "启用"
			}
			fmt.Printf("   - %s (%s) - %d 个域名\n", name, status, int(domains))
		}
	}
}

func testDNSRefreshAPI(client *http.Client, baseURL string) {
	start := time.Now()

	req, err := http.NewRequest("POST", baseURL+"/api/dns/refresh", strings.NewReader(""))
	if err != nil {
		fmt.Printf("❌ 创建请求失败: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ 请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ 读取响应失败: %v\n", err)
		return
	}

	if resp.StatusCode != 200 {
		fmt.Printf("❌ API 返回错误状态码: %d\n", resp.StatusCode)
		fmt.Printf("响应内容: %s\n", string(body))
		return
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("❌ 解析 JSON 失败: %v\n", err)
		return
	}

	success, _ := result["success"].(bool)
	message, _ := result["message"].(string)
	providers, _ := result["providers"].([]interface{})

	if success {
		fmt.Printf("✅ 缓存刷新成功 (耗时: %v)\n", duration)
		fmt.Printf("✅ 消息: %s\n", message)
		fmt.Printf("✅ 刷新的提供商: %v\n", providers)
	} else {
		fmt.Printf("❌ 缓存刷新失败\n")
	}
}
