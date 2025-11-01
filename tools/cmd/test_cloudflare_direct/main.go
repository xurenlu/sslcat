package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	fmt.Println("=== Cloudflare API 直接测试 ===")
	fmt.Println("直接测试 Cloudflare API 连接和权限")
	fmt.Println("")

	// 获取用户输入
	apiToken := getInput("请输入 Cloudflare API Token: ")
	if apiToken == "" {
		fmt.Println("❌ API Token 不能为空")
		return
	}

	fmt.Println("")
	fmt.Println("🔵 测试 Cloudflare API 连接...")
	testCloudflareAPI(apiToken)
}

func getInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func testCloudflareAPI(apiToken string) {
	// 测试 1: 获取用户信息
	fmt.Println("1. 测试获取用户信息...")
	testUserInfo(apiToken)

	fmt.Println("")

	// 测试 2: 获取 Zone 列表
	fmt.Println("2. 测试获取 Zone 列表...")
	testZones(apiToken)
}

func testUserInfo(apiToken string) {
	url := "https://api.cloudflare.com/client/v4/user"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("❌ 创建请求失败: %v\n", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

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

	if resp.StatusCode == 200 {
		var result struct {
			Success bool `json:"success"`
			Result  struct {
				ID       string `json:"id"`
				Email    string `json:"email"`
				Username string `json:"username"`
			} `json:"result"`
			Errors []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Printf("❌ 解析响应失败: %v\n", err)
			return
		}

		if result.Success {
			fmt.Printf("✅ 用户信息获取成功:\n")
			fmt.Printf("   ID: %s\n", result.Result.ID)
			fmt.Printf("   Email: %s\n", result.Result.Email)
			fmt.Printf("   Username: %s\n", result.Result.Username)
		} else {
			fmt.Printf("❌ API 返回错误: %v\n", result.Errors)
		}
	} else {
		fmt.Printf("❌ API 请求失败 (状态码: %d)\n", resp.StatusCode)
		fmt.Printf("响应内容: %s\n", string(body))
	}
}

func testZones(apiToken string) {
	url := "https://api.cloudflare.com/client/v4/zones"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("❌ 创建请求失败: %v\n", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

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

	if resp.StatusCode == 200 {
		var result struct {
			Success bool `json:"success"`
			Result  []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Status string `json:"status"`
				Paused bool   `json:"paused"`
			} `json:"result"`
			Errors []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}

		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Printf("❌ 解析响应失败: %v\n", err)
			return
		}

		if result.Success {
			fmt.Printf("✅ Zone 列表获取成功，共 %d 个域名:\n", len(result.Result))
			for i, zone := range result.Result {
				if i >= 5 { // 只显示前5个
					fmt.Printf("... 还有 %d 个域名\n", len(result.Result)-5)
					break
				}
				status := "活跃"
				if zone.Paused {
					status = "暂停"
				}
				fmt.Printf("   - %s (ID: %s) - %s\n", zone.Name, zone.ID, status)
			}
		} else {
			fmt.Printf("❌ API 返回错误: %v\n", result.Errors)
		}
	} else {
		fmt.Printf("❌ API 请求失败 (状态码: %d)\n", resp.StatusCode)
		fmt.Printf("响应内容: %s\n", string(body))
	}
}
