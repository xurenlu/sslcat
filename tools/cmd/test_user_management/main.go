package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func main() {
	fmt.Println("=== 用户管理功能测试 ===")
	fmt.Println("测试用户管理 API 的功能")
	fmt.Println("")

	// 测试 API 端点
	baseURL := "http://localhost:9933/sslcat-panel"
	
	// 测试 1: 获取用户列表
	fmt.Println("🔵 测试 1: 获取用户列表")
	testGetUsers(baseURL)
	
	fmt.Println("")
	
	// 测试 2: 添加用户
	fmt.Println("🔵 测试 2: 添加用户")
	testAddUser(baseURL)
	
	fmt.Println("")
	fmt.Println("=== 测试完成 ===")
}

func testGetUsers(baseURL string) {
	start := time.Now()
	
	resp, err := http.Get(baseURL + "/api/users")
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
	
	fmt.Printf("响应时间: %v\n", duration)
	fmt.Printf("状态码: %d\n", resp.StatusCode)
	
	if resp.StatusCode == 200 {
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Printf("❌ 解析 JSON 失败: %v\n", err)
			return
		}
		
		users, ok := result["users"].([]interface{})
		if ok {
			fmt.Printf("✅ 成功获取到 %d 个用户:\n", len(users))
			for i, user := range users {
				if i >= 3 { // 只显示前3个
					fmt.Printf("... 还有 %d 个用户\n", len(users)-3)
					break
				}
				
				if u, ok := user.(map[string]interface{}); ok {
					username, _ := u["username"].(string)
					role, _ := u["role"].(string)
					email, _ := u["email"].(string)
					fmt.Printf("   - %s (%s) - %s\n", username, role, email)
				}
			}
		} else {
			fmt.Printf("❌ 响应格式错误\n")
		}
	} else {
		fmt.Printf("❌ API 返回错误状态码: %d\n", resp.StatusCode)
		fmt.Printf("响应内容: %s\n", string(body))
	}
}

func testAddUser(baseURL string) {
	start := time.Now()
	
	userData := map[string]interface{}{
		"username": "testuser",
		"password": "testpass123",
		"role":     "viewer",
		"email":    "test@example.com",
	}
	
	jsonData, err := json.Marshal(userData)
	if err != nil {
		fmt.Printf("❌ 序列化数据失败: %v\n", err)
		return
	}
	
	resp, err := http.Post(baseURL+"/api/users", "application/json", strings.NewReader(string(jsonData)))
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
	
	fmt.Printf("响应时间: %v\n", duration)
	fmt.Printf("状态码: %d\n", resp.StatusCode)
	
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		fmt.Printf("✅ 用户创建成功\n")
	} else {
		fmt.Printf("❌ 用户创建失败，状态码: %d\n", resp.StatusCode)
		fmt.Printf("响应内容: %s\n", string(body))
	}
}
