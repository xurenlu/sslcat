package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// 修改后的 GoDaddy 提供商，支持只有 API Key 的情况
type ModifiedGoDaddyProvider struct {
	APIKey    string
	APISecret string
}

func NewModifiedGoDaddyProvider(apiKey, apiSecret string) *ModifiedGoDaddyProvider {
	return &ModifiedGoDaddyProvider{
		APIKey:    apiKey,
		APISecret: apiSecret,
	}
}

func (p *ModifiedGoDaddyProvider) Validate() error {
	if p.APIKey == "" {
		return fmt.Errorf("GoDaddy API key is required")
	}
	// 允许空的 API Secret
	return nil
}

func (p *ModifiedGoDaddyProvider) TestConnection(ctx context.Context) error {
	url := "https://api.godaddy.com/v1/domains"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	// 尝试不同的认证方式
	authHeader := ""
	if p.APISecret != "" {
		authHeader = fmt.Sprintf("sso-key %s:%s", p.APIKey, p.APISecret)
	} else {
		// 如果只有 API Key，尝试不同的格式
		authHeader = fmt.Sprintf("sso-key %s:", p.APIKey)
	}

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GoDaddy API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *ModifiedGoDaddyProvider) GetDomains(ctx context.Context) ([]map[string]interface{}, error) {
	url := "https://api.godaddy.com/v1/domains"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	authHeader := ""
	if p.APISecret != "" {
		authHeader = fmt.Sprintf("sso-key %s:%s", p.APIKey, p.APISecret)
	} else {
		authHeader = fmt.Sprintf("sso-key %s:", p.APIKey)
	}

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GoDaddy API error: %d, body: %s", resp.StatusCode, string(body))
	}

	var domains []map[string]interface{}
	if err := json.Unmarshal(body, &domains); err != nil {
		return nil, err
	}

	return domains, nil
}

func main() {
	fmt.Println("=== 修改版 GoDaddy API 测试 ===")
	fmt.Println("测试支持只有 API Key 的 GoDaddy 提供商")
	fmt.Println("")

	// 你提供的 token
	token := "9ZfgDzGKqGj_6jwuAsdMykaAcZmG3BXT8yKrkG9A5aE2JXtxjWm28rdh"

	// 测试不同的配置
	testConfigs := []struct {
		name      string
		apiKey    string
		apiSecret string
	}{
		{"只有 API Key", token, ""},
		{"API Key + 空 Secret", token, ""},
		{"API Key + 相同 Secret", token, token},
		{"API Key + 占位符 Secret", token, "your_secret"},
	}

	for _, config := range testConfigs {
		fmt.Printf("🔵 测试配置: %s\n", config.name)
		fmt.Printf("   API Key: %s\n", config.apiKey)
		fmt.Printf("   API Secret: %s\n", config.apiSecret)

		provider := NewModifiedGoDaddyProvider(config.apiKey, config.apiSecret)

		// 验证配置
		if err := provider.Validate(); err != nil {
			fmt.Printf("❌ 配置验证失败: %v\n", err)
			continue
		}

		fmt.Printf("✅ 配置验证通过\n")

		// 测试连接
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fmt.Printf("正在测试连接...\n")
		if err := provider.TestConnection(ctx); err != nil {
			fmt.Printf("❌ 连接测试失败: %v\n", err)
			continue
		}

		fmt.Printf("✅ 连接测试成功\n")

		// 测试获取域名
		fmt.Printf("正在获取域名列表...\n")
		domains, err := provider.GetDomains(ctx)
		if err != nil {
			fmt.Printf("❌ 获取域名失败: %v\n", err)
			continue
		}

		fmt.Printf("✅ 成功获取到 %d 个域名\n", len(domains))
		if len(domains) > 0 {
			fmt.Printf("第一个域名: %v\n", domains[0])
		}

		fmt.Println("")
		break // 如果成功，就停止测试其他配置
	}

	fmt.Println("=== 测试完成 ===")
}
