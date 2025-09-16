package ssl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CloudflareProvider Cloudflare DNS服务商
type CloudflareProvider struct {
	APIKey string
	ZoneID string
	log    Logger
}

// NewCloudflareProvider 创建Cloudflare DNS服务商
func NewCloudflareProvider(apiKey, zoneID string, log Logger) *CloudflareProvider {
	return &CloudflareProvider{
		APIKey: apiKey,
		ZoneID: zoneID,
		log:    log,
	}
}

func (p *CloudflareProvider) GetProviderName() string {
	return "cloudflare"
}

func (p *CloudflareProvider) Validate() error {
	if p.APIKey == "" {
		return fmt.Errorf("Cloudflare API key is required")
	}
	if p.ZoneID == "" {
		return fmt.Errorf("Cloudflare Zone ID is required")
	}
	return nil
}

func (p *CloudflareProvider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	// 检查记录是否已存在
	existingID, err := p.getRecordID(ctx, name)
	if err != nil {
		return err
	}
	
	if existingID != "" {
		// 更新现有记录
		return p.updateRecord(ctx, existingID, name, value, ttl)
	}
	
	// 创建新记录
	return p.createRecord(ctx, name, value, ttl)
}

func (p *CloudflareProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	recordID, err := p.getRecordID(ctx, name)
	if err != nil {
		return err
	}
	
	if recordID == "" {
		p.log.Debugf("TXT record not found: %s", name)
		return nil
	}
	
	return p.deleteRecord(ctx, recordID)
}

func (p *CloudflareProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	recordID, err := p.getRecordID(ctx, name)
	if err != nil {
		return "", err
	}
	
	if recordID == "" {
		return "", fmt.Errorf("TXT record not found: %s", name)
	}
	
	// 获取记录详情
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", p.ZoneID, recordID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Cloudflare API error: %d", resp.StatusCode)
	}
	
	var result struct {
		Success bool `json:"success"`
		Result  struct {
			Content string `json:"content"`
		} `json:"result"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	if !result.Success {
		return "", fmt.Errorf("Cloudflare API returned success=false")
	}
	
	return result.Result.Content, nil
}

func (p *CloudflareProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	// Cloudflare通常传播很快，等待30秒
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("DNS propagation timeout for %s", name)
		case <-ticker.C:
			recordValue, err := p.GetTXTRecord(ctx, domain, name)
			if err == nil && recordValue == value {
				p.log.Debugf("DNS record propagated: %s = %s", name, value)
				return nil
			}
		}
	}
}

func (p *CloudflareProvider) getRecordID(ctx context.Context, name string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=TXT&name=%s", p.ZoneID, name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Cloudflare API error: %d", resp.StatusCode)
	}
	
	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	if !result.Success {
		return "", fmt.Errorf("Cloudflare API returned success=false")
	}
	
	if len(result.Result) > 0 {
		return result.Result[0].ID, nil
	}
	
	return "", nil
}

func (p *CloudflareProvider) createRecord(ctx context.Context, name, value string, ttl int) error {
	data := map[string]interface{}{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     ttl,
	}
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", p.ZoneID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Cloudflare API error: %d, body: %s", resp.StatusCode, string(body))
	}
	
	var result struct {
		Success bool `json:"success"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	
	if !result.Success {
		return fmt.Errorf("Cloudflare API returned success=false")
	}
	
	return nil
}

func (p *CloudflareProvider) updateRecord(ctx context.Context, recordID, name, value string, ttl int) error {
	data := map[string]interface{}{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     ttl,
	}
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", p.ZoneID, recordID)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Cloudflare API error: %d, body: %s", resp.StatusCode, string(body))
	}
	
	var result struct {
		Success bool `json:"success"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	
	if !result.Success {
		return fmt.Errorf("Cloudflare API returned success=false")
	}
	
	return nil
}

func (p *CloudflareProvider) deleteRecord(ctx context.Context, recordID string) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", p.ZoneID, recordID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Cloudflare API error: %d, body: %s", resp.StatusCode, string(body))
	}
	
	var result struct {
		Success bool `json:"success"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	
	if !result.Success {
		return fmt.Errorf("Cloudflare API returned success=false")
	}
	
	return nil
}

// AliyunProvider 阿里云DNS服务商
type AliyunProvider struct {
	AccessKeyID     string
	AccessKeySecret string
	log             Logger
}

// NewAliyunProvider 创建阿里云DNS服务商
func NewAliyunProvider(accessKeyID, accessKeySecret string, log Logger) *AliyunProvider {
	return &AliyunProvider{
		AccessKeyID:     accessKeyID,
		AccessKeySecret: accessKeySecret,
		log:             log,
	}
}

func (p *AliyunProvider) GetProviderName() string {
	return "aliyun"
}

func (p *AliyunProvider) Validate() error {
	if p.AccessKeyID == "" {
		return fmt.Errorf("Aliyun Access Key ID is required")
	}
	if p.AccessKeySecret == "" {
		return fmt.Errorf("Aliyun Access Key Secret is required")
	}
	return nil
}

func (p *AliyunProvider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	// 阿里云DNS API实现
	// 这里需要实现阿里云DNS API的调用
	// 由于阿里云API比较复杂，这里先返回一个占位实现
	return fmt.Errorf("Aliyun DNS provider not implemented yet")
}

func (p *AliyunProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	return fmt.Errorf("Aliyun DNS provider not implemented yet")
}

func (p *AliyunProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return "", fmt.Errorf("Aliyun DNS provider not implemented yet")
}

func (p *AliyunProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	// 等待60秒
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("DNS propagation timeout for %s", name)
		case <-ticker.C:
			// 这里应该检查DNS记录是否已传播
			// 暂时直接返回成功
			return nil
		}
	}
}

// TencentProvider 腾讯云DNS服务商
type TencentProvider struct {
	SecretID  string
	SecretKey string
	log       Logger
}

// NewTencentProvider 创建腾讯云DNS服务商
func NewTencentProvider(secretID, secretKey string, log Logger) *TencentProvider {
	return &TencentProvider{
		SecretID:  secretID,
		SecretKey: secretKey,
		log:       log,
	}
}

func (p *TencentProvider) GetProviderName() string {
	return "tencent"
}

func (p *TencentProvider) Validate() error {
	if p.SecretID == "" {
		return fmt.Errorf("Tencent Secret ID is required")
	}
	if p.SecretKey == "" {
		return fmt.Errorf("Tencent Secret Key is required")
	}
	return nil
}

func (p *TencentProvider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	return fmt.Errorf("Tencent DNS provider not implemented yet")
}

func (p *TencentProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	return fmt.Errorf("Tencent DNS provider not implemented yet")
}

func (p *TencentProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return "", fmt.Errorf("Tencent DNS provider not implemented yet")
}

func (p *TencentProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	// 等待60秒
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("DNS propagation timeout for %s", name)
		case <-ticker.C:
			return nil
		}
	}
}

// CustomProvider 自定义DNS服务商
type CustomProvider struct {
	Endpoint string
	APIKey   string
	log      Logger
}

// NewCustomProvider 创建自定义DNS服务商
func NewCustomProvider(endpoint, apiKey string, log Logger) *CustomProvider {
	return &CustomProvider{
		Endpoint: endpoint,
		APIKey:   apiKey,
		log:      log,
	}
}

func (p *CustomProvider) GetProviderName() string {
	return "custom"
}

func (p *CustomProvider) Validate() error {
	if p.Endpoint == "" {
		return fmt.Errorf("Custom DNS endpoint is required")
	}
	return nil
}

func (p *CustomProvider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	return fmt.Errorf("Custom DNS provider not implemented yet")
}

func (p *CustomProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	return fmt.Errorf("Custom DNS provider not implemented yet")
}

func (p *CustomProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return "", fmt.Errorf("Custom DNS provider not implemented yet")
}

func (p *CustomProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	// 等待60秒
	timeout := time.After(60 * time.Second)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("DNS propagation timeout for %s", name)
		case <-ticker.C:
			return nil
		}
	}
}
