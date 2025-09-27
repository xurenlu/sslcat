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
	// Zone ID可以为空，这样会获取所有Zone
	return nil
}

func (p *CloudflareProvider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	// 如果Zone ID为空，根据域名自动查找Zone ID
	zoneID := p.ZoneID
	if zoneID == "" || zoneID == "YOUR_CLOUDFLARE_ZONE_ID" {
		var err error
		zoneID, err = p.findZoneIDByDomain(ctx, domain)
		if err != nil {
			return fmt.Errorf("failed to find zone ID for domain %s: %w", domain, err)
		}
	}

	// 临时设置Zone ID
	originalZoneID := p.ZoneID
	p.ZoneID = zoneID
	defer func() { p.ZoneID = originalZoneID }()

	// 检查记录是否已存在
	existingID, err := p.getRecordID(ctx, name)
	if err != nil && err.Error() != "record not found" {
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
	// 如果Zone ID为空，根据域名自动查找Zone ID
	zoneID := p.ZoneID
	if zoneID == "" || zoneID == "YOUR_CLOUDFLARE_ZONE_ID" {
		var err error
		zoneID, err = p.findZoneIDByDomain(ctx, domain)
		if err != nil {
			return fmt.Errorf("failed to find zone ID for domain %s: %w", domain, err)
		}
	}

	// 临时设置Zone ID
	originalZoneID := p.ZoneID
	p.ZoneID = zoneID
	defer func() { p.ZoneID = originalZoneID }()

	recordID, err := p.getRecordID(ctx, name)
	if err != nil {
		if err.Error() == "record not found" {
			p.log.Debugf("TXT record not found: %s", name)
			return nil
		}
		return err
	}

	return p.deleteRecord(ctx, recordID)
}

func (p *CloudflareProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return p.getTXTRecord(ctx, name)
}

func (p *CloudflareProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	// Cloudflare传播通常很快，等待30秒
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("DNS propagation timeout for %s", name)
		case <-ticker.C:
			recordValue, err := p.getTXTRecord(ctx, name)
			if err == nil && recordValue == value {
				p.log.Debugf("DNS record propagated: %s = %s", name, value)
				return nil
			}
		}
	}
}

func (p *CloudflareProvider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 如果指定了Zone ID，只获取该Zone的信息
	if p.ZoneID != "" && p.ZoneID != "YOUR_CLOUDFLARE_ZONE_ID" {
		return p.listSingleZone(ctx)
	}

	// 否则获取所有Zone
	return p.listAllZones(ctx)
}

// listSingleZone 获取单个Zone的信息
func (p *CloudflareProvider) listSingleZone(ctx context.Context) ([]DomainInfo, error) {
	// 获取区域信息
	zoneInfo, err := p.getZoneInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone info: %w", err)
	}

	var allDomains []DomainInfo

	// 添加区域域名
	allDomains = append(allDomains, DomainInfo{
		Name:      zoneInfo.Name,
		Type:      "domain",
		Status:    zoneInfo.Status,
		CreatedAt: zoneInfo.CreatedAt,
		UpdatedAt: zoneInfo.UpdatedAt,
		TTL:       600,
		Value:     zoneInfo.ID,
	})

	// 获取DNS记录
	records, err := p.getDNSRecords(ctx)
	if err != nil {
		p.log.Warnf("Failed to get DNS records: %v", err)
		return allDomains, nil
	}

	// 添加DNS记录（限制数量）
	for i, record := range records {
		if i >= 20 { // 限制最多显示20条记录
			break
		}

		fullName := record.Name
		if record.Name == zoneInfo.Name {
			fullName = record.Name
		}

		allDomains = append(allDomains, DomainInfo{
			Name:      fullName,
			Type:      record.Type,
			Status:    "active",
			CreatedAt: record.CreatedAt,
			UpdatedAt: record.UpdatedAt,
			TTL:       record.TTL,
			Value:     record.Content,
		})
	}

	return allDomains, nil
}

// listAllZones 获取所有Zone的信息
func (p *CloudflareProvider) listAllZones(ctx context.Context) ([]DomainInfo, error) {
	// 获取所有Zone
	zones, err := p.getAllZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get all zones: %w", err)
	}

	var allDomains []DomainInfo

	// 为每个Zone添加域名信息
	for _, zone := range zones {
		allDomains = append(allDomains, DomainInfo{
			Name:      zone.Name,
			Type:      "domain",
			Status:    zone.Status,
			CreatedAt: zone.CreatedAt,
			UpdatedAt: zone.UpdatedAt,
			TTL:       600,
			Value:     zone.ID, // Zone ID作为Value
		})
	}

	return allDomains, nil
}

// CloudflareZone Cloudflare区域信息
type CloudflareZone struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_on"`
	UpdatedAt time.Time `json:"modified_on"`
}

// CloudflareDNSRecord Cloudflare DNS记录
type CloudflareDNSRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Content   string    `json:"content"`
	TTL       int       `json:"ttl"`
	CreatedAt time.Time `json:"created_on"`
	UpdatedAt time.Time `json:"modified_on"`
}

func (p *CloudflareProvider) getZoneInfo(ctx context.Context) (*CloudflareZone, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s", p.ZoneID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

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

	var result struct {
		Success bool           `json:"success"`
		Result  CloudflareZone `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("Cloudflare API error: %s", result.Errors[0].Message)
		}
		return nil, fmt.Errorf("Cloudflare API returned success=false")
	}

	return &result.Result, nil
}

func (p *CloudflareProvider) getDNSRecords(ctx context.Context) ([]CloudflareDNSRecord, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?per_page=100", p.ZoneID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

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

	var result struct {
		Success bool                  `json:"success"`
		Result  []CloudflareDNSRecord `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("Cloudflare API error: %s", result.Errors[0].Message)
		}
		return nil, fmt.Errorf("Cloudflare API returned success=false")
	}

	return result.Result, nil
}

func (p *CloudflareProvider) getRecordID(ctx context.Context, name string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&type=TXT", p.ZoneID, name)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Success bool                  `json:"success"`
		Result  []CloudflareDNSRecord `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return "", fmt.Errorf("Cloudflare API error: %s", result.Errors[0].Message)
		}
		return "", fmt.Errorf("Cloudflare API returned success=false")
	}

	if len(result.Result) > 0 {
		return result.Result[0].ID, nil
	}

	return "", fmt.Errorf("record not found")
}

func (p *CloudflareProvider) getTXTRecord(ctx context.Context, name string) (string, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&type=TXT", p.ZoneID, name)
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Success bool                  `json:"success"`
		Result  []CloudflareDNSRecord `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return "", fmt.Errorf("Cloudflare API error: %s", result.Errors[0].Message)
		}
		return "", fmt.Errorf("Cloudflare API returned success=false")
	}

	if len(result.Result) > 0 {
		return result.Result[0].Content, nil
	}

	return "", fmt.Errorf("record not found")
}

func (p *CloudflareProvider) createRecord(ctx context.Context, name, value string, ttl int) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", p.ZoneID)

	record := map[string]interface{}{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     ttl,
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		return err
	}

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Cloudflare API error: %d, body: %s", resp.StatusCode, string(body))
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return fmt.Errorf("Cloudflare API error: %s", result.Errors[0].Message)
		}
		return fmt.Errorf("Cloudflare API returned success=false")
	}

	return nil
}

func (p *CloudflareProvider) updateRecord(ctx context.Context, recordID, name, value string, ttl int) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", p.ZoneID, recordID)

	record := map[string]interface{}{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     ttl,
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		return err
	}

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Cloudflare API error: %d, body: %s", resp.StatusCode, string(body))
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return fmt.Errorf("Cloudflare API error: %s", result.Errors[0].Message)
		}
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Cloudflare API error: %d, body: %s", resp.StatusCode, string(body))
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return fmt.Errorf("Cloudflare API error: %s", result.Errors[0].Message)
		}
		return fmt.Errorf("Cloudflare API returned success=false")
	}

	return nil
}

// getAllZones 获取所有Zone
func (p *CloudflareProvider) getAllZones(ctx context.Context) ([]CloudflareZone, error) {
	url := "https://api.cloudflare.com/client/v4/zones"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")

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

	var result struct {
		Success bool             `json:"success"`
		Result  []CloudflareZone `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("Cloudflare API error: %s", result.Errors[0].Message)
		}
		return nil, fmt.Errorf("Cloudflare API returned success=false")
	}

	return result.Result, nil
}

// findZoneIDByDomain 根据域名查找Zone ID
func (p *CloudflareProvider) findZoneIDByDomain(ctx context.Context, domain string) (string, error) {
	zones, err := p.getAllZones(ctx)
	if err != nil {
		return "", err
	}

	// 查找匹配的域名
	for _, zone := range zones {
		if zone.Name == domain {
			return zone.ID, nil
		}
	}

	return "", fmt.Errorf("zone not found for domain: %s", domain)
}
