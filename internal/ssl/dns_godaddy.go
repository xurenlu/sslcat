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

// GoDaddyProvider GoDaddy DNS服务商
type GoDaddyProvider struct {
	APIKey    string
	APISecret string
	log       Logger
}

// NewGoDaddyProvider 创建GoDaddy DNS服务商
func NewGoDaddyProvider(apiKey, apiSecret string, log Logger) *GoDaddyProvider {
	return &GoDaddyProvider{
		APIKey:    apiKey,
		APISecret: apiSecret,
		log:       log,
	}
}

func (p *GoDaddyProvider) GetProviderName() string {
	return "godaddy"
}

func (p *GoDaddyProvider) Validate() error {
	if p.APIKey == "" {
		return fmt.Errorf("GoDaddy API key is required")
	}
	if p.APISecret == "" {
		return fmt.Errorf("GoDaddy API secret is required")
	}
	return nil
}

func (p *GoDaddyProvider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	// 检查记录是否已存在
	existingRecord, err := p.getTXTRecord(ctx, domain, name)
	if err != nil && err.Error() != "record not found" {
		return err
	}

	if existingRecord != "" {
		// 更新现有记录
		return p.updateTXTRecord(ctx, domain, name, value, ttl)
	}

	// 创建新记录
	return p.createTXTRecord(ctx, domain, name, value, ttl)
}

func (p *GoDaddyProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	// GoDaddy删除记录通过PUT空数组实现
	return p.deleteTXTRecord(ctx, domain, name)
}

func (p *GoDaddyProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return p.getTXTRecord(ctx, domain, name)
}

func (p *GoDaddyProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	// GoDaddy传播时间较长，等待120秒
	timeout := time.After(120 * time.Second)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("DNS propagation timeout for %s", name)
		case <-ticker.C:
			recordValue, err := p.getTXTRecord(ctx, domain, name)
			if err == nil && recordValue == value {
				p.log.Debugf("DNS record propagated: %s = %s", name, value)
				return nil
			}
		}
	}
}

func (p *GoDaddyProvider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 获取域名列表
	domains, err := p.getDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get domains: %w", err)
	}

	var allDomains []DomainInfo

	// 为每个域名添加信息
	for _, domain := range domains {
		allDomains = append(allDomains, DomainInfo{
			Name:      domain.Domain,
			Type:      "domain",
			Status:    domain.Status,
			CreatedAt: domain.CreatedAt,
			UpdatedAt: domain.UpdatedAt,
			TTL:       600,
			Value:     fmt.Sprintf("%d", domain.DomainID),
		})

		// 获取域名的 DNS 记录（获取前几条记录作为示例）
		records, err := p.getDNSRecords(ctx, domain.Domain)
		if err != nil {
			p.log.Warnf("Failed to get DNS records for domain %s: %v", domain.Domain, err)
			continue
		}

		// 只添加前几条记录，避免数据过多
		for i, record := range records {
			if i >= 10 { // 限制每个域名最多显示10条记录
				break
			}

			fullName := record.Name
			if record.Name == "@" {
				fullName = domain.Domain
			} else {
				fullName = fmt.Sprintf("%s.%s", record.Name, domain.Domain)
			}

			allDomains = append(allDomains, DomainInfo{
				Name:      fullName,
				Type:      record.Type,
				Status:    "active",
				CreatedAt: time.Now(), // GoDaddy API不返回创建时间
				UpdatedAt: time.Now(),
				TTL:       record.TTL,
				Value:     record.Data,
			})
		}
	}

	return allDomains, nil
}

// GoDaddyDomain GoDaddy域名信息
type GoDaddyDomain struct {
	DomainID  int64     `json:"domainId"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"modifiedAt"`
}

// GoDaddyDNSRecord GoDaddy DNS记录
type GoDaddyDNSRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
	TTL  int    `json:"ttl"`
}

func (p *GoDaddyProvider) getDomains(ctx context.Context) ([]GoDaddyDomain, error) {
	url := "https://api.godaddy.com/v1/domains"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", p.APIKey, p.APISecret))
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

	var domains []GoDaddyDomain
	if err := json.Unmarshal(body, &domains); err != nil {
		return nil, err
	}

	return domains, nil
}

func (p *GoDaddyProvider) getDNSRecords(ctx context.Context, domain string) ([]GoDaddyDNSRecord, error) {
	url := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", p.APIKey, p.APISecret))
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

	var records []GoDaddyDNSRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, err
	}

	return records, nil
}

func (p *GoDaddyProvider) getTXTRecord(ctx context.Context, domain, name string) (string, error) {
	url := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records/TXT/%s", domain, name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", p.APIKey, p.APISecret))
	req.Header.Set("Accept", "application/json")

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

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("record not found")
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GoDaddy API error: %d, body: %s", resp.StatusCode, string(body))
	}

	var records []GoDaddyDNSRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return "", err
	}

	if len(records) > 0 {
		return records[0].Data, nil
	}

	return "", fmt.Errorf("record not found")
}

func (p *GoDaddyProvider) createTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	url := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records", domain)

	record := []GoDaddyDNSRecord{
		{
			Type: "TXT",
			Name: name,
			Data: value,
			TTL:  ttl,
		},
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", p.APIKey, p.APISecret))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GoDaddy API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *GoDaddyProvider) updateTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	// GoDaddy的更新和创建使用相同的API
	return p.createTXTRecord(ctx, domain, name, value, ttl)
}

func (p *GoDaddyProvider) deleteTXTRecord(ctx context.Context, domain, name string) error {
	url := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records/TXT/%s", domain, name)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", p.APIKey, p.APISecret))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GoDaddy API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}
