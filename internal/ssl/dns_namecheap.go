package ssl

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NamecheapProvider Namecheap DNS服务商
type NamecheapProvider struct {
	APIKey   string
	APIUser  string
	ClientIP string
	log      Logger
}

// NewNamecheapProvider 创建Namecheap DNS服务商
func NewNamecheapProvider(apiKey, apiUser, clientIP string, log Logger) *NamecheapProvider {
	return &NamecheapProvider{
		APIKey:   apiKey,
		APIUser:  apiUser,
		ClientIP: clientIP,
		log:      log,
	}
}

func (p *NamecheapProvider) GetProviderName() string {
	return "namecheap"
}

func (p *NamecheapProvider) Validate() error {
	if p.APIKey == "" {
		return fmt.Errorf("Namecheap API key is required")
	}
	if p.APIUser == "" {
		return fmt.Errorf("Namecheap API user is required")
	}
	if p.ClientIP == "" {
		return fmt.Errorf("Namecheap client IP is required")
	}
	return nil
}

func (p *NamecheapProvider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	// 分离域名和TLD
	domainParts := strings.Split(domain, ".")
	if len(domainParts) < 2 {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	sld := domainParts[0]
	tld := strings.Join(domainParts[1:], ".")

	// 获取当前所有记录
	records, err := p.getDNSRecords(ctx, sld, tld)
	if err != nil {
		return err
	}

	// 查找是否已存在该TXT记录
	found := false
	for i, record := range records {
		if record.Type == "TXT" && record.Name == name {
			records[i].Address = value
			records[i].TTL = ttl
			found = true
			break
		}
	}

	// 如果不存在，添加新记录
	if !found {
		newRecord := NamecheapDNSRecord{
			Type:    "TXT",
			Name:    name,
			Address: value,
			TTL:     ttl,
		}
		records = append(records, newRecord)
	}

	// 设置所有记录
	return p.setDNSRecords(ctx, sld, tld, records)
}

func (p *NamecheapProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	// 分离域名和TLD
	domainParts := strings.Split(domain, ".")
	if len(domainParts) < 2 {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	sld := domainParts[0]
	tld := strings.Join(domainParts[1:], ".")

	// 获取当前所有记录
	records, err := p.getDNSRecords(ctx, sld, tld)
	if err != nil {
		return err
	}

	// 移除指定的TXT记录
	var filteredRecords []NamecheapDNSRecord
	for _, record := range records {
		if !(record.Type == "TXT" && record.Name == name) {
			filteredRecords = append(filteredRecords, record)
		}
	}

	// 设置过滤后的记录
	return p.setDNSRecords(ctx, sld, tld, filteredRecords)
}

func (p *NamecheapProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	// 分离域名和TLD
	domainParts := strings.Split(domain, ".")
	if len(domainParts) < 2 {
		return "", fmt.Errorf("invalid domain format: %s", domain)
	}

	sld := domainParts[0]
	tld := strings.Join(domainParts[1:], ".")

	// 获取DNS记录
	records, err := p.getDNSRecords(ctx, sld, tld)
	if err != nil {
		return "", err
	}

	// 查找TXT记录
	for _, record := range records {
		if record.Type == "TXT" && record.Name == name {
			return record.Address, nil
		}
	}

	return "", fmt.Errorf("record not found")
}

func (p *NamecheapProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	// Namecheap传播时间较长，等待180秒
	timeout := time.After(180 * time.Second)
	ticker := time.NewTicker(15 * time.Second)
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

func (p *NamecheapProvider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 获取域名列表
	domains, err := p.getDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get domains: %w", err)
	}

	var allDomains []DomainInfo

	// 为每个域名添加信息
	for _, domain := range domains {
		allDomains = append(allDomains, DomainInfo{
			Name:      domain.Name,
			Type:      "domain",
			Status:    "active",
			CreatedAt: domain.Created,
			UpdatedAt: domain.Expires,
			TTL:       600,
			Value:     fmt.Sprintf("%d", domain.ID),
		})

		// 获取域名的 DNS 记录（获取前几条记录作为示例）
		domainParts := strings.Split(domain.Name, ".")
		if len(domainParts) >= 2 {
			sld := domainParts[0]
			tld := strings.Join(domainParts[1:], ".")

			records, err := p.getDNSRecords(ctx, sld, tld)
			if err != nil {
				p.log.Warnf("Failed to get DNS records for domain %s: %v", domain.Name, err)
				continue
			}

			// 只添加前几条记录，避免数据过多
			for i, record := range records {
				if i >= 8 { // 限制每个域名最多显示8条记录
					break
				}

				fullName := record.Name
				if record.Name == "@" {
					fullName = domain.Name
				} else {
					fullName = fmt.Sprintf("%s.%s", record.Name, domain.Name)
				}

				allDomains = append(allDomains, DomainInfo{
					Name:      fullName,
					Type:      record.Type,
					Status:    "active",
					CreatedAt: time.Now(), // Namecheap API不返回创建时间
					UpdatedAt: time.Now(),
					TTL:       record.TTL,
					Value:     record.Address,
				})
			}
		}
	}

	return allDomains, nil
}

// NamecheapDomain Namecheap域名信息
type NamecheapDomain struct {
	ID      int64     `xml:"DomainID,attr"`
	Name    string    `xml:"Name,attr"`
	User    string    `xml:"User,attr"`
	Created time.Time `xml:"Created,attr"`
	Expires time.Time `xml:"Expires,attr"`
}

// NamecheapDNSRecord Namecheap DNS记录
type NamecheapDNSRecord struct {
	Type     string `xml:"Type,attr"`
	Name     string `xml:"Name,attr"`
	Address  string `xml:"Address,attr"`
	MXPref   string `xml:"MXPref,attr"`
	TTL      int    `xml:"TTL,attr"`
	RecordID int    `xml:"RecordID,attr"`
}

// API响应结构
type NamecheapDomainsResponse struct {
	XMLName xml.Name `xml:"ApiResponse"`
	Status  string   `xml:"Status,attr"`
	Errors  []struct {
		Number      string `xml:"Number,attr"`
		Description string `xml:",chardata"`
	} `xml:"Errors>Error"`
	CommandResponse struct {
		DomainGetListResult struct {
			Domains []NamecheapDomain `xml:"Domain"`
		} `xml:"DomainGetListResult"`
	} `xml:"CommandResponse"`
}

type NamecheapDNSResponse struct {
	XMLName xml.Name `xml:"ApiResponse"`
	Status  string   `xml:"Status,attr"`
	Errors  []struct {
		Number      string `xml:"Number,attr"`
		Description string `xml:",chardata"`
	} `xml:"Errors>Error"`
	CommandResponse struct {
		DomainDNSGetHostsResult struct {
			Domain  string               `xml:"Domain,attr"`
			Records []NamecheapDNSRecord `xml:"host"`
		} `xml:"DomainDNSGetHostsResult"`
	} `xml:"CommandResponse"`
}

type NamecheapSetDNSResponse struct {
	XMLName xml.Name `xml:"ApiResponse"`
	Status  string   `xml:"Status,attr"`
	Errors  []struct {
		Number      string `xml:"Number,attr"`
		Description string `xml:",chardata"`
	} `xml:"Errors>Error"`
	CommandResponse struct {
		DomainDNSSetHostsResult struct {
			Domain    string `xml:"Domain,attr"`
			IsSuccess string `xml:"IsSuccess,attr"`
		} `xml:"DomainDNSSetHostsResult"`
	} `xml:"CommandResponse"`
}

func (p *NamecheapProvider) getDomains(ctx context.Context) ([]NamecheapDomain, error) {
	params := url.Values{}
	params.Set("ApiUser", p.APIUser)
	params.Set("ApiKey", p.APIKey)
	params.Set("UserName", p.APIUser)
	params.Set("Command", "namecheap.domains.getList")
	params.Set("ClientIp", p.ClientIP)
	params.Set("PageSize", "100")

	reqURL := "https://api.namecheap.com/xml.response?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

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

	var response NamecheapDomainsResponse
	if err := xml.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	if response.Status != "OK" {
		if len(response.Errors) > 0 {
			return nil, fmt.Errorf("Namecheap API error: %s", response.Errors[0].Description)
		}
		return nil, fmt.Errorf("Namecheap API error: unknown error")
	}

	return response.CommandResponse.DomainGetListResult.Domains, nil
}

func (p *NamecheapProvider) getDNSRecords(ctx context.Context, sld, tld string) ([]NamecheapDNSRecord, error) {
	params := url.Values{}
	params.Set("ApiUser", p.APIUser)
	params.Set("ApiKey", p.APIKey)
	params.Set("UserName", p.APIUser)
	params.Set("Command", "namecheap.domains.dns.getHosts")
	params.Set("ClientIp", p.ClientIP)
	params.Set("SLD", sld)
	params.Set("TLD", tld)

	reqURL := "https://api.namecheap.com/xml.response?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

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

	var response NamecheapDNSResponse
	if err := xml.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	if response.Status != "OK" {
		if len(response.Errors) > 0 {
			return nil, fmt.Errorf("Namecheap API error: %s", response.Errors[0].Description)
		}
		return nil, fmt.Errorf("Namecheap API error: unknown error")
	}

	return response.CommandResponse.DomainDNSGetHostsResult.Records, nil
}

func (p *NamecheapProvider) setDNSRecords(ctx context.Context, sld, tld string, records []NamecheapDNSRecord) error {
	params := url.Values{}
	params.Set("ApiUser", p.APIUser)
	params.Set("ApiKey", p.APIKey)
	params.Set("UserName", p.APIUser)
	params.Set("Command", "namecheap.domains.dns.setHosts")
	params.Set("ClientIp", p.ClientIP)
	params.Set("SLD", sld)
	params.Set("TLD", tld)

	// 添加记录参数
	for i, record := range records {
		index := strconv.Itoa(i + 1)
		params.Set("HostName"+index, record.Name)
		params.Set("RecordType"+index, record.Type)
		params.Set("Address"+index, record.Address)
		params.Set("TTL"+index, strconv.Itoa(record.TTL))

		if record.Type == "MX" && record.MXPref != "" {
			params.Set("MXPref"+index, record.MXPref)
		}
	}

	reqURL := "https://api.namecheap.com/xml.response?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, nil)
	if err != nil {
		return err
	}

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

	var response NamecheapSetDNSResponse
	if err := xml.Unmarshal(body, &response); err != nil {
		return err
	}

	if response.Status != "OK" {
		if len(response.Errors) > 0 {
			return fmt.Errorf("Namecheap API error: %s", response.Errors[0].Description)
		}
		return fmt.Errorf("Namecheap API error: unknown error")
	}

	if response.CommandResponse.DomainDNSSetHostsResult.IsSuccess != "true" {
		return fmt.Errorf("Namecheap API error: failed to set DNS records")
	}

	return nil
}
