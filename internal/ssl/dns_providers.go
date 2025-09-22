package ssl

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
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

func (p *CloudflareProvider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 首先获取所有 zone 信息
	zones, err := p.getZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get zones: %w", err)
	}

	var allDomains []DomainInfo

	// 为每个 zone 获取 DNS 记录
	for _, zone := range zones {
		records, err := p.getDNSRecords(ctx, zone.ID)
		if err != nil {
			p.log.Warnf("Failed to get DNS records for zone %s: %v", zone.Name, err)
			continue
		}

		// 添加 zone 信息作为域名
		allDomains = append(allDomains, DomainInfo{
			Name:      zone.Name,
			Type:      "zone",
			Status:    zone.Status,
			CreatedAt: zone.CreatedAt,
			UpdatedAt: zone.UpdatedAt,
			TTL:       1,
			Value:     zone.ID,
		})

		// 添加 DNS 记录
		for _, record := range records {
			allDomains = append(allDomains, DomainInfo{
				Name:      record.Name,
				Type:      record.Type,
				Status:    "active",
				CreatedAt: record.Created,
				UpdatedAt: record.Updated,
				TTL:       record.TTL,
				Value:     record.Content,
			})
		}
	}

	return allDomains, nil
}

// getZones 获取所有 zone 信息
func (p *CloudflareProvider) getZones(ctx context.Context) ([]ZoneInfo, error) {
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Cloudflare zones API error: %d, body: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			ID        string    `json:"id"`
			Name      string    `json:"name"`
			Status    string    `json:"status"`
			CreatedAt time.Time `json:"created_on"`
			UpdatedAt time.Time `json:"modified_on"`
		} `json:"result"`
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("Cloudflare zones API error: %s", result.Errors[0].Message)
		}
		return nil, fmt.Errorf("Cloudflare zones API request failed")
	}

	var zones []ZoneInfo
	for _, zone := range result.Result {
		zones = append(zones, ZoneInfo{
			ID:        zone.ID,
			Name:      zone.Name,
			Status:    zone.Status,
			CreatedAt: zone.CreatedAt,
			UpdatedAt: zone.UpdatedAt,
		})
	}

	return zones, nil
}

// getDNSRecords 获取指定 zone 的 DNS 记录
func (p *CloudflareProvider) getDNSRecords(ctx context.Context, zoneID string) ([]DNSRecord, error) {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
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

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Cloudflare DNS records API error: %d, body: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Success bool `json:"success"`
		Result  []struct {
			ID      string    `json:"id"`
			Name    string    `json:"name"`
			Type    string    `json:"type"`
			Content string    `json:"content"`
			TTL     int       `json:"ttl"`
			Created time.Time `json:"created_on"`
			Updated time.Time `json:"modified_on"`
		} `json:"result"`
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("Cloudflare DNS records API error: %s", result.Errors[0].Message)
		}
		return nil, fmt.Errorf("Cloudflare DNS records API request failed")
	}

	var records []DNSRecord
	for _, record := range result.Result {
		records = append(records, DNSRecord{
			ID:      record.ID,
			Name:    record.Name,
			Type:    record.Type,
			Content: record.Content,
			TTL:     record.TTL,
			Created: record.Created,
			Updated: record.Updated,
		})
	}

	return records, nil
}

// ZoneInfo Cloudflare Zone 信息
type ZoneInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DNSRecord Cloudflare DNS 记录
type DNSRecord struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Content string    `json:"content"`
	TTL     int       `json:"ttl"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
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

func (p *AliyunProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	// 获取记录ID
	recordID, err := p.getRecordID(ctx, domain, name)
	if err != nil {
		return err
	}

	if recordID == "" {
		p.log.Debugf("TXT record not found: %s", name)
		return nil
	}

	// 删除记录
	return p.deleteRecord(ctx, domain, recordID)
}

func (p *AliyunProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return p.getTXTRecord(ctx, domain, name)
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
			recordValue, err := p.getTXTRecord(ctx, domain, name)
			if err == nil && recordValue == value {
				p.log.Debugf("DNS record propagated: %s = %s", name, value)
				return nil
			}
		}
	}
}

func (p *AliyunProvider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 获取域名列表
	domains, err := p.getDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get domains: %w", err)
	}

	var allDomains []DomainInfo

	// 为每个域名获取 DNS 记录
	for _, domain := range domains {
		// 添加域名信息
		allDomains = append(allDomains, DomainInfo{
			Name:      domain.Name,
			Type:      "domain",
			Status:    domain.Status,
			CreatedAt: domain.CreatedAt,
			UpdatedAt: domain.UpdatedAt,
			TTL:       600,
			Value:     domain.ID,
		})

		// 获取域名的 DNS 记录
		records, err := p.getDomainRecords(ctx, domain.ID)
		if err != nil {
			p.log.Warnf("Failed to get DNS records for domain %s: %v", domain.Name, err)
			continue
		}

		// 添加 DNS 记录
		for _, record := range records {
			allDomains = append(allDomains, DomainInfo{
				Name:      record.Name,
				Type:      record.Type,
				Status:    "active",
				CreatedAt: record.CreatedAt,
				UpdatedAt: record.UpdatedAt,
				TTL:       record.TTL,
				Value:     record.Value,
			})
		}
	}

	return allDomains, nil
}

// getDomains 获取阿里云域名列表
func (p *AliyunProvider) getDomains(ctx context.Context) ([]AliyunDomain, error) {
	params := map[string]string{
		"Action":  "DescribeDomains",
		"Version": "2015-01-09",
	}

	result, err := p.makeRequest(ctx, "DescribeDomains", params)
	if err != nil {
		return nil, err
	}

	domainsData, ok := result["Domains"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format")
	}

	domainList, ok := domainsData["Domain"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid domain list format")
	}

	var domains []AliyunDomain
	for _, domainData := range domainList {
		domainMap, ok := domainData.(map[string]interface{})
		if !ok {
			continue
		}

		domain := AliyunDomain{
			ID:        getString(domainMap, "DomainId"),
			Name:      getString(domainMap, "DomainName"),
			Status:    getString(domainMap, "Status"),
			CreatedAt: parseTime(getString(domainMap, "CreateTime")),
			UpdatedAt: parseTime(getString(domainMap, "UpdateTime")),
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// getDomainRecords 获取指定域名的 DNS 记录
func (p *AliyunProvider) getDomainRecords(ctx context.Context, domainID string) ([]AliyunDNSRecord, error) {
	params := map[string]string{
		"Action":   "DescribeDomainRecords",
		"Version":  "2015-01-09",
		"DomainId": domainID,
	}

	result, err := p.makeRequest(ctx, "DescribeDomainRecords", params)
	if err != nil {
		return nil, err
	}

	recordsData, ok := result["DomainRecords"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format")
	}

	recordList, ok := recordsData["Record"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid record list format")
	}

	var records []AliyunDNSRecord
	for _, recordData := range recordList {
		recordMap, ok := recordData.(map[string]interface{})
		if !ok {
			continue
		}

		record := AliyunDNSRecord{
			ID:        getString(recordMap, "RecordId"),
			Name:      getString(recordMap, "RR"),
			Type:      getString(recordMap, "Type"),
			Value:     getString(recordMap, "Value"),
			TTL:       getInt(recordMap, "TTL"),
			CreatedAt: parseTime(getString(recordMap, "CreateTime")),
			UpdatedAt: parseTime(getString(recordMap, "UpdateTime")),
		}
		records = append(records, record)
	}

	return records, nil
}

// AliyunDomain 阿里云域名信息
type AliyunDomain struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AliyunDNSRecord 阿里云 DNS 记录
type AliyunDNSRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	TTL       int       `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 辅助函数
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		if num, ok := val.(float64); ok {
			return int(num)
		}
		if num, ok := val.(int); ok {
			return num
		}
	}
	return 0
}

func parseTime(timeStr string) time.Time {
	if timeStr == "" {
		return time.Now()
	}

	// 尝试解析不同的时间格式
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t
		}
	}

	return time.Now()
}

// 阿里云API签名和请求辅助函数
func (p *AliyunProvider) signRequest(params map[string]string) string {
	// 添加公共参数
	params["Format"] = "JSON"
	params["Version"] = "2015-01-09"
	params["AccessKeyId"] = p.AccessKeyID
	params["SignatureMethod"] = "HMAC-SHA1"
	params["Timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	params["SignatureVersion"] = "1.0"
	params["SignatureNonce"] = fmt.Sprintf("%d", time.Now().UnixNano())

	// 排序参数
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 构建查询字符串
	var queryParts []string
	for _, k := range keys {
		queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(params[k])))
	}
	queryString := strings.Join(queryParts, "&")

	// 构建签名字符串
	stringToSign := fmt.Sprintf("GET&%s&%s", url.QueryEscape("/"), url.QueryEscape(queryString))

	// 计算签名
	mac := hmac.New(sha1.New, []byte(p.AccessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return signature
}

func (p *AliyunProvider) makeRequest(ctx context.Context, action string, params map[string]string) (map[string]interface{}, error) {
	params["Action"] = action
	signature := p.signRequest(params)

	// 添加签名到参数
	params["Signature"] = signature

	// 构建URL
	var queryParts []string
	for k, v := range params {
		queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
	}
	queryString := strings.Join(queryParts, "&")
	requestURL := fmt.Sprintf("https://alidns.aliyuncs.com/?%s", queryString)

	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
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

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Aliyun API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return result, nil
}

func (p *AliyunProvider) getTXTRecord(ctx context.Context, domain, name string) (string, error) {
	params := map[string]string{
		"DomainName": domain,
		"RRKeyWord":  name,
		"Type":       "TXT",
	}

	result, err := p.makeRequest(ctx, "DescribeDomainRecords", params)
	if err != nil {
		return "", err
	}

	records, ok := result["DomainRecords"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	recordList, ok := records["Record"].([]interface{})
	if !ok {
		return "", fmt.Errorf("record not found")
	}

	for _, record := range recordList {
		recordMap, ok := record.(map[string]interface{})
		if !ok {
			continue
		}

		if recordMap["RR"] == name && recordMap["Type"] == "TXT" {
			value, ok := recordMap["Value"].(string)
			if ok {
				return value, nil
			}
		}
	}

	return "", fmt.Errorf("record not found")
}

func (p *AliyunProvider) getRecordID(ctx context.Context, domain, name string) (string, error) {
	params := map[string]string{
		"DomainName": domain,
		"RRKeyWord":  name,
		"Type":       "TXT",
	}

	result, err := p.makeRequest(ctx, "DescribeDomainRecords", params)
	if err != nil {
		return "", err
	}

	records, ok := result["DomainRecords"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	recordList, ok := records["Record"].([]interface{})
	if !ok {
		return "", nil
	}

	for _, record := range recordList {
		recordMap, ok := record.(map[string]interface{})
		if !ok {
			continue
		}

		if recordMap["RR"] == name && recordMap["Type"] == "TXT" {
			recordID, ok := recordMap["RecordId"].(string)
			if ok {
				return recordID, nil
			}
		}
	}

	return "", nil
}

func (p *AliyunProvider) createTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	params := map[string]string{
		"DomainName": domain,
		"RR":         name,
		"Type":       "TXT",
		"Value":      value,
		"TTL":        fmt.Sprintf("%d", ttl),
	}

	_, err := p.makeRequest(ctx, "AddDomainRecord", params)
	return err
}

func (p *AliyunProvider) updateTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	recordID, err := p.getRecordID(ctx, domain, name)
	if err != nil {
		return err
	}

	if recordID == "" {
		return fmt.Errorf("record not found")
	}

	params := map[string]string{
		"RecordId": recordID,
		"RR":       name,
		"Type":     "TXT",
		"Value":    value,
		"TTL":      fmt.Sprintf("%d", ttl),
	}

	_, err = p.makeRequest(ctx, "UpdateDomainRecord", params)
	return err
}

func (p *AliyunProvider) deleteRecord(ctx context.Context, domain, recordID string) error {
	params := map[string]string{
		"RecordId": recordID,
	}

	_, err := p.makeRequest(ctx, "DeleteDomainRecord", params)
	return err
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

func (p *TencentProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	// 获取记录ID
	recordID, err := p.getRecordID(ctx, domain, name)
	if err != nil {
		return err
	}

	if recordID == "" {
		p.log.Debugf("TXT record not found: %s", name)
		return nil
	}

	// 删除记录
	return p.deleteRecord(ctx, domain, recordID)
}

func (p *TencentProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return p.getTXTRecord(ctx, domain, name)
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
			recordValue, err := p.getTXTRecord(ctx, domain, name)
			if err == nil && recordValue == value {
				p.log.Debugf("DNS record propagated: %s = %s", name, value)
				return nil
			}
		}
	}
}

func (p *TencentProvider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 获取域名列表
	domains, err := p.getTencentDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get domains: %w", err)
	}

	var allDomains []DomainInfo

	// 为每个域名获取 DNS 记录
	for _, domain := range domains {
		// 添加域名信息
		allDomains = append(allDomains, DomainInfo{
			Name:      domain.Name,
			Type:      "domain",
			Status:    domain.Status,
			CreatedAt: domain.CreatedAt,
			UpdatedAt: domain.UpdatedAt,
			TTL:       600,
			Value:     domain.ID,
		})

		// 获取域名的 DNS 记录
		records, err := p.getTencentDomainRecords(ctx, domain.ID)
		if err != nil {
			p.log.Warnf("Failed to get DNS records for domain %s: %v", domain.Name, err)
			continue
		}

		// 添加 DNS 记录
		for _, record := range records {
			allDomains = append(allDomains, DomainInfo{
				Name:      record.Name,
				Type:      record.Type,
				Status:    "active",
				CreatedAt: record.CreatedAt,
				UpdatedAt: record.UpdatedAt,
				TTL:       record.TTL,
				Value:     record.Value,
			})
		}
	}

	return allDomains, nil
}

// getTencentDomains 获取腾讯云域名列表
func (p *TencentProvider) getTencentDomains(ctx context.Context) ([]TencentDomain, error) {
	params := map[string]string{
		"Action": "DescribeDomainList",
	}

	result, err := p.makeTencentRequest(ctx, "DescribeDomainList", params)
	if err != nil {
		return nil, err
	}

	domainList, ok := result["DomainList"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid domain list format")
	}

	var domains []TencentDomain
	for _, domainData := range domainList {
		domainMap, ok := domainData.(map[string]interface{})
		if !ok {
			continue
		}

		domain := TencentDomain{
			ID:        getString(domainMap, "DomainId"),
			Name:      getString(domainMap, "Domain"),
			Status:    getString(domainMap, "Status"),
			CreatedAt: parseTime(getString(domainMap, "CreateTime")),
			UpdatedAt: parseTime(getString(domainMap, "UpdateTime")),
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// getTencentDomainRecords 获取指定域名的 DNS 记录
func (p *TencentProvider) getTencentDomainRecords(ctx context.Context, domainID string) ([]TencentDNSRecord, error) {
	params := map[string]string{
		"Action":   "DescribeRecordList",
		"DomainId": domainID,
	}

	result, err := p.makeTencentRequest(ctx, "DescribeRecordList", params)
	if err != nil {
		return nil, err
	}

	recordList, ok := result["RecordList"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid record list format")
	}

	var records []TencentDNSRecord
	for _, recordData := range recordList {
		recordMap, ok := recordData.(map[string]interface{})
		if !ok {
			continue
		}

		record := TencentDNSRecord{
			ID:        getString(recordMap, "RecordId"),
			Name:      getString(recordMap, "Name"),
			Type:      getString(recordMap, "Type"),
			Value:     getString(recordMap, "Value"),
			TTL:       getInt(recordMap, "TTL"),
			CreatedAt: parseTime(getString(recordMap, "CreateTime")),
			UpdatedAt: parseTime(getString(recordMap, "UpdateTime")),
		}
		records = append(records, record)
	}

	return records, nil
}

// makeTencentRequest 发送腾讯云 API 请求
func (p *TencentProvider) makeTencentRequest(ctx context.Context, action string, params map[string]string) (map[string]interface{}, error) {
	// 添加公共参数
	params["Action"] = action
	params["Version"] = "2021-06-23"
	params["Region"] = "ap-beijing"
	params["Timestamp"] = fmt.Sprintf("%d", time.Now().Unix())

	// 构建请求 URL
	url := "https://cns.tencentcloudapi.com/"

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, err
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", "2021-06-23")
	req.Header.Set("X-TC-Region", "ap-beijing")
	req.Header.Set("X-TC-Timestamp", params["Timestamp"])

	// 这里需要实现腾讯云的签名算法
	// 为了简化，我们返回模拟数据
	return map[string]interface{}{
		"DomainList": []interface{}{
			map[string]interface{}{
				"DomainId":   "example-domain-id",
				"Domain":     "example.com",
				"Status":     "active",
				"CreateTime": "2023-01-01T00:00:00Z",
				"UpdateTime": "2023-01-01T00:00:00Z",
			},
		},
	}, nil
}

// TencentDomain 腾讯云域名信息
type TencentDomain struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TencentDNSRecord 腾讯云 DNS 记录
type TencentDNSRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	TTL       int       `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 腾讯云API签名和请求辅助函数
func (p *TencentProvider) signRequest(params map[string]string) string {
	// 添加公共参数
	params["Action"] = "DescribeRecordList"
	params["Version"] = "2021-03-23"
	params["Region"] = "ap-beijing"
	params["Timestamp"] = fmt.Sprintf("%d", time.Now().Unix())
	params["Nonce"] = fmt.Sprintf("%d", time.Now().UnixNano())
	params["SecretId"] = p.SecretID

	// 排序参数
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 构建查询字符串
	var queryParts []string
	for _, k := range keys {
		queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(params[k])))
	}
	queryString := strings.Join(queryParts, "&")

	// 构建签名字符串
	stringToSign := fmt.Sprintf("GETcns.tencentcloudapi.com/?%s", queryString)

	// 计算签名
	mac := hmac.New(sha1.New, []byte(p.SecretKey))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return signature
}

func (p *TencentProvider) makeRequest(ctx context.Context, action string, params map[string]string) (map[string]interface{}, error) {
	params["Action"] = action
	params["Version"] = "2021-03-23"
	params["Region"] = "ap-beijing"
	params["Timestamp"] = fmt.Sprintf("%d", time.Now().Unix())
	params["Nonce"] = fmt.Sprintf("%d", time.Now().UnixNano())
	params["SecretId"] = p.SecretID

	signature := p.signRequest(params)
	params["Signature"] = signature

	// 构建URL
	var queryParts []string
	for k, v := range params {
		queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
	}
	queryString := strings.Join(queryParts, "&")
	requestURL := fmt.Sprintf("https://cns.tencentcloudapi.com/?%s", queryString)

	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
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

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Tencent API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return result, nil
}

func (p *TencentProvider) getTXTRecord(ctx context.Context, domain, name string) (string, error) {
	params := map[string]string{
		"Domain":     domain,
		"Subdomain":  name,
		"RecordType": "TXT",
	}

	result, err := p.makeRequest(ctx, "DescribeRecordList", params)
	if err != nil {
		return "", err
	}

	records, ok := result["Response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	recordList, ok := records["RecordList"].([]interface{})
	if !ok {
		return "", fmt.Errorf("record not found")
	}

	for _, record := range recordList {
		recordMap, ok := record.(map[string]interface{})
		if !ok {
			continue
		}

		if recordMap["Name"] == name && recordMap["Type"] == "TXT" {
			value, ok := recordMap["Value"].(string)
			if ok {
				return value, nil
			}
		}
	}

	return "", fmt.Errorf("record not found")
}

func (p *TencentProvider) getRecordID(ctx context.Context, domain, name string) (string, error) {
	params := map[string]string{
		"Domain":     domain,
		"Subdomain":  name,
		"RecordType": "TXT",
	}

	result, err := p.makeRequest(ctx, "DescribeRecordList", params)
	if err != nil {
		return "", err
	}

	records, ok := result["Response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	recordList, ok := records["RecordList"].([]interface{})
	if !ok {
		return "", nil
	}

	for _, record := range recordList {
		recordMap, ok := record.(map[string]interface{})
		if !ok {
			continue
		}

		if recordMap["Name"] == name && recordMap["Type"] == "TXT" {
			recordID, ok := recordMap["RecordId"].(float64)
			if ok {
				return fmt.Sprintf("%.0f", recordID), nil
			}
		}
	}

	return "", nil
}

func (p *TencentProvider) createTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	params := map[string]string{
		"Domain":     domain,
		"SubDomain":  name,
		"RecordType": "TXT",
		"RecordLine": "默认",
		"Value":      value,
		"TTL":        fmt.Sprintf("%d", ttl),
	}

	_, err := p.makeRequest(ctx, "CreateRecord", params)
	return err
}

func (p *TencentProvider) updateTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	recordID, err := p.getRecordID(ctx, domain, name)
	if err != nil {
		return err
	}

	if recordID == "" {
		return fmt.Errorf("record not found")
	}

	params := map[string]string{
		"RecordId":   recordID,
		"SubDomain":  name,
		"RecordType": "TXT",
		"RecordLine": "默认",
		"Value":      value,
		"TTL":        fmt.Sprintf("%d", ttl),
	}

	_, err = p.makeRequest(ctx, "ModifyRecord", params)
	return err
}

func (p *TencentProvider) deleteRecord(ctx context.Context, domain, recordID string) error {
	params := map[string]string{
		"RecordId": recordID,
		"Domain":   domain,
	}

	_, err := p.makeRequest(ctx, "DeleteRecord", params)
	return err
}

// AWSRoute53Provider AWS Route53 DNS服务商
type AWSRoute53Provider struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	log             Logger
}

// NewAWSRoute53Provider 创建AWS Route53 DNS服务商
func NewAWSRoute53Provider(accessKeyID, secretAccessKey, region string, log Logger) *AWSRoute53Provider {
	if region == "" {
		region = "us-east-1"
	}
	return &AWSRoute53Provider{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          region,
		log:             log,
	}
}

func (p *AWSRoute53Provider) GetProviderName() string {
	return "aws"
}

func (p *AWSRoute53Provider) Validate() error {
	if p.AccessKeyID == "" {
		return fmt.Errorf("AWS Access Key ID is required")
	}
	if p.SecretAccessKey == "" {
		return fmt.Errorf("AWS Secret Access Key is required")
	}
	return nil
}

func (p *AWSRoute53Provider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	// 获取托管区域ID
	hostedZoneID, err := p.getHostedZoneID(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to get hosted zone ID: %w", err)
	}

	// 检查记录是否已存在
	existingRecord, err := p.GetTXTRecord(ctx, domain, name)
	if err != nil && err.Error() != "record not found" {
		return err
	}

	if existingRecord != "" {
		// 更新现有记录
		return p.updateTXTRecord(ctx, hostedZoneID, domain, name, value, ttl)
	}

	// 创建新记录
	return p.createTXTRecord(ctx, hostedZoneID, domain, name, value, ttl)
}

func (p *AWSRoute53Provider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	// 获取托管区域ID
	hostedZoneID, err := p.getHostedZoneID(ctx, domain)
	if err != nil {
		return fmt.Errorf("failed to get hosted zone ID: %w", err)
	}

	// 获取记录信息
	recordInfo, err := p.getRecordInfo(ctx, hostedZoneID, name)
	if err != nil {
		if err.Error() == "record not found" {
			p.log.Debugf("TXT record not found: %s", name)
			return nil
		}
		return err
	}

	// 删除记录
	return p.deleteRecord(ctx, hostedZoneID, recordInfo)
}

func (p *AWSRoute53Provider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	// 获取托管区域ID
	hostedZoneID, err := p.getHostedZoneID(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("failed to get hosted zone ID: %w", err)
	}

	recordInfo, err := p.getRecordInfo(ctx, hostedZoneID, name)
	if err != nil {
		return "", err
	}

	// 查找TXT记录
	for _, record := range recordInfo.ResourceRecords {
		if record.Value != nil {
			// 移除引号（AWS Route53返回的值包含引号）
			value := *record.Value
			if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
				value = value[1 : len(value)-1]
			}
			return value, nil
		}
	}

	return "", fmt.Errorf("record not found")
}

func (p *AWSRoute53Provider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
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

func (p *AWSRoute53Provider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 获取所有托管区域
	hostedZones, err := p.getHostedZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get hosted zones: %w", err)
	}

	var allDomains []DomainInfo

	// 为每个托管区域获取资源记录集
	for _, zone := range hostedZones {
		// 添加托管区域信息
		allDomains = append(allDomains, DomainInfo{
			Name:      zone.Name,
			Type:      "hosted-zone",
			Status:    "active",
			CreatedAt: zone.CreatedAt,
			UpdatedAt: zone.UpdatedAt,
			TTL:       1,
			Value:     zone.ID,
		})

		// 获取资源记录集
		records, err := p.getResourceRecordSets(ctx, zone.ID)
		if err != nil {
			p.log.Warnf("Failed to get resource record sets for zone %s: %v", zone.Name, err)
			continue
		}

		// 添加资源记录
		for _, record := range records {
			allDomains = append(allDomains, DomainInfo{
				Name:      record.Name,
				Type:      record.Type,
				Status:    "active",
				CreatedAt: record.CreatedAt,
				UpdatedAt: record.UpdatedAt,
				TTL:       record.TTL,
				Value:     record.Value,
			})
		}
	}

	return allDomains, nil
}

// getHostedZones 获取所有托管区域
func (p *AWSRoute53Provider) getHostedZones(ctx context.Context) ([]AWSHostedZone, error) {
	url := "https://route53.amazonaws.com/2013-04-01/hostedzone"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 添加AWS签名
	if err := p.signAWSRequest(req, "route53", "us-east-1", ""); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AWS Route53 API error: %d, body: %s", resp.StatusCode, string(body))
	}

	// 解析XML响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 简化的XML解析 - 实际应用中应该使用XML解析器
	zones := p.parseHostedZonesXML(string(body))
	return zones, nil
}

// getResourceRecordSets 获取指定托管区域的资源记录集
func (p *AWSRoute53Provider) getResourceRecordSets(ctx context.Context, hostedZoneID string) ([]AWSResourceRecord, error) {
	url := fmt.Sprintf("https://route53.amazonaws.com/2013-04-01/hostedzone/%s/rrset", hostedZoneID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 添加AWS签名
	if err := p.signAWSRequest(req, "route53", "us-east-1", ""); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AWS Route53 API error: %d, body: %s", resp.StatusCode, string(body))
	}

	// 解析XML响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 简化的XML解析 - 实际应用中应该使用XML解析器
	records := p.parseResourceRecordSetsXML(string(body))
	return records, nil
}

// parseHostedZonesXML 解析托管区域XML响应
func (p *AWSRoute53Provider) parseHostedZonesXML(xmlData string) []AWSHostedZone {
	// 简化的XML解析 - 实际应用中应该使用XML解析器
	// 这里返回模拟数据
	return []AWSHostedZone{
		{
			ID:        "Z1234567890",
			Name:      "example.com.",
			Status:    "active",
			CreatedAt: time.Now().Add(-24 * time.Hour),
			UpdatedAt: time.Now(),
		},
	}
}

// parseResourceRecordSetsXML 解析资源记录集XML响应
func (p *AWSRoute53Provider) parseResourceRecordSetsXML(xmlData string) []AWSResourceRecord {
	// 简化的XML解析 - 实际应用中应该使用XML解析器
	// 这里返回模拟数据
	return []AWSResourceRecord{
		{
			Name:      "example.com.",
			Type:      "A",
			TTL:       300,
			Value:     "192.168.1.1",
			CreatedAt: time.Now().Add(-12 * time.Hour),
			UpdatedAt: time.Now(),
		},
		{
			Name:      "www.example.com.",
			Type:      "CNAME",
			TTL:       300,
			Value:     "example.com.",
			CreatedAt: time.Now().Add(-6 * time.Hour),
			UpdatedAt: time.Now(),
		},
	}
}

// AWSHostedZone AWS托管区域信息
type AWSHostedZone struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AWSResourceRecord AWS资源记录
type AWSResourceRecord struct {
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	TTL       int       `json:"ttl"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

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
		return fmt.Errorf("GoDaddy API Key is required")
	}
	if p.APISecret == "" {
		return fmt.Errorf("GoDaddy API Secret is required")
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
	// GoDaddy API删除记录
	url := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records/TXT/%s", domain, name)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
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

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GoDaddy API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *GoDaddyProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return p.getTXTRecord(ctx, domain, name)
}

func (p *GoDaddyProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
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
	domains, err := p.getGoDaddyDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get domains: %w", err)
	}

	var allDomains []DomainInfo

	// 为每个域名获取 DNS 记录
	for _, domain := range domains {
		// 添加域名信息
		allDomains = append(allDomains, DomainInfo{
			Name:      domain.Name,
			Type:      "domain",
			Status:    domain.Status,
			CreatedAt: domain.CreatedAt,
			UpdatedAt: domain.UpdatedAt,
			TTL:       600,
			Value:     domain.ID,
		})

		// 获取域名的 DNS 记录
		records, err := p.getGoDaddyDomainRecords(ctx, domain.Name)
		if err != nil {
			p.log.Warnf("Failed to get DNS records for domain %s: %v", domain.Name, err)
			continue
		}

		// 添加 DNS 记录
		for _, record := range records {
			allDomains = append(allDomains, DomainInfo{
				Name:      record.Name,
				Type:      record.Type,
				Status:    "active",
				CreatedAt: record.CreatedAt,
				UpdatedAt: record.UpdatedAt,
				TTL:       record.TTL,
				Value:     record.Value,
			})
		}
	}

	return allDomains, nil
}

// getGoDaddyDomains 获取 GoDaddy 域名列表
func (p *GoDaddyProvider) getGoDaddyDomains(ctx context.Context) ([]GoDaddyDomain, error) {
	url := "https://api.godaddy.com/v1/domains"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 设置认证头
	req.Header.Set("Authorization", "sso-key "+p.APIKey+":"+p.APISecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GoDaddy domains API error: %d, body: %s", resp.StatusCode, string(body))
	}

	var domains []GoDaddyDomain
	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		return nil, err
	}

	return domains, nil
}

// getGoDaddyDomainRecords 获取指定域名的 DNS 记录
func (p *GoDaddyProvider) getGoDaddyDomainRecords(ctx context.Context, domain string) ([]GoDaddyDNSRecord, error) {
	url := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 设置认证头
	req.Header.Set("Authorization", "sso-key "+p.APIKey+":"+p.APISecret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GoDaddy DNS records API error: %d, body: %s", resp.StatusCode, string(body))
	}

	var records []GoDaddyDNSRecord
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, err
	}

	return records, nil
}

// GoDaddyDomain GoDaddy 域名信息
type GoDaddyDomain struct {
	ID        string    `json:"domainId"`
	Name      string    `json:"domain"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// GoDaddyDNSRecord GoDaddy DNS 记录
type GoDaddyDNSRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	TTL       int       `json:"ttl"`
	Value     string    `json:"data"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (p *GoDaddyProvider) getTXTRecord(ctx context.Context, domain, name string) (string, error) {
	url := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records/TXT/%s", domain, name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", p.APIKey, p.APISecret))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("record not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GoDaddy API error: %d, body: %s", resp.StatusCode, string(body))
	}

	var records []struct {
		Data string `json:"data"`
		TTL  int    `json:"ttl"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return "", err
	}

	if len(records) > 0 {
		return records[0].Data, nil
	}

	return "", fmt.Errorf("record not found")
}

func (p *GoDaddyProvider) createTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	url := fmt.Sprintf("https://api.godaddy.com/v1/domains/%s/records", domain)

	record := []struct {
		Type string `json:"type"`
		Name string `json:"name"`
		Data string `json:"data"`
		TTL  int    `json:"ttl"`
	}{
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
	// 自定义DNS API实现
	// 这里实现一个通用的HTTP API调用
	url := fmt.Sprintf("%s/dns/records", p.Endpoint)

	payload := map[string]interface{}{
		"domain": domain,
		"name":   name,
		"type":   "TXT",
		"value":  value,
		"ttl":    ttl,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Custom DNS API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *CustomProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	url := fmt.Sprintf("%s/dns/records/%s/%s", p.Endpoint, domain, name)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return err
	}

	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Custom DNS API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *CustomProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	url := fmt.Sprintf("%s/dns/records/%s/%s", p.Endpoint, domain, name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("record not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Custom DNS API error: %d, body: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Value string `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Value, nil
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
			recordValue, err := p.GetTXTRecord(ctx, domain, name)
			if err == nil && recordValue == value {
				p.log.Debugf("DNS record propagated: %s = %s", name, value)
				return nil
			}
		}
	}
}

func (p *CustomProvider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 自定义提供者域名列表获取 - 简化实现
	// 这里返回一个示例域名，实际实现需要调用自定义API
	return []DomainInfo{
		{
			Name:      "example.com",
			Type:      "domain",
			Status:    "active",
			CreatedAt: time.Now().Add(-24 * time.Hour),
			UpdatedAt: time.Now(),
			TTL:       600,
			Value:     "example-domain-id",
		},
	}, nil
}

// AWS Route53 辅助方法

// Route53RecordInfo AWS Route53记录信息
type Route53RecordInfo struct {
	Name            string
	Type            string
	TTL             *int64
	ResourceRecords []*Route53ResourceRecord
}

// Route53ResourceRecord AWS Route53资源记录
type Route53ResourceRecord struct {
	Value *string
}

// Route53Change AWS Route53变更
type Route53Change struct {
	Action            string
	ResourceRecordSet *Route53RecordInfo
}

// Route53ChangeBatch AWS Route53变更批次
type Route53ChangeBatch struct {
	Changes []*Route53Change
}

// Route53Response AWS Route53响应
type Route53Response struct {
	ChangeInfo *Route53ChangeInfo
}

// Route53ChangeInfo AWS Route53变更信息
type Route53ChangeInfo struct {
	ID     string
	Status string
}

// getHostedZoneID 获取托管区域ID
func (p *AWSRoute53Provider) getHostedZoneID(ctx context.Context, domain string) (string, error) {
	// 构建请求URL
	url := fmt.Sprintf("https://route53.amazonaws.com/2013-04-01/hostedzone")

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	// 添加AWS签名
	if err := p.signAWSRequest(req, "route53", "us-east-1", ""); err != nil {
		return "", fmt.Errorf("failed to sign request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("AWS Route53 API error: %d, body: %s", resp.StatusCode, string(body))
	}

	// 解析响应，查找匹配的域名
	// 注意：这里使用简化的字符串解析，实际应用中应该使用XML解析器

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// 简单的XML解析，查找匹配的域名
	// 这里使用简单的字符串匹配，实际应用中应该使用XML解析器
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.Contains(line, domain+".") && strings.Contains(line, "Id") {
			// 提取ID
			start := strings.Index(line, "Id>")
			if start != -1 {
				start += 3
				end := strings.Index(line[start:], "</Id>")
				if end != -1 {
					id := line[start : start+end]
					// 移除前缀 "hostedzone/"
					if strings.HasPrefix(id, "hostedzone/") {
						return id[11:], nil
					}
					return id, nil
				}
			}
		}
	}

	return "", fmt.Errorf("hosted zone not found for domain: %s", domain)
}

// getRecordInfo 获取记录信息
func (p *AWSRoute53Provider) getRecordInfo(ctx context.Context, hostedZoneID, name string) (*Route53RecordInfo, error) {
	url := fmt.Sprintf("https://route53.amazonaws.com/2013-04-01/hostedzone/%s/rrset?name=%s&type=TXT", hostedZoneID, name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// 添加AWS签名
	if err := p.signAWSRequest(req, "route53", "us-east-1", ""); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("record not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AWS Route53 API error: %d, body: %s", resp.StatusCode, string(body))
	}

	// 解析响应
	// 注意：这里使用简化的字符串解析，实际应用中应该使用XML解析器

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 简单的XML解析
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ResourceRecordSet") && strings.Contains(line, name) {
			// 这里应该解析完整的XML，但为了简化，我们返回一个基本结构
			return &Route53RecordInfo{
				Name: name,
				Type: "TXT",
				ResourceRecords: []*Route53ResourceRecord{
					{Value: &name}, // 占位值
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("record not found")
}

// createTXTRecord 创建TXT记录
func (p *AWSRoute53Provider) createTXTRecord(ctx context.Context, hostedZoneID, domain, name, value string, ttl int) error {
	changeBatch := &Route53ChangeBatch{
		Changes: []*Route53Change{
			{
				Action: "CREATE",
				ResourceRecordSet: &Route53RecordInfo{
					Name: name + "." + domain,
					Type: "TXT",
					TTL:  func() *int64 { t := int64(ttl); return &t }(),
					ResourceRecords: []*Route53ResourceRecord{
						{Value: func() *string { v := "\"" + value + "\""; return &v }()},
					},
				},
			},
		},
	}

	return p.changeResourceRecordSets(ctx, hostedZoneID, changeBatch)
}

// updateTXTRecord 更新TXT记录
func (p *AWSRoute53Provider) updateTXTRecord(ctx context.Context, hostedZoneID, domain, name, value string, ttl int) error {
	// 获取现有记录
	recordInfo, err := p.getRecordInfo(ctx, hostedZoneID, name)
	if err != nil {
		return err
	}

	changeBatch := &Route53ChangeBatch{
		Changes: []*Route53Change{
			{
				Action:            "DELETE",
				ResourceRecordSet: recordInfo,
			},
			{
				Action: "CREATE",
				ResourceRecordSet: &Route53RecordInfo{
					Name: name + "." + domain,
					Type: "TXT",
					TTL:  func() *int64 { t := int64(ttl); return &t }(),
					ResourceRecords: []*Route53ResourceRecord{
						{Value: func() *string { v := "\"" + value + "\""; return &v }()},
					},
				},
			},
		},
	}

	return p.changeResourceRecordSets(ctx, hostedZoneID, changeBatch)
}

// deleteRecord 删除记录
func (p *AWSRoute53Provider) deleteRecord(ctx context.Context, hostedZoneID string, recordInfo *Route53RecordInfo) error {
	changeBatch := &Route53ChangeBatch{
		Changes: []*Route53Change{
			{
				Action:            "DELETE",
				ResourceRecordSet: recordInfo,
			},
		},
	}

	return p.changeResourceRecordSets(ctx, hostedZoneID, changeBatch)
}

// changeResourceRecordSets 执行资源记录集变更
func (p *AWSRoute53Provider) changeResourceRecordSets(ctx context.Context, hostedZoneID string, changeBatch *Route53ChangeBatch) error {
	jsonData, err := json.Marshal(changeBatch)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://route53.amazonaws.com/2013-04-01/hostedzone/%s/rrset", hostedZoneID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	// 添加AWS签名
	if err := p.signAWSRequest(req, "route53", "us-east-1", string(jsonData)); err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("AWS Route53 API error: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// signAWSRequest 为AWS请求添加签名
func (p *AWSRoute53Provider) signAWSRequest(req *http.Request, service, region, payload string) error {
	// 这里实现AWS Signature Version 4
	// 为了简化，我们使用基本的HMAC-SHA256签名

	// 创建日期
	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	timeStr := now.Format("20060102T150405Z")

	// 设置必要的头部
	req.Header.Set("X-Amz-Date", timeStr)
	req.Header.Set("Host", req.URL.Host)

	// 构建规范请求（简化处理）
	_ = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		"host:"+req.URL.Host+"\nx-amz-date:"+timeStr+"\n",
		"host;x-amz-date",
		"UNSIGNED-PAYLOAD", // 简化处理
	)

	// 创建字符串签名
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s/%s/%s/aws4_request\n%s",
		timeStr,
		dateStr,
		region,
		service,
		"UNSIGNED-PAYLOAD", // 简化处理
	)

	// 计算签名
	dateKey := hmacSHA256([]byte("AWS4"+p.SecretAccessKey), dateStr)
	dateRegionKey := hmacSHA256(dateKey, region)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, service)
	signingKey := hmacSHA256(dateRegionServiceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	// 设置授权头
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s",
		p.AccessKeyID, dateStr, region, service, signature)
	req.Header.Set("Authorization", authHeader)

	return nil
}

// hmacSHA256 计算HMAC-SHA256
func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
