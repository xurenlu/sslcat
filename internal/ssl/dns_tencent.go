package ssl

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

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
			Status:    domain.Status,
			CreatedAt: domain.CreatedAt,
			UpdatedAt: domain.UpdatedAt,
			TTL:       600,
			Value:     fmt.Sprintf("%d", domain.ID),
		})

		// 获取域名的 DNS 记录（获取前几条记录作为示例）
		records, err := p.getDomainRecords(ctx, domain.Name)
		if err != nil {
			p.log.Warnf("Failed to get DNS records for domain %s: %v", domain.Name, err)
			continue
		}

		// 只添加前几条记录，避免数据过多
		for i, record := range records {
			if i >= 5 { // 限制每个域名最多显示5条记录
				break
			}
			fullName := record.Name
			if record.Name != "@" && record.Name != "" {
				fullName = fmt.Sprintf("%s.%s", record.Name, domain.Name)
			} else {
				fullName = domain.Name
			}
			allDomains = append(allDomains, DomainInfo{
				Name:      fullName,
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

// TencentDomain 腾讯云域名信息
type TencentDomain struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TencentDNSRecord 腾讯云 DNS 记录
type TencentDNSRecord struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	TTL       int       `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// getDomains 获取腾讯云域名列表
func (p *TencentProvider) getDomains(ctx context.Context) ([]TencentDomain, error) {
	params := map[string]interface{}{
		"Offset": 0,
		"Limit":  100,
	}

	result, err := p.makeRequest(ctx, "DescribeDomainList", params)
	if err != nil {
		return nil, err
	}

	response, ok := result["Response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format")
	}

	domainListData, ok := response["DomainList"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid domain list format")
	}

	var domains []TencentDomain
	for _, domainData := range domainListData {
		domainMap, ok := domainData.(map[string]interface{})
		if !ok {
			continue
		}

		domain := TencentDomain{
			ID:        int64(getInt(domainMap, "DomainId")),
			Name:      getString(domainMap, "Name"),
			Status:    getString(domainMap, "Status"),
			CreatedAt: parseTime(getString(domainMap, "CreatedOn")),
			UpdatedAt: parseTime(getString(domainMap, "UpdatedOn")),
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// getDomainRecords 获取指定域名的 DNS 记录
func (p *TencentProvider) getDomainRecords(ctx context.Context, domainName string) ([]TencentDNSRecord, error) {
	params := map[string]interface{}{
		"Domain": domainName,
		"Offset": 0,
		"Limit":  20, // 限制返回记录数
	}

	result, err := p.makeRequest(ctx, "DescribeRecordList", params)
	if err != nil {
		return nil, err
	}

	response, ok := result["Response"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format")
	}

	recordListData, ok := response["RecordList"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid record list format")
	}

	var records []TencentDNSRecord
	for _, recordData := range recordListData {
		recordMap, ok := recordData.(map[string]interface{})
		if !ok {
			continue
		}

		record := TencentDNSRecord{
			ID:        int64(getInt(recordMap, "RecordId")),
			Name:      getString(recordMap, "Name"),
			Type:      getString(recordMap, "Type"),
			Value:     getString(recordMap, "Value"),
			TTL:       getInt(recordMap, "TTL"),
			CreatedAt: parseTime(getString(recordMap, "CreatedOn")),
			UpdatedAt: parseTime(getString(recordMap, "UpdatedOn")),
		}
		records = append(records, record)
	}

	return records, nil
}

// 腾讯云API V3签名算法
func (p *TencentProvider) sign(payload []byte, timestamp string) string {
	// Step 1: 构建规范请求串
	canonicalRequest := fmt.Sprintf("POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:dnspod.tencentcloudapi.com\n\ncontent-type;host\n%s",
		sha256Hex(payload))

	// Step 2: 构建待签名字符串
	date := timestamp[:8] // YYYYMMDD
	credentialScope := fmt.Sprintf("%s/dnspod/tc3_request", date)
	stringToSign := fmt.Sprintf("TC3-HMAC-SHA256\n%s\n%s\n%s",
		timestamp, credentialScope, sha256Hex([]byte(canonicalRequest)))

	// Step 3: 计算签名
	secretDate := hmacSha256([]byte("TC3"+p.SecretKey), []byte(date))
	secretService := hmacSha256(secretDate, []byte("dnspod"))
	secretSigning := hmacSha256(secretService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSha256(secretSigning, []byte(stringToSign)))

	// Step 4: 构建 Authorization
	return fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host, Signature=%s",
		p.SecretID, credentialScope, signature)
}

func (p *TencentProvider) makeRequest(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	// 构建请求体
	jsonData, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	// 生成时间戳
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	date := time.Unix(time.Now().Unix(), 0).UTC().Format("2006-01-02")

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "POST", "https://dnspod.tencentcloudapi.com/", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", "dnspod.tencentcloudapi.com")
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", "2021-03-23")
	req.Header.Set("X-TC-Timestamp", timestamp)
	req.Header.Set("X-TC-Region", "")

	// 签名
	auth := p.sign(jsonData, date+timestamp[8:])
	req.Header.Set("Authorization", auth)

	// 发送请求
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

	// 检查API错误
	if response, exists := result["Response"]; exists {
		if responseMap, ok := response.(map[string]interface{}); ok {
			if errorData, exists := responseMap["Error"]; exists {
				if errorMap, ok := errorData.(map[string]interface{}); ok {
					errorCode := getString(errorMap, "Code")
					errorMsg := getString(errorMap, "Message")
					return nil, fmt.Errorf("Tencent API error: %s - %s", errorCode, errorMsg)
				}
			}
		}
	}

	return result, nil
}

// 辅助方法实现
func (p *TencentProvider) getTXTRecord(ctx context.Context, domain, name string) (string, error) {
	params := map[string]interface{}{
		"Domain":     domain,
		"Subdomain":  name,
		"RecordType": "TXT",
	}

	result, err := p.makeRequest(ctx, "DescribeRecordList", params)
	if err != nil {
		return "", err
	}

	response, ok := result["Response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	recordList, ok := response["RecordList"].([]interface{})
	if !ok {
		return "", fmt.Errorf("record not found")
	}

	for _, record := range recordList {
		recordMap, ok := record.(map[string]interface{})
		if !ok {
			continue
		}

		if getString(recordMap, "Name") == name && getString(recordMap, "Type") == "TXT" {
			return getString(recordMap, "Value"), nil
		}
	}

	return "", fmt.Errorf("record not found")
}

func (p *TencentProvider) createTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	params := map[string]interface{}{
		"Domain":     domain,
		"SubDomain":  name,
		"RecordType": "TXT",
		"RecordLine": "默认",
		"Value":      value,
		"TTL":        ttl,
	}

	_, err := p.makeRequest(ctx, "CreateRecord", params)
	return err
}

func (p *TencentProvider) updateTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	// 获取记录ID
	recordID, err := p.getRecordID(ctx, domain, name)
	if err != nil {
		return err
	}

	params := map[string]interface{}{
		"Domain":     domain,
		"RecordId":   recordID,
		"SubDomain":  name,
		"RecordType": "TXT",
		"RecordLine": "默认",
		"Value":      value,
		"TTL":        ttl,
	}

	_, err = p.makeRequest(ctx, "ModifyRecord", params)
	return err
}

func (p *TencentProvider) deleteRecord(ctx context.Context, domain, recordID string) error {
	params := map[string]interface{}{
		"Domain":   domain,
		"RecordId": recordID,
	}

	_, err := p.makeRequest(ctx, "DeleteRecord", params)
	return err
}

func (p *TencentProvider) getRecordID(ctx context.Context, domain, name string) (string, error) {
	params := map[string]interface{}{
		"Domain":     domain,
		"Subdomain":  name,
		"RecordType": "TXT",
	}

	result, err := p.makeRequest(ctx, "DescribeRecordList", params)
	if err != nil {
		return "", err
	}

	response, ok := result["Response"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid response format")
	}

	recordList, ok := response["RecordList"].([]interface{})
	if !ok {
		return "", fmt.Errorf("record not found")
	}

	for _, record := range recordList {
		recordMap, ok := record.(map[string]interface{})
		if !ok {
			continue
		}

		if getString(recordMap, "Name") == name && getString(recordMap, "Type") == "TXT" {
			return fmt.Sprintf("%d", getInt(recordMap, "RecordId")), nil
		}
	}

	return "", fmt.Errorf("record not found")
}

// 辅助函数
func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
