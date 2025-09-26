package ssl

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

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

	// 为每个域名添加信息
	for _, domain := range domains {
		allDomains = append(allDomains, DomainInfo{
			Name:      domain.Name,
			Type:      "domain",
			Status:    domain.Status,
			CreatedAt: domain.CreatedAt,
			UpdatedAt: domain.UpdatedAt,
			TTL:       600,
			Value:     domain.ID,
		})

		// 获取域名的 DNS 记录（可选，获取前几条记录作为示例）
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
			allDomains = append(allDomains, DomainInfo{
				Name:      fmt.Sprintf("%s.%s", record.Name, domain.Name),
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
func (p *AliyunProvider) getDomainRecords(ctx context.Context, domainName string) ([]AliyunDNSRecord, error) {
	params := map[string]string{
		"Action":     "DescribeDomainRecords",
		"Version":    "2015-01-09",
		"DomainName": domainName,
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

	// 检查API错误
	if errorCode, exists := result["Code"]; exists {
		errorMsg, _ := result["Message"].(string)
		return nil, fmt.Errorf("Aliyun API error: %s - %s", errorCode, errorMsg)
	}

	return result, nil
}

// 其他辅助方法的实现
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
	// 获取记录ID
	recordID, err := p.getRecordID(ctx, domain, name)
	if err != nil {
		return err
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
		return "", fmt.Errorf("record not found")
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

	return "", fmt.Errorf("record not found")
}
