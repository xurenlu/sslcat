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
	// 阿里云 API 需要根域名和子域名分离
	// domain 参数可能是 ca.17push.com，需要提取根域名 17push.com
	rootDomain, rr := p.extractDomainAndRR(domain, name)
	p.log.Debugf("Aliyun SetTXTRecord: original domain=%s, name=%s -> rootDomain=%s, RR=%s", domain, name, rootDomain, rr)
	
	// 阿里云 TTL 要求在 600-86400 之间
	if ttl < 600 {
		ttl = 600
	} else if ttl > 86400 {
		ttl = 86400
	}

	// 检查记录是否已存在
	existingRecord, err := p.getTXTRecord(ctx, rootDomain, rr)
	if err != nil && err.Error() != "record not found" {
		return err
	}

	if existingRecord != "" {
		// 更新现有记录
		return p.updateTXTRecord(ctx, rootDomain, rr, value, ttl)
	}

	// 创建新记录
	return p.createTXTRecord(ctx, rootDomain, rr, value, ttl)
}

// extractDomainAndRR 从完整域名中提取根域名和 RR 记录
// 例如：domain=ca.17push.com, name=_acme-challenge -> rootDomain=17push.com, rr=_acme-challenge.ca
func (p *AliyunProvider) extractDomainAndRR(domain, name string) (rootDomain, rr string) {
	// 尝试从已知的域名列表中查找根域名
	// 如果没有，则按照常见规则处理（最后两段为根域名）
	parts := strings.Split(domain, ".")
	
	// 处理特殊情况：如 co.uk, com.cn 等二级域名后缀
	specialSuffixes := map[string]bool{
		"co.uk": true, "com.cn": true, "net.cn": true, "org.cn": true,
		"com.au": true, "co.jp": true, "co.nz": true, "co.kr": true,
	}
	
	if len(parts) >= 2 {
		lastTwo := strings.Join(parts[len(parts)-2:], ".")
		if specialSuffixes[lastTwo] && len(parts) >= 3 {
			// 三级域名后缀，根域名取最后三段
			rootDomain = strings.Join(parts[len(parts)-3:], ".")
			if len(parts) > 3 {
				subdomain := strings.Join(parts[:len(parts)-3], ".")
				rr = name + "." + subdomain
			} else {
				rr = name
			}
		} else {
			// 普通二级域名后缀，根域名取最后两段
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
			if len(parts) > 2 {
				subdomain := strings.Join(parts[:len(parts)-2], ".")
				rr = name + "." + subdomain
			} else {
				rr = name
			}
		}
	} else {
		// 域名格式不对，直接返回原值
		rootDomain = domain
		rr = name
	}
	
	return rootDomain, rr
}

func (p *AliyunProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	// 阿里云 API 需要根域名和子域名分离
	rootDomain, rr := p.extractDomainAndRR(domain, name)
	p.log.Debugf("Aliyun DeleteTXTRecord: original domain=%s, name=%s -> rootDomain=%s, RR=%s", domain, name, rootDomain, rr)

	// 获取记录ID
	recordID, err := p.getRecordID(ctx, rootDomain, rr)
	if err != nil {
		return err
	}

	if recordID == "" {
		p.log.Debugf("TXT record not found: %s", rr)
		return nil
	}

	// 删除记录
	return p.deleteRecord(ctx, rootDomain, recordID)
}

func (p *AliyunProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	// 阿里云 API 需要根域名和子域名分离
	rootDomain, rr := p.extractDomainAndRR(domain, name)
	return p.getTXTRecord(ctx, rootDomain, rr)
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
		"Action":    "DescribeDomains",
		"Version":   "2015-01-09",
		"PageSize":  "100", // 设置每页大小，最多100
		"PageNumber": "1",  // 从第一页开始
	}

	var allDomains []AliyunDomain

	// 处理分页，最多获取10页（1000个域名）
	for pageNum := 1; pageNum <= 10; pageNum++ {
		params["PageNumber"] = fmt.Sprintf("%d", pageNum)

		result, err := p.makeRequest(ctx, "DescribeDomains", params)
		if err != nil {
			if pageNum == 1 {
				return nil, fmt.Errorf("failed to get domains from Aliyun API: %w", err)
			}
			// 如果不是第一页出错，可能是已经获取完所有数据
			p.log.Debugf("Error fetching page %d, assuming all domains retrieved: %v", pageNum, err)
			break
		}

		// 记录原始响应以便调试
		p.log.Debugf("Aliyun API response keys: %v", getMapKeys(result))

		domainsData, ok := result["Domains"].(map[string]interface{})
		if !ok {
			if pageNum == 1 {
				// 记录原始响应以便调试
				p.log.Warnf("Invalid response format from Aliyun API, result keys: %v", getMapKeys(result))
				return nil, fmt.Errorf("invalid response format: missing 'Domains' field, response keys: %v", getMapKeys(result))
			}
			break
		}

		// 处理 Domain 字段：可能是数组或单个对象
		var domainList []interface{}
		domainValue := domainsData["Domain"]

		if domainValue == nil {
			// 没有域名数据
			if pageNum == 1 {
				p.log.Infof("No domains found in Aliyun account")
				return []AliyunDomain{}, nil
			}
			break
		}

		switch v := domainValue.(type) {
		case []interface{}:
			// 多个域名，是数组
			domainList = v
		case map[string]interface{}:
			// 单个域名，是对象
			domainList = []interface{}{v}
		default:
			if pageNum == 1 {
				p.log.Warnf("Unexpected Domain type: %T, value: %v", domainValue, domainValue)
				return nil, fmt.Errorf("invalid domain list format: unexpected type %T", domainValue)
			}
			break
		}

		// 解析域名列表
		pageDomains := 0
		for _, domainData := range domainList {
			domainMap, ok := domainData.(map[string]interface{})
			if !ok {
				p.log.Warnf("Skipping invalid domain data: %v", domainData)
				continue
			}

			domain := AliyunDomain{
				ID:        getString(domainMap, "DomainId"),
				Name:      getString(domainMap, "DomainName"),
				Status:    getString(domainMap, "Status"),
				CreatedAt: parseTime(getString(domainMap, "CreateTime")),
				UpdatedAt: parseTime(getString(domainMap, "UpdateTime")),
			}

			if domain.Name == "" {
				p.log.Warnf("Skipping domain with empty name: %v", domainMap)
				continue
			}

			allDomains = append(allDomains, domain)
			pageDomains++
		}

		// 如果这一页没有域名，说明已经获取完所有数据
		if pageDomains == 0 {
			break
		}

		// 检查是否还有更多页
		totalCount := getInt(domainsData, "TotalCount")
		if totalCount > 0 && len(allDomains) >= totalCount {
			break
		}

		// 如果这一页的域名数量少于 PageSize，说明已经是最后一页
		if pageDomains < 100 {
			break
		}
	}

	p.log.Infof("Retrieved %d domains from Aliyun", len(allDomains))
	return allDomains, nil
}

// getMapKeys 获取 map 的所有键（用于调试）
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// getDomainRecords 获取指定域名的 DNS 记录
func (p *AliyunProvider) getDomainRecords(ctx context.Context, domainName string) ([]AliyunDNSRecord, error) {
	params := map[string]string{
		"Action":     "DescribeDomainRecords",
		"Version":    "2015-01-09",
		"DomainName": domainName,
		"PageSize":   "100",
		"PageNumber": "1",
	}

	var allRecords []AliyunDNSRecord

	// 处理分页
	for pageNum := 1; pageNum <= 10; pageNum++ {
		params["PageNumber"] = fmt.Sprintf("%d", pageNum)

		result, err := p.makeRequest(ctx, "DescribeDomainRecords", params)
		if err != nil {
			if pageNum == 1 {
				return nil, err
			}
			break
		}

		recordsData, ok := result["DomainRecords"].(map[string]interface{})
		if !ok {
			if pageNum == 1 {
				p.log.Warnf("Invalid response format for domain records, result keys: %v", getMapKeys(result))
				return nil, fmt.Errorf("invalid response format: missing 'DomainRecords' field")
			}
			break
		}

		// 处理 Record 字段：可能是数组或单个对象
		var recordList []interface{}
		recordValue := recordsData["Record"]

		if recordValue == nil {
			if pageNum == 1 {
				p.log.Debugf("No records found for domain %s", domainName)
				return []AliyunDNSRecord{}, nil
			}
			break
		}

		switch v := recordValue.(type) {
		case []interface{}:
			// 多个记录，是数组
			recordList = v
		case map[string]interface{}:
			// 单个记录，是对象
			recordList = []interface{}{v}
		default:
			if pageNum == 1 {
				p.log.Warnf("Unexpected Record type: %T, value: %v", recordValue, recordValue)
				return nil, fmt.Errorf("invalid record list format: unexpected type %T", recordValue)
			}
			break
		}

		// 解析记录列表
		pageRecords := 0
		for _, recordData := range recordList {
			recordMap, ok := recordData.(map[string]interface{})
			if !ok {
				p.log.Warnf("Skipping invalid record data: %v", recordData)
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
			allRecords = append(allRecords, record)
			pageRecords++
		}

		// 如果这一页没有记录，说明已经获取完所有数据
		if pageRecords == 0 {
			break
		}

		// 如果这一页的记录数量少于 PageSize，说明已经是最后一页
		if pageRecords < 100 {
			break
		}
	}

	return allRecords, nil
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
		p.log.Errorf("Failed to parse Aliyun API response: %v, body: %s", err, string(body))
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		p.log.Errorf("Aliyun API returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
		return nil, fmt.Errorf("Aliyun API error: %d, body: %s", resp.StatusCode, string(body))
	}

	// 检查API错误
	if errorCode, exists := result["Code"]; exists {
		errorMsg, _ := result["Message"].(string)
		requestID, _ := result["RequestId"].(string)
		errMsg := fmt.Sprintf("Aliyun API error: %s - %s", errorCode, errorMsg)
		if requestID != "" {
			errMsg += fmt.Sprintf(" (RequestId: %s)", requestID)
		}
		p.log.Errorf("Aliyun API error: %s, response: %s", errMsg, string(body))
		return nil, fmt.Errorf("%s", errMsg)
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
