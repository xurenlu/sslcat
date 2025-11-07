package runner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DNSVerifier DNS 验证器
type DNSVerifier struct {
	logger *logrus.Entry
}

// NewDNSVerifier 创建 DNS 验证器
func NewDNSVerifier(logger *logrus.Logger) *DNSVerifier {
	return &DNSVerifier{
		logger: logger.WithField("component", "dns_verifier"),
	}
}

// DNSVerificationResult DNS 验证结果
type DNSVerificationResult struct {
	Domain      string            `json:"domain"`
	Resolved    bool              `json:"resolved"`
	IPAddresses []string          `json:"ip_addresses,omitempty"`
	Records     map[string]string `json:"records,omitempty"`
	Error       string            `json:"error,omitempty"`
	VerifiedAt  time.Time         `json:"verified_at"`
}

// VerifyDomain 验证域名 DNS 配置
func (dv *DNSVerifier) VerifyDomain(ctx context.Context, domain string) (*DNSVerificationResult, error) {
	result := &DNSVerificationResult{
		Domain:     domain,
		VerifiedAt: time.Now(),
		Records:    make(map[string]string),
	}

	// 解析 A 记录
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		result.Error = fmt.Sprintf("DNS 解析失败: %v", err)
		dv.logger.WithError(err).Warnf("域名 %s DNS 解析失败", domain)
		return result, nil // 不返回错误，只记录结果
	}

	result.Resolved = true
	result.IPAddresses = make([]string, 0, len(ips))
	for _, ip := range ips {
		result.IPAddresses = append(result.IPAddresses, ip.IP.String())
	}

	// 解析 CNAME 记录（如果存在）
	cname, err := net.DefaultResolver.LookupCNAME(ctx, domain)
	if err == nil && cname != "" && cname != domain+"." {
		result.Records["CNAME"] = cname
	}

	// 解析 MX 记录
	mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err == nil && len(mxRecords) > 0 {
		mxList := make([]string, 0, len(mxRecords))
		for _, mx := range mxRecords {
			mxList = append(mxList, fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
		}
		result.Records["MX"] = strings.Join(mxList, ", ")
	}

	// 解析 TXT 记录
	txtRecords, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err == nil && len(txtRecords) > 0 {
		result.Records["TXT"] = strings.Join(txtRecords, ", ")
	}

	return result, nil
}

// VerifyDomainPointsToServer 验证域名是否指向指定服务器 IP
func (dv *DNSVerifier) VerifyDomainPointsToServer(ctx context.Context, domain string, serverIPs []string) (bool, error) {
	result, err := dv.VerifyDomain(ctx, domain)
	if err != nil {
		return false, err
	}

	if !result.Resolved {
		return false, nil
	}

	// 检查是否有任何解析的 IP 匹配服务器 IP
	serverIPMap := make(map[string]bool)
	for _, ip := range serverIPs {
		serverIPMap[ip] = true
	}

	for _, resolvedIP := range result.IPAddresses {
		if serverIPMap[resolvedIP] {
			return true, nil
		}
	}

	return false, nil
}

// VerifyDomainWithTimeout 带超时的域名验证
func (dv *DNSVerifier) VerifyDomainWithTimeout(domain string, timeout time.Duration) (*DNSVerificationResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return dv.VerifyDomain(ctx, domain)
}

