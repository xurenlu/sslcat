package ssl

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// AWSRoute53Provider AWS Route53 DNS服务商
type AWSRoute53Provider struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	client          *route53.Client
	log             Logger
}

// NewAWSRoute53Provider 创建AWS Route53 DNS服务商
func NewAWSRoute53Provider(accessKeyID, secretAccessKey, region string, log Logger) *AWSRoute53Provider {
	provider := &AWSRoute53Provider{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          region,
		log:             log,
	}
	
	// 初始化AWS客户端
	if err := provider.initClient(context.Background()); err != nil {
		log.Errorf("Failed to initialize AWS Route53 client: %v", err)
	}
	
	return provider
}

// initClient 初始化AWS Route53客户端
func (p *AWSRoute53Provider) initClient(ctx context.Context) error {
	// 创建AWS配置
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(p.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			p.AccessKeyID,
			p.SecretAccessKey,
			"",
		)),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	
	// 创建Route53客户端
	p.client = route53.NewFromConfig(cfg)
	return nil
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
	if p.Region == "" {
		p.Region = "us-east-1" // 默认区域
	}
	return nil
}

// getHostedZoneID 获取域名对应的Hosted Zone ID
func (p *AWSRoute53Provider) getHostedZoneID(ctx context.Context, domain string) (string, error) {
	if p.client == nil {
		if err := p.initClient(ctx); err != nil {
			return "", err
		}
	}
	
	// 规范化域名（确保以.结尾）
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	
	// 列出所有Hosted Zones
	result, err := p.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return "", fmt.Errorf("failed to list hosted zones: %w", err)
	}
	
	// 查找匹配的Hosted Zone
	for _, zone := range result.HostedZones {
		if zone.Name != nil && *zone.Name == domain {
			// 提取Zone ID（格式：/hostedzone/Z1234567890ABC）
			zoneID := *zone.Id
			if strings.HasPrefix(zoneID, "/hostedzone/") {
				zoneID = strings.TrimPrefix(zoneID, "/hostedzone/")
			}
			return zoneID, nil
		}
	}
	
	return "", fmt.Errorf("hosted zone not found for domain: %s", domain)
}

func (p *AWSRoute53Provider) SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error {
	if p.client == nil {
		if err := p.initClient(ctx); err != nil {
			return err
		}
	}
	
	// 获取Hosted Zone ID
	zoneID, err := p.getHostedZoneID(ctx, domain)
	if err != nil {
		return err
	}
	
	// 构建完整的记录名称
	recordName := name
	if !strings.HasSuffix(recordName, ".") {
		recordName = recordName + "."
	}
	
	// 确保值被引号包围（TXT记录要求）
	if !strings.HasPrefix(value, "\"") {
		value = "\"" + value + "\""
	}
	
	// 创建或更新TXT记录
	change := types.Change{
		Action: types.ChangeActionUpsert,
		ResourceRecordSet: &types.ResourceRecordSet{
			Name: aws.String(recordName),
			Type: types.RRTypeTxt,
			TTL:  aws.Int64(int64(ttl)),
			ResourceRecords: []types.ResourceRecord{
				{
					Value: aws.String(value),
				},
			},
		},
	}
	
	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{change},
			Comment: aws.String("ACME DNS-01 challenge"),
		},
	}
	
	result, err := p.client.ChangeResourceRecordSets(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to set TXT record: %w", err)
	}
	
	p.log.Infof("AWS Route53: TXT record set for %s, change ID: %s", recordName, *result.ChangeInfo.Id)
	return nil
}

func (p *AWSRoute53Provider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	if p.client == nil {
		if err := p.initClient(ctx); err != nil {
			return err
		}
	}
	
	// 获取Hosted Zone ID
	zoneID, err := p.getHostedZoneID(ctx, domain)
	if err != nil {
		return err
	}
	
	// 构建完整的记录名称
	recordName := name
	if !strings.HasSuffix(recordName, ".") {
		recordName = recordName + "."
	}
	
	// 首先获取现有记录
	value, err := p.GetTXTRecord(ctx, domain, name)
	if err != nil {
		// 如果记录不存在，直接返回成功
		p.log.Warnf("AWS Route53: TXT record %s not found, skipping deletion", recordName)
		return nil
	}
	
	// 确保值被引号包围
	if !strings.HasPrefix(value, "\"") {
		value = "\"" + value + "\""
	}
	
	// 删除TXT记录
	change := types.Change{
		Action: types.ChangeActionDelete,
		ResourceRecordSet: &types.ResourceRecordSet{
			Name: aws.String(recordName),
			Type: types.RRTypeTxt,
			TTL:  aws.Int64(300),
			ResourceRecords: []types.ResourceRecord{
				{
					Value: aws.String(value),
				},
			},
		},
	}
	
	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{change},
			Comment: aws.String("ACME DNS-01 challenge cleanup"),
		},
	}
	
	result, err := p.client.ChangeResourceRecordSets(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to delete TXT record: %w", err)
	}
	
	p.log.Infof("AWS Route53: TXT record deleted for %s, change ID: %s", recordName, *result.ChangeInfo.Id)
	return nil
}

func (p *AWSRoute53Provider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	if p.client == nil {
		if err := p.initClient(ctx); err != nil {
			return "", err
		}
	}
	
	// 获取Hosted Zone ID
	zoneID, err := p.getHostedZoneID(ctx, domain)
	if err != nil {
		return "", err
	}
	
	// 构建完整的记录名称
	recordName := name
	if !strings.HasSuffix(recordName, ".") {
		recordName = recordName + "."
	}
	
	// 列出记录集
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneID),
		StartRecordName: aws.String(recordName),
		StartRecordType: types.RRTypeTxt,
		MaxItems:        aws.Int32(1),
	}
	
	result, err := p.client.ListResourceRecordSets(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to list resource record sets: %w", err)
	}
	
	// 查找匹配的TXT记录
	for _, recordSet := range result.ResourceRecordSets {
		if recordSet.Name != nil && *recordSet.Name == recordName && recordSet.Type == types.RRTypeTxt {
			if len(recordSet.ResourceRecords) > 0 && recordSet.ResourceRecords[0].Value != nil {
				value := *recordSet.ResourceRecords[0].Value
				// 移除引号
				value = strings.Trim(value, "\"")
				return value, nil
			}
		}
	}
	
	return "", fmt.Errorf("TXT record not found: %s", recordName)
}

func (p *AWSRoute53Provider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	// AWS Route53的DNS传播通常很快，但我们还是等待一下确保安全
	maxAttempts := 30
	interval := 2 * time.Second
	
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// 检查记录是否已经传播
		currentValue, err := p.GetTXTRecord(ctx, domain, name)
		if err == nil && currentValue == value {
			p.log.Infof("AWS Route53: DNS propagation confirmed for %s", name)
			return nil
		}
		
		if attempt < maxAttempts-1 {
			p.log.Debugf("AWS Route53: Waiting for DNS propagation (attempt %d/%d)", attempt+1, maxAttempts)
			time.Sleep(interval)
		}
	}
	
	return fmt.Errorf("DNS propagation timeout after %d attempts", maxAttempts)
}

func (p *AWSRoute53Provider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	if p.client == nil {
		if err := p.initClient(ctx); err != nil {
			return nil, err
		}
	}
	
	// 列出所有Hosted Zones
	result, err := p.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list hosted zones: %w", err)
	}
	
	domains := make([]DomainInfo, 0, len(result.HostedZones))
	for _, zone := range result.HostedZones {
		if zone.Name != nil {
			domainName := strings.TrimSuffix(*zone.Name, ".")
			domains = append(domains, DomainInfo{
				Name:      domainName,
				Type:      "Zone",
				Status:    "active",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			})
		}
	}
	
	return domains, nil
}
