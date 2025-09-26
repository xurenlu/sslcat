package ssl

import (
	"context"
	"fmt"
)

// CustomProvider 自定义DNS服务商（占位符实现）
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
	return fmt.Errorf("Custom DNS API not implemented yet")
}

func (p *CustomProvider) DeleteTXTRecord(ctx context.Context, domain, name string) error {
	return fmt.Errorf("Custom DNS API not implemented yet")
}

func (p *CustomProvider) GetTXTRecord(ctx context.Context, domain, name string) (string, error) {
	return "", fmt.Errorf("Custom DNS API not implemented yet")
}

func (p *CustomProvider) WaitForPropagation(ctx context.Context, domain, name, value string) error {
	return fmt.Errorf("Custom DNS API not implemented yet")
}

func (p *CustomProvider) ListDomains(ctx context.Context) ([]DomainInfo, error) {
	// 暂时返回空结果，需要实现真实的自定义API调用
	return []DomainInfo{}, nil
}
