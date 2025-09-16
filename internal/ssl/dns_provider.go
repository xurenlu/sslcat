package ssl

import (
	"context"
	"fmt"
	"time"
)

// DNSProviderInterface DNS服务商接口
type DNSProviderInterface interface {
	// SetTXTRecord 设置TXT记录
	SetTXTRecord(ctx context.Context, domain, name, value string, ttl int) error
	
	// DeleteTXTRecord 删除TXT记录
	DeleteTXTRecord(ctx context.Context, domain, name string) error
	
	// GetTXTRecord 获取TXT记录值
	GetTXTRecord(ctx context.Context, domain, name string) (string, error)
	
	// WaitForPropagation 等待DNS记录传播
	WaitForPropagation(ctx context.Context, domain, name, value string) error
	
	// GetProviderName 获取服务商名称
	GetProviderName() string
	
	// Validate 验证配置
	Validate() error
}

// DNSProviderManager DNS服务商管理器
type DNSProviderManager struct {
	providers map[string]DNSProviderInterface
	log       Logger
}

type Logger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// NewDNSProviderManager 创建DNS服务商管理器
func NewDNSProviderManager(log Logger) *DNSProviderManager {
	return &DNSProviderManager{
		providers: make(map[string]DNSProviderInterface),
		log:       log,
	}
}

// RegisterProvider 注册DNS服务商
func (m *DNSProviderManager) RegisterProvider(name string, provider DNSProviderInterface) {
	m.providers[name] = provider
	m.log.Infof("Registered DNS provider: %s", name)
}

// GetProvider 获取DNS服务商
func (m *DNSProviderManager) GetProvider(name string) (DNSProviderInterface, error) {
	provider, exists := m.providers[name]
	if !exists {
		return nil, fmt.Errorf("DNS provider not found: %s", name)
	}
	return provider, nil
}

// ListProviders 列出所有可用的DNS服务商
func (m *DNSProviderManager) ListProviders() []string {
	var names []string
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}

// ValidateProvider 验证DNS服务商配置
func (m *DNSProviderManager) ValidateProvider(name string) error {
	provider, err := m.GetProvider(name)
	if err != nil {
		return err
	}
	return provider.Validate()
}

// SetTXTRecordWithProvider 使用指定服务商设置TXT记录
func (m *DNSProviderManager) SetTXTRecordWithProvider(ctx context.Context, providerName, domain, name, value string, ttl int) error {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return err
	}
	
	m.log.Infof("Setting TXT record via %s: %s.%s = %s", providerName, name, domain, value)
	return provider.SetTXTRecord(ctx, domain, name, value, ttl)
}

// DeleteTXTRecordWithProvider 使用指定服务商删除TXT记录
func (m *DNSProviderManager) DeleteTXTRecordWithProvider(ctx context.Context, providerName, domain, name string) error {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return err
	}
	
	m.log.Infof("Deleting TXT record via %s: %s.%s", providerName, name, domain)
	return provider.DeleteTXTRecord(ctx, domain, name)
}

// WaitForPropagationWithProvider 使用指定服务商等待DNS传播
func (m *DNSProviderManager) WaitForPropagationWithProvider(ctx context.Context, providerName, domain, name, value string) error {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return err
	}
	
	m.log.Infof("Waiting for DNS propagation via %s: %s.%s", providerName, name, domain)
	return provider.WaitForPropagation(ctx, domain, name, value)
}

// DNSChallengeInfo DNS挑战信息
type DNSChallengeInfo struct {
	Domain      string    `json:"domain"`
	RecordName  string    `json:"record_name"`
	RecordValue string    `json:"record_value"`
	Provider    string    `json:"provider"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// CreateDNSChallenge 创建DNS挑战记录
func (m *DNSProviderManager) CreateDNSChallenge(ctx context.Context, providerName, domain, recordName, recordValue string) (*DNSChallengeInfo, error) {
	// 设置TXT记录
	err := m.SetTXTRecordWithProvider(ctx, providerName, domain, recordName, recordValue, 60)
	if err != nil {
		return nil, fmt.Errorf("failed to set TXT record: %w", err)
	}
	
	// 等待DNS传播
	err = m.WaitForPropagationWithProvider(ctx, providerName, domain, recordName, recordValue)
	if err != nil {
		// 如果传播失败，尝试清理记录
		_ = m.DeleteTXTRecordWithProvider(ctx, providerName, domain, recordName)
		return nil, fmt.Errorf("DNS propagation failed: %w", err)
	}
	
	challenge := &DNSChallengeInfo{
		Domain:      domain,
		RecordName:  recordName,
		RecordValue: recordValue,
		Provider:    providerName,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour), // 24小时后过期
	}
	
	m.log.Infof("DNS challenge created successfully: %s.%s", recordName, domain)
	return challenge, nil
}

// CleanupDNSChallenge 清理DNS挑战记录
func (m *DNSProviderManager) CleanupDNSChallenge(ctx context.Context, challenge *DNSChallengeInfo) error {
	if challenge == nil {
		return nil
	}
	
	err := m.DeleteTXTRecordWithProvider(ctx, challenge.Provider, challenge.Domain, challenge.RecordName)
	if err != nil {
		m.log.Warnf("Failed to cleanup DNS challenge record %s.%s: %v", challenge.RecordName, challenge.Domain, err)
		return err
	}
	
	m.log.Infof("DNS challenge cleaned up: %s.%s", challenge.RecordName, challenge.Domain)
	return nil
}

// GetACMEChallengeRecordName 获取ACME挑战记录名称
func GetACMEChallengeRecordName(domain string) string {
	return fmt.Sprintf("_acme-challenge.%s", domain)
}

// GetACMEChallengeRecordNameForWildcard 获取通配符域名的ACME挑战记录名称
func GetACMEChallengeRecordNameForWildcard(domain string) string {
	// 对于 *.example.com，需要为 example.com 设置 _acme-challenge.example.com
	if domain[0] == '*' && domain[1] == '.' {
		return fmt.Sprintf("_acme-challenge.%s", domain[2:])
	}
	return GetACMEChallengeRecordName(domain)
}
