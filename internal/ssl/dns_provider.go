package ssl

import (
	"context"
	"fmt"
	"sort"
)

// DNSProviderManager DNS服务商管理器
type DNSProviderManager struct {
	providers  map[string]DNSProviderInterface
	priorities map[string]int // 提供程序优先级
	log        Logger
}

// NewDNSProviderManager 创建DNS服务商管理器
func NewDNSProviderManager(log Logger) *DNSProviderManager {
	return &DNSProviderManager{
		providers:  make(map[string]DNSProviderInterface),
		priorities: make(map[string]int),
		log:        log,
	}
}

// RegisterProvider 注册DNS服务商
func (m *DNSProviderManager) RegisterProvider(name string, provider DNSProviderInterface) {
	m.RegisterProviderWithPriority(name, provider, 100) // 默认优先级
}

// RegisterProviderWithPriority 注册DNS服务商并设置优先级
func (m *DNSProviderManager) RegisterProviderWithPriority(name string, provider DNSProviderInterface, priority int) {
	m.providers[name] = provider
	m.priorities[name] = priority
	m.log.Infof("Registered DNS provider: %s with priority %d", name, priority)
}

// UnregisterProvider 注销DNS服务商
func (m *DNSProviderManager) UnregisterProvider(name string) {
	if _, exists := m.providers[name]; exists {
		delete(m.providers, name)
		delete(m.priorities, name)
		m.log.Infof("Unregistered DNS provider: %s", name)
	}
}

// ClearProviders 清空所有DNS服务商
func (m *DNSProviderManager) ClearProviders() {
	m.providers = make(map[string]DNSProviderInterface)
	m.priorities = make(map[string]int)
	m.log.Infof("Cleared all DNS providers")
}

// GetProvider 获取指定的DNS服务商
func (m *DNSProviderManager) GetProvider(name string) (DNSProviderInterface, error) {
	provider, exists := m.providers[name]
	if !exists {
		return nil, fmt.Errorf("DNS provider %s not found", name)
	}
	return provider, nil
}

// GetProviders 获取所有DNS服务商
func (m *DNSProviderManager) GetProviders() map[string]DNSProviderInterface {
	return m.providers
}

// GetProvidersSortedByPriority 按优先级排序获取DNS服务商
func (m *DNSProviderManager) GetProvidersSortedByPriority() []string {
	type providerPriority struct {
		name     string
		priority int
	}

	var providers []providerPriority
	for name, priority := range m.priorities {
		providers = append(providers, providerPriority{name: name, priority: priority})
	}

	// 按优先级排序（数字越小优先级越高）
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].priority < providers[j].priority
	})

	var sortedNames []string
	for _, p := range providers {
		sortedNames = append(sortedNames, p.name)
	}

	return sortedNames
}

// TestProvider 测试DNS服务商连接
func (m *DNSProviderManager) TestProvider(name string) error {
	provider, err := m.GetProvider(name)
	if err != nil {
		return err
	}

	// 验证配置
	if err := provider.Validate(); err != nil {
		return fmt.Errorf("provider validation failed: %w", err)
	}

	// 尝试获取域名列表
	ctx := context.Background()
	_, err = provider.ListDomains(ctx)
	if err != nil {
		return fmt.Errorf("failed to list domains: %w", err)
	}

	return nil
}

// SetTXTRecordWithFailover 使用故障转移机制设置TXT记录
func (m *DNSProviderManager) SetTXTRecordWithFailover(ctx context.Context, domain, name, value string, ttl int) error {
	sortedProviders := m.GetProvidersSortedByPriority()

	var lastErr error
	for _, providerName := range sortedProviders {
		provider, err := m.GetProvider(providerName)
		if err != nil {
			lastErr = err
			continue
		}

		err = provider.SetTXTRecord(ctx, domain, name, value, ttl)
		if err == nil {
			m.log.Infof("Successfully set TXT record using provider: %s", providerName)
			return nil
		}

		m.log.Warnf("Failed to set TXT record with provider %s: %v", providerName, err)
		lastErr = err
	}

	return fmt.Errorf("all DNS providers failed, last error: %w", lastErr)
}

// DeleteTXTRecordWithFailover 使用故障转移机制删除TXT记录
func (m *DNSProviderManager) DeleteTXTRecordWithFailover(ctx context.Context, domain, name string) error {
	sortedProviders := m.GetProvidersSortedByPriority()

	var lastErr error
	for _, providerName := range sortedProviders {
		provider, err := m.GetProvider(providerName)
		if err != nil {
			lastErr = err
			continue
		}

		err = provider.DeleteTXTRecord(ctx, domain, name)
		if err == nil {
			m.log.Infof("Successfully deleted TXT record using provider: %s", providerName)
			return nil
		}

		m.log.Warnf("Failed to delete TXT record with provider %s: %v", providerName, err)
		lastErr = err
	}

	return fmt.Errorf("all DNS providers failed, last error: %w", lastErr)
}

// WaitForPropagationWithFailover 使用故障转移机制等待DNS传播
func (m *DNSProviderManager) WaitForPropagationWithFailover(ctx context.Context, domain, name, value string) error {
	sortedProviders := m.GetProvidersSortedByPriority()

	var lastErr error
	for _, providerName := range sortedProviders {
		provider, err := m.GetProvider(providerName)
		if err != nil {
			lastErr = err
			continue
		}

		err = provider.WaitForPropagation(ctx, domain, name, value)
		if err == nil {
			m.log.Infof("DNS propagation completed using provider: %s", providerName)
			return nil
		}

		m.log.Warnf("DNS propagation failed with provider %s: %v", providerName, err)
		lastErr = err
	}

	return fmt.Errorf("all DNS providers failed, last error: %w", lastErr)
}

// GetProviderHealth 获取所有DNS服务商的健康状态
func (m *DNSProviderManager) GetProviderHealth() map[string]interface{} {
	health := make(map[string]interface{})

	for name, provider := range m.providers {
		status := map[string]interface{}{
			"name":     name,
			"priority": m.priorities[name],
			"healthy":  false,
			"error":    "",
		}

		// 验证配置
		if err := provider.Validate(); err != nil {
			status["error"] = err.Error()
		} else {
			// 尝试简单连接测试
			ctx := context.Background()
			_, err := provider.ListDomains(ctx)
			if err != nil {
				status["error"] = err.Error()
			} else {
				status["healthy"] = true
			}
		}

		health[name] = status
	}

	return health
}

// ListProviders 获取所有DNS提供商列表
func (m *DNSProviderManager) ListProviders() []string {
	var providers []string
	for name := range m.providers {
		providers = append(providers, name)
	}
	return providers
}

// CreateDNSChallengeWithFailover 使用故障转移机制创建DNS挑战
func (m *DNSProviderManager) CreateDNSChallengeWithFailover(ctx context.Context, domain, name, value string) (interface{}, error) {
	err := m.SetTXTRecordWithFailover(ctx, domain, name, value, 600)
	if err != nil {
		return nil, err
	}

	// 返回挑战信息
	return map[string]interface{}{
		"domain": domain,
		"name":   name,
		"value":  value,
		"type":   "dns-01",
	}, nil
}

// CreateDNSChallenge 使用指定提供商创建DNS挑战
func (m *DNSProviderManager) CreateDNSChallenge(ctx context.Context, domain, name, value, providerName string) (*DNSChallengeInfo, error) {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	err = provider.SetTXTRecord(ctx, domain, name, value, 600)
	if err != nil {
		return nil, err
	}

	return &DNSChallengeInfo{
		Domain: domain,
		Name:   name,
		Value:  value,
		Type:   "dns-01",
	}, nil
}

// CleanupDNSChallenge 清理DNS挑战记录
func (m *DNSProviderManager) CleanupDNSChallenge(ctx context.Context, challengeInfo interface{}) error {
	// 从挑战信息中提取域名和记录名
	if info, ok := challengeInfo.(map[string]interface{}); ok {
		domain := info["domain"].(string)
		name := info["name"].(string)
		return m.DeleteTXTRecordWithFailover(ctx, domain, name)
	}
	return fmt.Errorf("invalid challenge info")
}

// ValidateProvider 验证DNS提供商
func (m *DNSProviderManager) ValidateProvider(name string) error {
	provider, err := m.GetProvider(name)
	if err != nil {
		return err
	}
	return provider.Validate()
}

// GetDNSProviderHealth 获取DNS提供商健康状态
func (m *DNSProviderManager) GetDNSProviderHealth(ctx context.Context) map[string]string {
	health := m.GetProviderHealth()
	result := make(map[string]string)

	for name, status := range health {
		if statusMap, ok := status.(map[string]interface{}); ok {
			if healthy, ok := statusMap["healthy"].(bool); ok && healthy {
				result[name] = "healthy"
			} else if errorMsg, ok := statusMap["error"].(string); ok {
				result[name] = errorMsg
			} else {
				result[name] = "unknown"
			}
		}
	}

	return result
}

// DNSChallengeInfo DNS挑战信息
type DNSChallengeInfo struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	Type   string `json:"type"`
}

// GetACMEChallengeRecordNameForWildcard 获取通配符域名的ACME挑战记录名
func GetACMEChallengeRecordNameForWildcard(domain string) string {
	return "_acme-challenge"
}
