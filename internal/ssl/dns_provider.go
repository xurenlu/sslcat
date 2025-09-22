package ssl

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
	providers  map[string]DNSProviderInterface
	priorities map[string]int // 提供程序优先级
	log        Logger
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
		providers:  make(map[string]DNSProviderInterface),
		priorities: make(map[string]int),
		log:        log,
	}
}

// RegisterProvider 注册DNS服务商
func (m *DNSProviderManager) RegisterProvider(name string, provider DNSProviderInterface) {
	m.RegisterProviderWithPriority(name, provider, 100) // 默认优先级100
}

// RegisterProviderWithPriority 注册带优先级的DNS服务商
func (m *DNSProviderManager) RegisterProviderWithPriority(name string, provider DNSProviderInterface, priority int) {
	m.providers[name] = provider
	m.priorities[name] = priority
	m.log.Infof("Registered DNS provider: %s (priority: %d)", name, priority)
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

	// 等待DNS传播，使用增强的监控
	err = m.WaitForPropagationWithEnhancedMonitoring(ctx, providerName, domain, recordName, recordValue)
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

// WaitForPropagationWithEnhancedMonitoring 使用增强监控等待DNS传播
func (m *DNSProviderManager) WaitForPropagationWithEnhancedMonitoring(ctx context.Context, providerName, domain, name, value string) error {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return err
	}

	m.log.Infof("Starting enhanced DNS propagation monitoring for %s.%s via %s", name, domain, providerName)

	// 根据提供程序类型设置不同的超时和检查间隔
	timeout, checkInterval := m.getProviderTimeoutAndInterval(providerName)

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	attempts := 0
	maxAttempts := int(timeout / checkInterval)

	for {
		attempts++
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("DNS propagation timeout for %s.%s after %v (attempted %d times)", name, domain, timeout, attempts)
		case <-ticker.C:
			// 检查记录值
			recordValue, err := provider.GetTXTRecord(ctx, domain, name)
			if err == nil && recordValue == value {
				m.log.Infof("DNS record propagated successfully: %s.%s = %s (attempt %d)", name, domain, value, attempts)
				return nil
			}

			// 记录详细状态
			if err != nil {
				m.log.Debugf("DNS propagation check %d/%d failed for %s.%s: %v", attempts, maxAttempts, name, domain, err)
			} else if recordValue != value {
				m.log.Debugf("DNS propagation check %d/%d: %s.%s = %s (expected %s)", attempts, maxAttempts, name, domain, recordValue, value)
			}

			// 如果接近超时，提供更多信息
			if attempts >= maxAttempts*3/4 {
				m.log.Warnf("DNS propagation taking longer than expected for %s.%s (attempt %d/%d)", name, domain, attempts, maxAttempts)
			}
		}
	}
}

// getProviderTimeoutAndInterval 根据提供程序类型获取超时和检查间隔
func (m *DNSProviderManager) getProviderTimeoutAndInterval(providerName string) (time.Duration, time.Duration) {
	switch strings.ToLower(providerName) {
	case "cloudflare":
		// Cloudflare通常传播很快
		return 60 * time.Second, 3 * time.Second
	case "aws", "route53":
		// AWS Route53传播较慢
		return 120 * time.Second, 5 * time.Second
	case "aliyun", "tencent":
		// 国内云服务商传播中等
		return 90 * time.Second, 4 * time.Second
	case "godaddy":
		// GoDaddy传播较慢
		return 120 * time.Second, 6 * time.Second
	default:
		// 默认设置
		return 90 * time.Second, 5 * time.Second
	}
}

// CleanupDNSChallenge 清理DNS挑战记录
func (m *DNSProviderManager) CleanupDNSChallenge(ctx context.Context, challenge *DNSChallengeInfo) error {
	if challenge == nil {
		return nil
	}

	// 使用带重试的清理机制
	err := m.cleanupWithRetry(ctx, challenge, 3)
	if err != nil {
		m.log.Warnf("Failed to cleanup DNS challenge record %s.%s after retries: %v", challenge.RecordName, challenge.Domain, err)
		return err
	}

	m.log.Infof("DNS challenge cleaned up: %s.%s", challenge.RecordName, challenge.Domain)
	return nil
}

// cleanupWithRetry 带重试的清理机制
func (m *DNSProviderManager) cleanupWithRetry(ctx context.Context, challenge *DNSChallengeInfo, maxRetries int) error {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := m.DeleteTXTRecordWithProvider(ctx, challenge.Provider, challenge.Domain, challenge.RecordName)
		if err == nil {
			return nil
		}

		lastErr = err
		m.log.Debugf("DNS cleanup attempt %d/%d failed for %s.%s: %v", attempt, maxRetries, challenge.RecordName, challenge.Domain, err)

		// 如果不是最后一次尝试，等待后重试
		if attempt < maxRetries {
			waitTime := time.Duration(attempt*2) * time.Second
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(waitTime):
				// 继续重试
			}
		}
	}

	return fmt.Errorf("cleanup failed after %d attempts: %w", maxRetries, lastErr)
}

// ValidateDNSChallenge 验证DNS挑战记录是否存在且正确
func (m *DNSProviderManager) ValidateDNSChallenge(ctx context.Context, challenge *DNSChallengeInfo) (bool, error) {
	if challenge == nil {
		return false, fmt.Errorf("challenge info is nil")
	}

	provider, err := m.GetProvider(challenge.Provider)
	if err != nil {
		return false, fmt.Errorf("failed to get provider: %w", err)
	}

	// 检查记录是否存在
	recordValue, err := provider.GetTXTRecord(ctx, challenge.Domain, challenge.RecordName)
	if err != nil {
		return false, fmt.Errorf("failed to get record: %w", err)
	}

	// 验证记录值是否匹配
	if recordValue != challenge.RecordValue {
		return false, fmt.Errorf("record value mismatch: expected %s, got %s", challenge.RecordValue, recordValue)
	}

	return true, nil
}

// GetDNSChallengeStatus 获取DNS挑战状态
func (m *DNSProviderManager) GetDNSChallengeStatus(ctx context.Context, challenge *DNSChallengeInfo) (*DNSChallengeStatus, error) {
	if challenge == nil {
		return nil, fmt.Errorf("challenge info is nil")
	}

	status := &DNSChallengeStatus{
		ChallengeInfo: challenge,
		CreatedAt:     challenge.CreatedAt,
		ExpiresAt:     challenge.ExpiresAt,
	}

	// 检查是否过期
	if time.Now().After(challenge.ExpiresAt) {
		status.Status = "expired"
		return status, nil
	}

	// 验证挑战记录
	valid, err := m.ValidateDNSChallenge(ctx, challenge)
	if err != nil {
		status.Status = "error"
		status.Error = err.Error()
		return status, nil
	}

	if valid {
		status.Status = "active"
	} else {
		status.Status = "invalid"
	}

	return status, nil
}

// DNSChallengeStatus DNS挑战状态
type DNSChallengeStatus struct {
	ChallengeInfo *DNSChallengeInfo `json:"challenge_info"`
	Status        string            `json:"status"` // active, invalid, expired, error
	Error         string            `json:"error,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
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

// GetProvidersByPriority 按优先级获取提供程序列表
func (m *DNSProviderManager) GetProvidersByPriority() []string {
	var providers []string
	for name := range m.providers {
		providers = append(providers, name)
	}

	// 按优先级排序（数字越小优先级越高）
	sort.Slice(providers, func(i, j int) bool {
		priorityI := m.priorities[providers[i]]
		priorityJ := m.priorities[providers[j]]
		return priorityI < priorityJ
	})

	return providers
}

// SetTXTRecordWithFailover 使用故障转移机制设置TXT记录
func (m *DNSProviderManager) SetTXTRecordWithFailover(ctx context.Context, domain, name, value string, ttl int) error {
	providers := m.GetProvidersByPriority()

	var lastErr error
	for _, providerName := range providers {
		m.log.Infof("Attempting to set TXT record via provider: %s", providerName)

		err := m.SetTXTRecordWithProvider(ctx, providerName, domain, name, value, ttl)
		if err == nil {
			m.log.Infof("Successfully set TXT record via provider: %s", providerName)
			return nil
		}

		lastErr = err
		m.log.Warnf("Failed to set TXT record via provider %s: %v", providerName, err)
	}

	return fmt.Errorf("all providers failed, last error: %w", lastErr)
}

// DeleteTXTRecordWithFailover 使用故障转移机制删除TXT记录
func (m *DNSProviderManager) DeleteTXTRecordWithFailover(ctx context.Context, domain, name string) error {
	providers := m.GetProvidersByPriority()

	var lastErr error
	successCount := 0

	for _, providerName := range providers {
		m.log.Infof("Attempting to delete TXT record via provider: %s", providerName)

		err := m.DeleteTXTRecordWithProvider(ctx, providerName, domain, name)
		if err == nil {
			successCount++
			m.log.Infof("Successfully deleted TXT record via provider: %s", providerName)
		} else {
			lastErr = err
			m.log.Warnf("Failed to delete TXT record via provider %s: %v", providerName, err)
		}
	}

	// 如果至少有一个提供程序成功，则认为删除成功
	if successCount > 0 {
		return nil
	}

	return fmt.Errorf("all providers failed to delete record, last error: %w", lastErr)
}

// CreateDNSChallengeWithFailover 使用故障转移机制创建DNS挑战
func (m *DNSProviderManager) CreateDNSChallengeWithFailover(ctx context.Context, domain, recordName, recordValue string) (*DNSChallengeInfo, error) {
	providers := m.GetProvidersByPriority()

	var lastErr error
	for _, providerName := range providers {
		m.log.Infof("Attempting to create DNS challenge via provider: %s", providerName)

		challenge, err := m.CreateDNSChallenge(ctx, providerName, domain, recordName, recordValue)
		if err == nil {
			m.log.Infof("Successfully created DNS challenge via provider: %s", providerName)
			return challenge, nil
		}

		lastErr = err
		m.log.Warnf("Failed to create DNS challenge via provider %s: %v", providerName, err)
	}

	return nil, fmt.Errorf("all providers failed to create challenge, last error: %w", lastErr)
}

// TestProvider 测试提供程序连接性
func (m *DNSProviderManager) TestProvider(ctx context.Context, providerName string) error {
	provider, err := m.GetProvider(providerName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	// 尝试获取一个测试记录来验证连接
	testDomain := "example.com"
	testName := "_test_connection"

	// 使用较短的超时进行测试
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, err = provider.GetTXTRecord(testCtx, testDomain, testName)
	// 我们期望这个记录不存在，所以任何非"记录不存在"的错误都是连接问题
	if err != nil && !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "not exist") {
		return fmt.Errorf("provider test failed: %w", err)
	}

	m.log.Infof("Provider %s test successful", providerName)
	return nil
}

// GetProviderHealth 获取提供程序健康状态
func (m *DNSProviderManager) GetProviderHealth(ctx context.Context) map[string]string {
	health := make(map[string]string)

	for providerName := range m.providers {
		err := m.TestProvider(ctx, providerName)
		if err == nil {
			health[providerName] = "healthy"
		} else {
			health[providerName] = "unhealthy: " + err.Error()
		}
	}

	return health
}
