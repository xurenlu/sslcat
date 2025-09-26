package ssl

import (
	"context"
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

	// ListDomains 获取域名列表
	ListDomains(ctx context.Context) ([]DomainInfo, error)
}

// DomainInfo 域名信息
type DomainInfo struct {
	Name      string    `json:"name"`       // 域名
	Type      string    `json:"type"`       // 域名类型 (A, AAAA, CNAME, MX, TXT, etc.)
	Status    string    `json:"status"`     // 状态 (active, inactive, pending)
	CreatedAt time.Time `json:"created_at"` // 创建时间
	UpdatedAt time.Time `json:"updated_at"` // 更新时间
	TTL       int       `json:"ttl"`        // TTL值
	Value     string    `json:"value"`      // 记录值
}

// Logger 日志接口
type Logger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// 通用辅助函数
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
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t
		}
	}

	return time.Now()
}
