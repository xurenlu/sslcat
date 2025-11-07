package runner

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	defaultCredentialLength  = 16
	defaultCredentialCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// CredentialManager 负责生成与管理模板凭证
type CredentialManager struct {
	logger *logrus.Entry
}

// NewCredentialManager 创建凭证管理器
func NewCredentialManager(logger *logrus.Logger) *CredentialManager {
	entry := logger.WithField("component", "credential_manager")
	return &CredentialManager{logger: entry}
}

// Generate 根据模板定义生成凭证
func (cm *CredentialManager) Generate(meta TemplateMeta, appName string) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string)

	for service, rule := range meta.Credentials {
		values := make(map[string]string)

		// 默认 host 为服务名（Docker Compose 网络中的服务名）
		values["host"] = service

		// 查找服务的端口
		for _, svc := range meta.Services {
			if svc.Name == service && len(svc.Ports) > 0 {
				values["port"] = fmt.Sprintf("%d", svc.Ports[0].Internal)
				break
			}
		}

		if value, err := cm.renderPattern(rule.Username, appName); err == nil && value != "" {
			values["username"] = value
		} else if err != nil {
			return nil, fmt.Errorf("生成服务 %s 用户名失败: %w", service, err)
		}

		if value, err := cm.renderPattern(rule.Password, appName); err == nil && value != "" {
			values["password"] = value
		} else if err != nil {
			return nil, fmt.Errorf("生成服务 %s 密码失败: %w", service, err)
		}

		if value, err := cm.renderPattern(rule.Database, appName); err == nil && value != "" {
			values["database"] = value
		} else if err != nil {
			return nil, fmt.Errorf("生成服务 %s 数据库名失败: %w", service, err)
		}

		if value, err := cm.renderPattern(rule.Token, appName); err == nil && value != "" {
			values["token"] = value
		} else if err != nil {
			return nil, fmt.Errorf("生成服务 %s token 失败: %w", service, err)
		}

		if value, err := cm.renderPattern(rule.Secret, appName); err == nil && value != "" {
			values["secret"] = value
		} else if err != nil {
			return nil, fmt.Errorf("生成服务 %s secret 失败: %w", service, err)
		}

		if value, err := cm.renderPattern(rule.Endpoint, appName); err == nil && value != "" {
			values["endpoint"] = value
		} else if err != nil {
			return nil, fmt.Errorf("生成服务 %s endpoint 失败: %w", service, err)
		}

		if len(values) > 0 {
			result[service] = values
		}
	}

	return result, nil
}

func (cm *CredentialManager) renderPattern(pattern TemplateCredentialPattern, appName string) (string, error) {
	pat := strings.TrimSpace(pattern.Pattern)
	if pat == "" {
		return "", nil
	}

	switch strings.ToLower(pat) {
	case "random":
		length := pattern.Length
		if length <= 0 {
			length = defaultCredentialLength
		}

		charset := pattern.Charset
		if charset == "" {
			charset = defaultCredentialCharset
		}

		value, err := randomString(length, charset)
		if err != nil {
			return "", err
		}
		return pattern.Prefix + value + pattern.Suffix, nil
	default:
		replaced := strings.ReplaceAll(pat, "{app_name}", sanitizeAppName(appName))
		replaced = strings.ReplaceAll(replaced, "{APP_NAME}", sanitizeAppName(appName))
		return pattern.Prefix + replaced + pattern.Suffix, nil
	}
}

func sanitizeAppName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), " ", "-")
}

func randomString(length int, charset string) (string, error) {
	if length <= 0 {
		return "", nil
	}

	result := make([]byte, length)
	max := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}

	return string(result), nil
}
