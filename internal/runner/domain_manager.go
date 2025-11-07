package runner

import (
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
)

// DomainManager 负责管理应用域名列表
type DomainManager struct {
	logger *logrus.Entry
}

// NewDomainManager 创建域名管理器
func NewDomainManager(logger *logrus.Logger) *DomainManager {
	return &DomainManager{
		logger: logger.WithField("component", "domain_manager"),
	}
}

// SetPrimaryDomain 设置主域名，并保证在域名列表首位
func (dm *DomainManager) SetPrimaryDomain(app *GitApp, domain string) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return
	}

	aliases := dm.removeDomain(app.Domains, domain)
	app.Domain = domain
	app.Domains = append([]string{domain}, aliases...)
}

// AddDomainAlias 添加域名别名，返回是否新增
func (dm *DomainManager) AddDomainAlias(app *GitApp, domain string) bool {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false
	}

	for _, existing := range app.Domains {
		if strings.EqualFold(existing, domain) {
			return false
		}
	}

	app.Domains = append(app.Domains, domain)
	dm.sortDomains(app)
	return true
}

// RemoveDomainAlias 移除域名别名，返回是否删除
func (dm *DomainManager) RemoveDomainAlias(app *GitApp, domain string) bool {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false
	}

	if strings.EqualFold(app.Domain, domain) {
		return false
	}

	originalLen := len(app.Domains)
	app.Domains = dm.removeDomain(app.Domains, domain)
	return len(app.Domains) != originalLen
}

// EnsurePrimaryInList 确保主域名在列表首位
func (dm *DomainManager) EnsurePrimaryInList(app *GitApp) {
	if app.Domain == "" {
		return
	}
	app.Domains = append([]string{}, dm.removeDomain(app.Domains, app.Domain)...)
	app.Domains = append([]string{app.Domain}, app.Domains...)
}

func (dm *DomainManager) removeDomain(domains []string, target string) []string {
	clean := make([]string, 0, len(domains))
	for _, d := range domains {
		if !strings.EqualFold(d, target) && strings.TrimSpace(d) != "" {
			clean = append(clean, d)
		}
	}
	return clean
}

func (dm *DomainManager) sortDomains(app *GitApp) {
	if len(app.Domains) <= 1 {
		return
	}
	primary := app.Domain
	aliases := dm.removeDomain(app.Domains, primary)
	sort.Slice(aliases, func(i, j int) bool {
		return aliases[i] < aliases[j]
	})
	if primary != "" {
		app.Domains = append([]string{primary}, aliases...)
	} else {
		app.Domains = aliases
	}
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimSuffix(domain, "/")
	return domain
}
