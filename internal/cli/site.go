package cli

import (
	"fmt"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// RegisterSiteCommands 注册站点管理命令。
func (m *Manager) RegisterSiteCommands() {
	m.RegisterCommand(&Command{
		Name:        "site",
		Description: "Static/PHP site management",
		Handler: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("site subcommand required (list|add|update|delete|enable|disable)")
			}
			switch args[0] {
			case "list":
				return m.siteList(args[1:])
			case "add":
				return m.siteAdd(args[1:])
			case "update":
				return m.siteUpdate(args[1:])
			case "delete":
				return m.siteDelete(args[1:])
			case "enable":
				return m.siteToggle(args[1:], true)
			case "disable":
				return m.siteToggle(args[1:], false)
			default:
				return fmt.Errorf("unknown site subcommand: %s", args[0])
			}
		},
	})
}

func (m *Manager) siteList(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	if hasFlag(args, "--json", "-json") {
		return printJSON(map[string]interface{}{
			"static_sites": m.config.StaticSites,
			"php_sites":    m.config.PHPSites,
		})
	}

	fmt.Println("Static Sites:")
	if len(m.config.StaticSites) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, site := range m.config.StaticSites {
			fmt.Printf("  %-28s enabled=%v root=%s index=%s try_files=%v\n",
				site.Domain, site.Enabled, site.Root, site.Index, site.TryFiles)
		}
	}

	fmt.Println()
	fmt.Println("PHP Sites:")
	if len(m.config.PHPSites) == 0 {
		fmt.Println("  (none)")
	} else {
		for _, site := range m.config.PHPSites {
			fmt.Printf("  %-28s enabled=%v root=%s index=%s fcgi=%s\n",
				site.Domain, site.Enabled, site.Root, site.Index, site.FCGIAddr)
		}
	}
	return nil
}

func (m *Manager) siteAdd(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	flags := parseLooseFlags(args)
	siteType := normalizeSiteType(flags["type"])
	domain := strings.ToLower(strings.TrimSpace(flags["domain"]))
	root := cleanPath(flags["root"])
	if siteType == "" || domain == "" || root == "" {
		return fmt.Errorf("usage: sslcat site add --type static|php --domain <domain> --root <path> [--index index.html] [--fcgi 127.0.0.1:9000] [--disabled] [--try-files]")
	}
	if siteDomainExists(m.config, domain) {
		return fmt.Errorf("site %s already exists", domain)
	}

	enabled := !truthyFlag(flags, "disabled")
	index := nonEmptyString(flags["index"], defaultSiteIndex(siteType))
	switch siteType {
	case "static":
		m.config.StaticSites = append(m.config.StaticSites, config.StaticSite{
			Domain:   domain,
			Root:     root,
			Index:    index,
			Enabled:  enabled,
			TryFiles: truthyFlag(flags, "try-files"),
		})
	case "php":
		fcgi := nonEmptyString(flags["fcgi"], "127.0.0.1:9000")
		m.config.PHPSites = append(m.config.PHPSites, config.PHPSite{
			Domain:   domain,
			Root:     root,
			Index:    index,
			Enabled:  enabled,
			FCGIAddr: fcgi,
			Vars:     map[string]string{},
		})
	default:
		return fmt.Errorf("unsupported site type: %s", siteType)
	}

	if err := m.saveConfig(); err != nil {
		return err
	}
	fmt.Printf("✅ %s 站点已添加: %s\n", siteType, domain)
	return nil
}

func (m *Manager) siteUpdate(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	flags := parseLooseFlags(args)
	siteType := normalizeSiteType(flags["type"])
	domain := strings.ToLower(strings.TrimSpace(flags["domain"]))
	if siteType == "" || domain == "" {
		return fmt.Errorf("usage: sslcat site update --type static|php --domain <domain> [--root <path>] [--index <file>] [--fcgi <addr>] [--enabled|--disabled]")
	}

	switch siteType {
	case "static":
		idx := findStaticSite(m.config, domain)
		if idx < 0 {
			return fmt.Errorf("static site %s not found", domain)
		}
		site := &m.config.StaticSites[idx]
		if flags["root"] != "" {
			site.Root = cleanPath(flags["root"])
		}
		if flags["index"] != "" {
			site.Index = flags["index"]
		}
		applyEnabledFlag(&site.Enabled, flags)
		if truthyFlag(flags, "try-files") {
			site.TryFiles = true
		}
		if truthyFlag(flags, "no-try-files") {
			site.TryFiles = false
		}
	case "php":
		idx := findPHPSite(m.config, domain)
		if idx < 0 {
			return fmt.Errorf("php site %s not found", domain)
		}
		site := &m.config.PHPSites[idx]
		if flags["root"] != "" {
			site.Root = cleanPath(flags["root"])
		}
		if flags["index"] != "" {
			site.Index = flags["index"]
		}
		if flags["fcgi"] != "" {
			site.FCGIAddr = flags["fcgi"]
		}
		applyEnabledFlag(&site.Enabled, flags)
	default:
		return fmt.Errorf("unsupported site type: %s", siteType)
	}

	if err := m.saveConfig(); err != nil {
		return err
	}
	fmt.Printf("✅ %s 站点已更新: %s\n", siteType, domain)
	return nil
}

func (m *Manager) siteDelete(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	flags := parseLooseFlags(args)
	siteType := normalizeSiteType(flags["type"])
	domain := strings.ToLower(strings.TrimSpace(flags["domain"]))
	if siteType == "" || domain == "" {
		return fmt.Errorf("usage: sslcat site delete --type static|php --domain <domain> --yes")
	}
	if !truthyFlag(flags, "yes") {
		return fmt.Errorf("删除站点是不可逆操作，请确认后追加 --yes")
	}

	switch siteType {
	case "static":
		idx := findStaticSite(m.config, domain)
		if idx < 0 {
			return fmt.Errorf("static site %s not found", domain)
		}
		m.config.StaticSites = append(m.config.StaticSites[:idx], m.config.StaticSites[idx+1:]...)
	case "php":
		idx := findPHPSite(m.config, domain)
		if idx < 0 {
			return fmt.Errorf("php site %s not found", domain)
		}
		m.config.PHPSites = append(m.config.PHPSites[:idx], m.config.PHPSites[idx+1:]...)
	default:
		return fmt.Errorf("unsupported site type: %s", siteType)
	}

	if err := m.saveConfig(); err != nil {
		return err
	}
	fmt.Printf("✅ %s 站点已删除: %s\n", siteType, domain)
	return nil
}

func (m *Manager) siteToggle(args []string, enabled bool) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	flags := parseLooseFlags(args)
	siteType := normalizeSiteType(flags["type"])
	domain := strings.ToLower(strings.TrimSpace(flags["domain"]))
	if siteType == "" || domain == "" {
		return fmt.Errorf("usage: sslcat site %s --type static|php --domain <domain>", map[bool]string{true: "enable", false: "disable"}[enabled])
	}

	switch siteType {
	case "static":
		idx := findStaticSite(m.config, domain)
		if idx < 0 {
			return fmt.Errorf("static site %s not found", domain)
		}
		m.config.StaticSites[idx].Enabled = enabled
	case "php":
		idx := findPHPSite(m.config, domain)
		if idx < 0 {
			return fmt.Errorf("php site %s not found", domain)
		}
		m.config.PHPSites[idx].Enabled = enabled
	default:
		return fmt.Errorf("unsupported site type: %s", siteType)
	}

	if err := m.saveConfig(); err != nil {
		return err
	}
	state := "启用"
	if !enabled {
		state = "禁用"
	}
	fmt.Printf("✅ %s 站点已%s: %s\n", siteType, state, domain)
	return nil
}

func normalizeSiteType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "static", "html":
		return "static"
	case "php":
		return "php"
	default:
		return ""
	}
}

func defaultSiteIndex(siteType string) string {
	if siteType == "php" {
		return "index.php"
	}
	return "index.html"
}

func findStaticSite(cfg *config.Config, domain string) int {
	for i, site := range cfg.StaticSites {
		if strings.EqualFold(site.Domain, domain) {
			return i
		}
	}
	return -1
}

func findPHPSite(cfg *config.Config, domain string) int {
	for i, site := range cfg.PHPSites {
		if strings.EqualFold(site.Domain, domain) {
			return i
		}
	}
	return -1
}

func siteDomainExists(cfg *config.Config, domain string) bool {
	return findStaticSite(cfg, domain) >= 0 || findPHPSite(cfg, domain) >= 0
}

func truthyFlag(flags map[string]string, key string) bool {
	value, ok := flags[key]
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "true", "1", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func applyEnabledFlag(enabled *bool, flags map[string]string) {
	if truthyFlag(flags, "enabled") {
		*enabled = true
	}
	if truthyFlag(flags, "disabled") {
		*enabled = false
	}
}
