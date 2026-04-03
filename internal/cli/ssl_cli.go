package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ssl"
)

// parseSSLDomainFlags 解析 -domain / -d，可重复。
func parseSSLDomainFlags(args []string) ([]string, error) {
	var domains []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-domain", "-d":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("-domain 需要参数")
			}
			d := strings.TrimSpace(args[i+1])
			if d == "" {
				return nil, fmt.Errorf("domain 不能为空")
			}
			domains = append(domains, d)
			i++
		default:
			return nil, fmt.Errorf("未知参数: %q（续期/申请请使用 -domain <域名>，通配符请加引号，如 -domain '*.example.com'）", args[i])
		}
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("至少指定一个 -domain")
	}
	return domains, nil
}

func sslRenewOrRequest(cfg *config.Config, domains []string, preloadExisting bool) error {
	mgr, err := ssl.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("初始化 SSL 管理器失败: %w", err)
	}
	if !mgr.ACMEEnabled() {
		return fmt.Errorf("ACME 未启用：请在配置中设置 ssl.email（或环境变量 SSLCAT_SSL_EMAIL），并确保使用 ACME/Let's Encrypt（非纯自签名模式）")
	}

	var fail int
	for _, d := range domains {
		domain := strings.ToLower(strings.TrimSpace(d))
		if preloadExisting {
			_ = mgr.LoadCertificateFromDisk(domain)
		}
		fmt.Fprintf(os.Stdout, "正在处理 %s ...\n", domain)
		if err := mgr.EnsureDomainCert(domain); err != nil {
			fmt.Fprintf(os.Stderr, "❌ %s: %v\n", domain, err)
			fail++
			continue
		}
		fmt.Fprintf(os.Stdout, "✅ %s\n", domain)
	}
	if fail > 0 {
		return fmt.Errorf("%d 个域名失败", fail)
	}
	return nil
}

func sslListCerts(cfg *config.Config) error {
	mgr, err := ssl.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("初始化 SSL 管理器失败: %w", err)
	}
	list := mgr.ListCertificatesFromDisk()
	if len(list) == 0 {
		fmt.Println("（未找到证书文件，证书目录: " + cfg.SSL.CertDir + "）")
		return nil
	}
	fmt.Println("域名\t状态\t过期时间\t颁发者")
	for _, c := range list {
		exp := c.ExpiresAt.Format("2006-01-02")
		fmt.Printf("%s\t%s\t%s\t%s\n", c.Domain, c.Status, exp, c.Issuer)
	}
	return nil
}

func sslShowCert(cfg *config.Config, domain string) error {
	mgr, err := ssl.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("初始化 SSL 管理器失败: %w", err)
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, c := range mgr.ListCertificatesFromDisk() {
		if strings.EqualFold(c.Domain, domain) {
			fmt.Printf("域名: %s\n状态: %s\n颁发者: %s\n生效: %s\n过期: %s\n通配符: %v\n自签名: %v\n",
				c.Domain, c.Status, c.Issuer,
				c.IssuedAt.Format("2006-01-02 15:04:05"),
				c.ExpiresAt.Format("2006-01-02 15:04:05"),
				c.IsWildcard, c.SelfSigned)
			return nil
		}
	}
	return fmt.Errorf("未找到域名 %s 的证书（目录: %s）", domain, cfg.SSL.CertDir)
}

func sslDeleteCerts(cfg *config.Config, domains []string) error {
	mgr, err := ssl.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("初始化 SSL 管理器失败: %w", err)
	}
	var fail int
	for _, d := range domains {
		domain := strings.ToLower(strings.TrimSpace(d))
		fmt.Fprintf(os.Stdout, "正在删除 %s ...\n", domain)
		if err := mgr.DeleteCertificate(domain); err != nil {
			fmt.Fprintf(os.Stderr, "❌ %s: %v\n", domain, err)
			fail++
			continue
		}
		fmt.Fprintf(os.Stdout, "✅ 已删除 %s\n", domain)
	}
	if fail > 0 {
		return fmt.Errorf("%d 个域名删除失败", fail)
	}
	return nil
}
