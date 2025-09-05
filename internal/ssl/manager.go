package ssl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/notify"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Manager SSL证书管理器
type Manager struct {
	config     *config.Config
	certCache  map[string]*tls.Certificate
	certMutex  sync.RWMutex
	stopChan   chan struct{}
	log        *logrus.Entry
	notifier   *notify.Notifier
	lastNotify map[string]string
	acmeMgr    *autocert.Manager
	defaultCert *tls.Certificate
}

// NewManager 创建SSL管理器
func NewManager(cfg *config.Config) (*Manager, error) {
	log := logrus.WithFields(logrus.Fields{
		"component": "ssl_manager",
	})

	manager := &Manager{
		config:     cfg,
		certCache:  make(map[string]*tls.Certificate),
		stopChan:   make(chan struct{}),
		log:        log,
		notifier:   notify.NewFromEnv(),
		lastNotify: make(map[string]string),
	}

	// 初始化一个默认自签证书（用于未允许域名回退，避免写盘）
	if cert, err := manager.generateSelfSignedCert("localhost"); err == nil {
		manager.defaultCert = cert
	}

	// 初始化 ACME/Let's Encrypt（当配置了 Email 且仅允许配置域名时启用）
	if strings.TrimSpace(cfg.SSL.Email) != "" {
		acmeCacheDir := filepath.Join(filepath.Dir(cfg.SSL.CertDir), "acme-cache")
		if err := os.MkdirAll(acmeCacheDir, 0755); err != nil {
			log.Warnf("创建 ACME 缓存目录失败: %v", err)
		}

		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(acmeCacheDir),
			Email:  cfg.SSL.Email,
			HostPolicy: func(ctx context.Context, host string) error {
				host = strings.ToLower(host)
				if manager.isAllowedDomain(host) {
					return nil
				}
				return fmt.Errorf("acme: host not allowed: %s", host)
			},
		}

		client := &acme.Client{}
		if cfg.SSL.Staging {
			client.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		} else {
			client.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
		}
		m.Client = client
		manager.acmeMgr = m
		log.Infof("ACME 已启用（邮箱: %s, staging=%v）", cfg.SSL.Email, cfg.SSL.Staging)
	} else {
		log.Infof("ACME 未启用（未配置 ssl.email）")
	}

	return manager, nil
}

// CertificateInfo 证书信息
type CertificateInfo struct {
	Domain     string    `json:"domain"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Status     string    `json:"status"`
	IsWildcard bool      `json:"is_wildcard"`
	SelfSigned bool      `json:"self_signed"`
}

// GetCertificateList 获取证书列表
func (m *Manager) GetCertificateList() []CertificateInfo {
	m.certMutex.RLock()
	defer m.certMutex.RUnlock()

	var certs []CertificateInfo
	for domain, cert := range m.certCache {
		if cert != nil && len(cert.Certificate) > 0 {
			// 解析证书信息
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				continue
			}

			status := "有效"
			if time.Now().After(x509Cert.NotAfter) {
				status = "过期"
			} else if time.Now().Add(30 * 24 * time.Hour).After(x509Cert.NotAfter) {
				status = "即将过期"
			}

			selfSigned := x509Cert.Issuer.String() == x509Cert.Subject.String()

			certs = append(certs, CertificateInfo{
				Domain:     domain,
				IssuedAt:   x509Cert.NotBefore,
				ExpiresAt:  x509Cert.NotAfter,
				Status:     status,
				IsWildcard: strings.HasPrefix(domain, "*."),
				SelfSigned: selfSigned,
			})
		}
	}

	return certs
}

// DeleteCertificate 删除证书
func (m *Manager) DeleteCertificate(domain string) error {
	m.certMutex.Lock()
	defer m.certMutex.Unlock()

	// 从缓存中删除
	delete(m.certCache, domain)

	// 删除文件
	certFile := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyFile := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
		m.log.Warnf("删除证书文件失败 %s: %v", certFile, err)
	}

	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		m.log.Warnf("删除密钥文件失败 %s: %v", keyFile, err)
	}

	m.log.Infof("已删除域名 %s 的证书", domain)
	return nil
}

// Start 启动SSL管理器
func (m *Manager) Start() error {
	m.log.Info("启动SSL管理器")

	// 启动证书自动续期
	if m.config.SSL.AutoRenew {
		go m.autoRenewCerts()
	}
	// 周期性证书到期提醒
	go m.expiryNotifier()

	return nil
}

// Stop 停止SSL管理器
func (m *Manager) Stop() {
	m.log.Info("停止SSL管理器")
	close(m.stopChan)
}

// expiryNotifier 定期检查证书到期，分别在15/7/3天提醒一次
func (m *Manager) expiryNotifier() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.notifyExpiringCerts()
		case <-m.stopChan:
			return
		}
	}
}

func (m *Manager) notifyExpiringCerts() {
	certs := m.ListCertificatesFromDisk()
	for _, ci := range certs {
		days := int(time.Until(ci.ExpiresAt).Hours() / 24)
		if days == 15 || days == 7 || days == 3 {
			key := ci.Domain
			stamp := fmt.Sprintf("%d", days)
			if m.lastNotify[key] == stamp {
				continue
			}
			m.lastNotify[key] = stamp
			m.log.Warnf("证书即将到期: %s, %d 天后过期", ci.Domain, days)
			if m.notifier != nil && m.notifier.Enabled() {
				m.notifier.SendJSON(map[string]any{
					"ts":        time.Now().Format(time.RFC3339),
					"level":     "warn",
					"event":     "cert_expiring",
					"domain":    ci.Domain,
					"days_left": days,
				})
			}
		}
	}
}

// GetCertificate 获取指定域名的证书
func (m *Manager) GetCertificate(domain string) (*tls.Certificate, error) {
	// 首先检查是否有包含此域名的多域名证书
	m.certMutex.RLock()
	for cachedDomain, cert := range m.certCache {
		if m.domainMatchesCert(domain, cert) {
			m.certMutex.RUnlock()
			m.log.Debugf("域名 %s 匹配已缓存的证书 %s", domain, cachedDomain)
			return cert, nil
		}
	}
	m.certMutex.RUnlock()

	// 检查单域名证书
	m.certMutex.RLock()
	if cert, exists := m.certCache[domain]; exists {
		m.certMutex.RUnlock()
		return cert, nil
	}
	m.certMutex.RUnlock()

	// 尝试从文件加载证书
	certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				m.log.Errorf("加载证书失败 %s: %v", domain, err)
			} else {
				m.certMutex.Lock()
				m.certCache[domain] = &cert
				m.certMutex.Unlock()
				return &cert, nil
			}
		}
	}

	// 检查是否有通配符证书
	if wildcardCert := m.findWildcardCert(domain); wildcardCert != nil {
		return wildcardCert, nil
	}

	// 如果没有证书，生成自签名证书作为临时方案
	m.log.Infof("为域名 %s 生成自签名证书", domain)
	return m.generateSelfSignedCert(domain)
}

// generateSelfSignedCert 生成自签名证书
func (m *Manager) generateSelfSignedCert(domain string) (*tls.Certificate, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %w", err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("生成证书失败: %w", err)
	}

	// 编码私钥
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 编码证书
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// 保存证书和密钥
	certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		m.log.Errorf("保存证书失败: %v", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		m.log.Errorf("保存私钥失败: %v", err)
	}

	// 加载证书到内存
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	// 缓存证书
	m.certMutex.Lock()
	m.certCache[domain] = &cert
	m.certMutex.Unlock()

	m.log.Infof("成功生成并缓存域名 %s 的自签名证书", domain)
	return &cert, nil
}

// autoRenewCerts 自动续期证书
func (m *Manager) autoRenewCerts() {
	ticker := time.NewTicker(24 * time.Hour) // 每天检查一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.renewExpiringCerts()
		case <-m.stopChan:
			return
		}
	}
}

// renewExpiringCerts 续期即将过期的证书
func (m *Manager) renewExpiringCerts() {
	m.certMutex.RLock()
	domains := make([]string, 0, len(m.certCache))
	for domain := range m.certCache {
		domains = append(domains, domain)
	}
	m.certMutex.RUnlock()

	for _, domain := range domains {
		certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
		if _, err := os.Stat(certPath); err != nil {
			continue
		}

		// 检查证书是否即将过期（30天内）
		if m.isCertExpiringSoon(certPath) {
			m.log.Infof("证书即将过期，开始续期: %s", domain)
			if _, err := m.generateSelfSignedCert(domain); err != nil {
				m.log.Errorf("续期证书失败 %s: %v", domain, err)
			}
		}
	}
}

// isCertExpiringSoon 检查证书是否即将过期
func (m *Manager) isCertExpiringSoon(certPath string) bool {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	// 检查是否在30天内过期
	return time.Until(cert.NotAfter) < 30*24*time.Hour
}

// domainMatchesCert 检查域名是否匹配证书的SAN
func (m *Manager) domainMatchesCert(domain string, cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// 检查 CN
	if x509Cert.Subject.CommonName == domain {
		return true
	}

	// 检查 SAN (Subject Alternative Names)
	for _, dnsName := range x509Cert.DNSNames {
		if matchDomain(domain, dnsName) {
			return true
		}
	}

	return false
}

// findWildcardCert 查找匹配的通配符证书
func (m *Manager) findWildcardCert(domain string) *tls.Certificate {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil
	}

	// 尝试匹配 *.domain.com 格式的通配符证书
	wildcardDomain := "*." + strings.Join(parts[1:], ".")

	m.certMutex.RLock()
	defer m.certMutex.RUnlock()

	for cachedDomain, cert := range m.certCache {
		if cachedDomain == wildcardDomain || strings.Contains(cachedDomain, "*") {
			if m.domainMatchesCert(domain, cert) {
				m.log.Debugf("域名 %s 匹配通配符证书 %s", domain, cachedDomain)
				return cert
			}
		}
	}

	return nil
}

// matchDomain 域名匹配函数，支持通配符
func matchDomain(domain, pattern string) bool {
	if pattern == domain {
		return true
	}

	// 支持通配符匹配
	if strings.HasPrefix(pattern, "*.") {
		// 移除 "*." 前缀
		suffix := pattern[2:]
		// 检查域名是否以该后缀结尾，且前面只有一个子域名
		if strings.HasSuffix(domain, "."+suffix) {
			// 确保通配符只匹配一个级别的子域名
			prefix := strings.TrimSuffix(domain, "."+suffix)
			return !strings.Contains(prefix, ".")
		}
		// 直接匹配根域名
		return domain == suffix
	}

	return false
}

// GetTLSConfig 获取用于HTTPS服务器的TLS配置
func (m *Manager) GetTLSConfig() *tls.Config {
	// 若启用 ACME，优先使用 ACME 的证书获取逻辑（仅允许域名）
	if m.acmeMgr != nil {
		return &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				host := hello.ServerName
				if host == "" {
					host = "localhost"
				}
				if m.isAllowedDomain(host) {
					if cert, err := m.acmeMgr.GetCertificate(hello); err == nil {
						return cert, nil
					}
				}
				// 回退到本地（文件/缓存）或默认自签
				if cert, err := m.GetCertificate(host); err == nil {
					return cert, nil
				}
				if m.defaultCert != nil {
					return m.defaultCert, nil
				}
				return nil, fmt.Errorf("no certificate available for %s", host)
			},
			NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
			MinVersion: tls.VersionTLS12,
		}
	}

	// 默认：使用本地缓存/磁盘并在缺失时自签
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = "localhost"
			}
			if cert, err := m.GetCertificate(host); err == nil {
				return cert, nil
			}
			if m.defaultCert != nil {
				return m.defaultCert, nil
			}
			return nil, fmt.Errorf("no certificate available for %s", host)
		},
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
}

// HTTPChallengeHandler 包裹 HTTP 服务器以处理 ACME HTTP-01 挑战
func (m *Manager) HTTPChallengeHandler(h http.Handler) http.Handler {
	if m.acmeMgr != nil {
		return m.acmeMgr.HTTPHandler(h)
	}
	return h
}

// EnsureDomainCert 主动为指定域名申请（或加载）证书（当启用 ACME 时）
func (m *Manager) EnsureDomainCert(domain string) error {
	if m.acmeMgr == nil {
		return nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("empty domain")
	}
	if !m.isAllowedDomain(domain) {
		return fmt.Errorf("domain not allowed by policy: %s", domain)
	}
	_, err := m.acmeMgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil {
		m.log.Warnf("ACME 申请证书失败 %s: %v", domain, err)
	}
	return err
}

// isAllowedDomain 仅允许配置中的域名（代理规则或 ssl.domains）
func (m *Manager) isAllowedDomain(host string) bool {
	host = strings.ToLower(host)
	// 显式配置的 ssl.domains
	for _, d := range m.config.SSL.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if host == d || matchDomain(host, d) {
			return true
		}
	}
	// 代理规则中启用的域名
	for _, r := range m.config.Proxy.Rules {
		if !r.Enabled {
			continue
		}
		d := strings.ToLower(strings.TrimSpace(r.Domain))
		if d == "" {
			continue
		}
		if host == d || matchDomain(host, d) {
			return true
		}
	}
	return false
}

// GenerateMultiDomainCert 生成多域名自签名证书
func (m *Manager) GenerateMultiDomainCert(domains []string) (*tls.Certificate, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("域名列表不能为空")
	}

	primaryDomain := domains[0]
	m.log.Infof("为域名组 %v 生成多域名自签名证书", domains)

	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %w", err)
	}

	// 创建证书模板，支持多域名
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: primaryDomain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              domains, // 设置多个域名到SAN
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("生成证书失败: %w", err)
	}

	// 编码私钥
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 编码证书
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// 保存多域名证书 (使用主域名作为文件名)
	certPath := filepath.Join(m.config.SSL.CertDir, primaryDomain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, primaryDomain+".key")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		m.log.Errorf("保存证书失败: %v", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		m.log.Errorf("保存私钥失败: %v", err)
	}

	// 加载证书到内存
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	// 为所有域名缓存同一个证书
	m.certMutex.Lock()
	for _, domain := range domains {
		m.certCache[domain] = &cert
	}
	m.certMutex.Unlock()

	m.log.Infof("成功生成并缓存多域名证书: %v", domains)
	return &cert, nil
}

// LoadCertificateFromDisk 从磁盘加载指定域名证书到缓存
func (m *Manager) LoadCertificateFromDisk(domain string) error {
	certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	if _, err := os.Stat(certPath); err != nil {
		return fmt.Errorf("证书文件不存在: %s", certPath)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("私钥文件不存在: %s", keyPath)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("加载证书失败: %w", err)
	}

	m.certMutex.Lock()
	m.certCache[domain] = &cert
	m.certMutex.Unlock()
	m.log.Infof("已从磁盘加载证书到缓存: %s", domain)
	return nil
}

// ListCertificatesFromDisk 扫描证书目录获取证书信息
func (m *Manager) ListCertificatesFromDisk() []CertificateInfo {
	certDir := m.config.SSL.CertDir
	entries, err := os.ReadDir(certDir)
	if err != nil {
		m.log.Warnf("读取证书目录失败 %s: %v", certDir, err)
		return nil
	}

	var certs []CertificateInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".crt") {
			continue
		}
		domain := strings.TrimSuffix(name, ".crt")
		certPath := filepath.Join(certDir, name)
		pemBytes, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		status := "有效"
		if time.Now().After(x509Cert.NotAfter) {
			status = "过期"
		} else if time.Now().Add(30 * 24 * time.Hour).After(x509Cert.NotAfter) {
			status = "即将过期"
		}

		selfSigned := x509Cert.Issuer.String() == x509Cert.Subject.String()

		certs = append(certs, CertificateInfo{
			Domain:     domain,
			IssuedAt:   x509Cert.NotBefore,
			ExpiresAt:  x509Cert.NotAfter,
			Status:     status,
			IsWildcard: strings.HasPrefix(domain, "*."),
			SelfSigned: selfSigned,
		})
	}
	return certs
}
