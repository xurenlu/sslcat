package ssl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/notification"
	"github.com/xurenlu/sslcat/internal/notify"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// certMetadata 证书元数据缓存
type certMetadata struct {
	exists      bool      // 证书文件是否存在
	expiresAt   time.Time // 证书过期时间
	lastChecked time.Time // 最后检查时间
}

// Manager SSL证书管理器
type Manager struct {
	config        *config.Config
	certCache     map[string]*tls.Certificate
	certMutex     sync.RWMutex
	stopChan      chan struct{}
	log           *logrus.Entry
	notifier      *notify.Notifier
	lastNotify    map[string]string
	acmeMgr       *autocert.Manager
	defaultCert   *tls.Certificate
	onClientHello func(*tls.ClientHelloInfo)
	// 运行时临时允许 ACME 的域名（例如来自面板的手动申请），带过期时间
	tempAllowedDomains map[string]time.Time
	// DNS服务商管理器
	dnsManager *DNSProviderManager
	// 通知集成器
	notificationIntegrator *notification.NotificationIntegrator
	// 失败域名缓存：记录已知没有证书的域名，避免重复查找（TTL: 15分钟）
	failedDomainCache map[string]time.Time
	failedCacheMutex  sync.RWMutex
	// 证书元数据缓存：缓存证书文件存在性和有效期，避免频繁磁盘查找
	certMetadataCache map[string]*certMetadata
	metadataMutex     sync.RWMutex
}

// NewManager 创建SSL管理器
func NewManager(cfg *config.Config) (*Manager, error) {
	log := logrus.WithFields(logrus.Fields{
		"component": "ssl_manager",
	})

	manager := &Manager{
		config:             cfg,
		certCache:          make(map[string]*tls.Certificate),
		stopChan:           make(chan struct{}),
		log:                log,
		notifier:           notify.NewFromEnv(),
		lastNotify:         make(map[string]string),
		tempAllowedDomains: make(map[string]time.Time),
		dnsManager:         NewDNSProviderManager(log),
		failedDomainCache:  make(map[string]time.Time),
		certMetadataCache:  make(map[string]*certMetadata),
	}

	// 初始化一个默认自签证书（用于未允许域名回退，避免写盘）
	// 若禁用自签，则不生成默认证书
	if !cfg.SSL.DisableSelfSigned {
		if cert, err := manager.generateSelfSignedCert("localhost"); err == nil {
			manager.defaultCert = cert
		}
	}

	// 初始化DNS服务商
	manager.initializeDNSProviders()

	// 初始化 ACME/Let's Encrypt（当配置了 Email 且仅允许配置域名时启用）
	if strings.TrimSpace(cfg.SSL.Email) != "" {
		acmeCacheDir := filepath.Join(filepath.Dir(cfg.SSL.CertDir), "acme-cache")
		if err := os.MkdirAll(acmeCacheDir, 0755); err != nil {
			log.Warnf("Failed to create ACME cache directory: %v", err)
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
		log.Infof("ACME enabled (email: %s, staging=%v)", cfg.SSL.Email, cfg.SSL.Staging)
	} else {
		log.Infof("ACME disabled (ssl.email not configured)")
	}

	// 启动失败缓存清理 goroutine
	go manager.cleanFailedCache()
	// 启动证书元数据缓存清理 goroutine
	go manager.cleanCertMetadataCache()

	return manager, nil
}

// SetNotificationIntegrator 设置通知集成器
func (m *Manager) SetNotificationIntegrator(integrator *notification.NotificationIntegrator) {
	m.notificationIntegrator = integrator
}

// CertificateInfo 证书信息
type CertificateInfo struct {
	Domain     string    `json:"domain"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Status     string    `json:"status"`
	IsWildcard bool      `json:"is_wildcard"`
	SelfSigned bool      `json:"self_signed"`
	Issuer     string    `json:"issuer"`
}

// GetCertificateList 获取证书列表（内存缓存+磁盘聚合）
func (m *Manager) GetCertificateList() []CertificateInfo {
	// 使用 ListCertificatesFromDisk 来获取所有证书（包括磁盘和内存缓存）
	// 这样可以确保显示所有存在的证书文件，而不仅仅是内存缓存中的
	return m.ListCertificatesFromDisk()
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
		m.log.Warnf("Failed to remove certificate file %s: %v", certFile, err)
	}

	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		m.log.Warnf("Failed to remove private key file %s: %v", keyFile, err)
	}

	m.log.Infof("Deleted certificate for domain %s", domain)
	return nil
}

// Start 启动SSL管理器
func (m *Manager) Start() error {
	m.log.Info("Starting SSL manager")

	// 启动证书自动续期
	if m.config.SSL.AutoRenew {
		go m.autoRenewCerts()
	}
	// 周期性证书到期提醒
	go m.expiryNotifier()

	// 周期性从 acme-cache 同步证书到 certs/keys（每13分钟，因为申请成功后会立即同步）
	go func() {
		ticker := time.NewTicker(13 * time.Minute) // 使用质数间隔避免与其他定时器同时触发
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := m.SyncACMECertsToDisk(); err != nil {
					m.log.Debugf("ACME sync skipped or failed: %v", err)
				}
			case <-m.stopChan:
				return
			}
		}
	}()

	return nil
}

// Stop 停止SSL管理器
func (m *Manager) Stop() {
	m.log.Info("Stopping SSL manager")
	close(m.stopChan)
}

// cleanFailedCache 定期清理过期的失败缓存条目
func (m *Manager) cleanFailedCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			m.failedCacheMutex.Lock()
			cleaned := 0
			for domain, expireTime := range m.failedDomainCache {
				if now.After(expireTime) {
					delete(m.failedDomainCache, domain)
					cleaned++
				}
			}
			m.failedCacheMutex.Unlock()
			if cleaned > 0 {
				m.log.Debugf("Cleaned %d expired failed domain cache entries", cleaned)
			}
		case <-m.stopChan:
			return
		}
	}
}

// cleanCertMetadataCache 定期清理过期的证书元数据缓存条目
func (m *Manager) cleanCertMetadataCache() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			m.metadataMutex.Lock()
			cleaned := 0
			for domain, metadata := range m.certMetadataCache {
				// 清理超过1小时未检查的元数据，或已过期的证书元数据
				if now.Sub(metadata.lastChecked) > 1*time.Hour || now.After(metadata.expiresAt) {
					delete(m.certMetadataCache, domain)
					cleaned++
				}
			}
			m.metadataMutex.Unlock()
			if cleaned > 0 {
				m.log.Debugf("Cleaned %d expired certificate metadata cache entries", cleaned)
			}
		case <-m.stopChan:
			return
		}
	}
}

// getCertMetadata 获取证书元数据（优先从缓存，避免磁盘查找）
func (m *Manager) getCertMetadata(domain string) *certMetadata {
	m.metadataMutex.RLock()
	metadata, exists := m.certMetadataCache[domain]
	m.metadataMutex.RUnlock()

	// 如果缓存存在且未过期（1小时内检查过），直接返回
	if exists && time.Since(metadata.lastChecked) < 1*time.Hour {
		return metadata
	}

	// 缓存不存在或已过期，检查磁盘
	certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	metadata = &certMetadata{
		exists:      false,
		lastChecked: time.Now(),
	}

	// 检查文件是否存在
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			metadata.exists = true
			// 尝试读取证书获取过期时间（不加载完整证书，只解析元数据）
			if certData, err := os.ReadFile(certPath); err == nil {
				if block, _ := pem.Decode(certData); block != nil {
					if x509Cert, err := x509.ParseCertificate(block.Bytes); err == nil {
						metadata.expiresAt = x509Cert.NotAfter
					}
				}
			}
		}
	}

	// 更新缓存
	m.metadataMutex.Lock()
	m.certMetadataCache[domain] = metadata
	m.metadataMutex.Unlock()

	return metadata
}

// updateCertMetadata 更新证书元数据缓存（在证书加载/刷新时调用）
func (m *Manager) updateCertMetadata(domain string, cert *tls.Certificate) {
	if cert == nil || len(cert.Certificate) == 0 {
		return
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	m.metadataMutex.Lock()
	m.certMetadataCache[domain] = &certMetadata{
		exists:      true,
		expiresAt:   x509Cert.NotAfter,
		lastChecked: time.Now(),
	}
	m.metadataMutex.Unlock()
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
			m.log.Warnf("Certificate expiring soon: %s, expires in %d days", ci.Domain, days)

			// 发送新通知系统通知
			if m.notificationIntegrator != nil {
				m.notificationIntegrator.SendCertExpiringNotification(ci.Domain, days)
			}

			// 保留原有通知系统
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
	// 检查失败缓存，避免重复查找已知没有证书的域名
	m.failedCacheMutex.RLock()
	if expireTime, exists := m.failedDomainCache[domain]; exists {
		if time.Now().Before(expireTime) {
			// 仍在缓存期内，直接返回错误，避免重复查找
			m.failedCacheMutex.RUnlock()
			// 不记录日志，避免日志刷屏
			return nil, fmt.Errorf("no certificate for %s (cached failure)", domain)
		}
		// 缓存已过期，删除过期条目
		m.failedCacheMutex.RUnlock()
		m.failedCacheMutex.Lock()
		delete(m.failedDomainCache, domain)
		m.failedCacheMutex.Unlock()
	} else {
		m.failedCacheMutex.RUnlock()
	}

	// 首先检查是否有包含此域名的多域名证书
	m.certMutex.RLock()
	for cachedDomain, cert := range m.certCache {
		if m.domainMatchesCert(domain, cert) {
			m.certMutex.RUnlock()
			m.log.Debugf("Domain %s matches cached certificate %s", domain, cachedDomain)
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

	// 使用元数据缓存检查证书是否存在，避免频繁磁盘查找
	metadata := m.getCertMetadata(domain)
	if !metadata.exists {
		// 证书不存在，添加到失败缓存
		m.failedCacheMutex.Lock()
		m.failedDomainCache[domain] = time.Now().Add(15 * time.Minute)
		m.failedCacheMutex.Unlock()
		return nil, fmt.Errorf("no certificate for %s", domain)
	}

	// 证书文件存在，从磁盘加载
	certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		m.log.Errorf("Failed to load certificate %s: %v", domain, err)
		// 加载失败，更新元数据缓存标记为不存在
		m.metadataMutex.Lock()
		m.certMetadataCache[domain] = &certMetadata{
			exists:      false,
			lastChecked: time.Now(),
		}
		m.metadataMutex.Unlock()
		return nil, err
	}

	// 加载成功，更新证书缓存和元数据缓存
	m.certMutex.Lock()
	m.certCache[domain] = &cert
	m.certMutex.Unlock()
	m.updateCertMetadata(domain, &cert)

	// 清除失败缓存（如果存在）
	m.failedCacheMutex.Lock()
	delete(m.failedDomainCache, domain)
	m.failedCacheMutex.Unlock()

	return &cert, nil
}

// generateSelfSignedCert 生成自签名证书
func (m *Manager) generateSelfSignedCert(domain string) (*tls.Certificate, error) {
	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
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
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
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
		m.log.Errorf("Failed to save certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		m.log.Errorf("Failed to save private key: %v", err)
	}

	// 加载证书到内存
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 缓存证书
	m.certMutex.Lock()
	m.certCache[domain] = &cert
	m.certMutex.Unlock()
	m.updateCertMetadata(domain, &cert) // 更新元数据缓存

	m.log.Infof("Successfully generated and cached self-signed certificate for %s", domain)
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
	// 从磁盘扫描所有证书文件，而不仅仅是内存缓存
	// 这样可以确保所有证书都会被检查续期，即使没有被访问过
	certDir := m.config.SSL.CertDir
	entries, err := os.ReadDir(certDir)
	if err != nil {
		m.log.Warnf("Failed to read certificate directory for renewal check: %v", err)
		return
	}

	var domains []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".crt") {
			continue
		}
		domain := strings.TrimSuffix(name, ".crt")
		domains = append(domains, domain)
	}

	m.log.Infof("Checking %d certificates for renewal", len(domains))

	for _, domain := range domains {
		certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")

		// 检查证书是否即将过期（30天内）
		if m.isCertExpiringSoon(certPath) {
			m.log.Infof("Certificate expiring soon, starting renewal: %s", domain)
			if m.config.SSL.DisableSelfSigned {
				if m.acmeMgr != nil && m.isAllowedDomain(domain) {
					if _, err := m.acmeMgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain}); err != nil {
						m.log.Errorf("ACME renewal failed %s: %v", domain, err)

						// 发送证书续期失败通知
						if m.notificationIntegrator != nil {
							m.notificationIntegrator.SendCertFailedNotification(domain, fmt.Sprintf("自动续期失败: %v", err))
						}
					} else {
						m.log.Infof("ACME renewal triggered: %s", domain)

						// 同步ACME证书到磁盘
						if _, syncErr := m.SyncACMECertsToDisk(); syncErr != nil {
							m.log.Debugf("ACME post-renewal sync failed: %v", syncErr)
						}

						// 发送证书续期成功通知
						if m.notificationIntegrator != nil {
							m.notificationIntegrator.SendCertSuccessNotification(domain, 1, 0)
						}
					}
				} else {
					m.log.Warnf("Self-signed renewal disabled; ACME unavailable or domain not allowed: %s", domain)
				}
				continue
			}
			if _, err := m.generateSelfSignedCert(domain); err != nil {
				m.log.Errorf("Failed to renew certificate %s: %v", domain, err)
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
				m.log.Debugf("Domain %s matches wildcard certificate %s", domain, cachedDomain)
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

// SetOnClientHello 设置客户端握手钩子
func (m *Manager) SetOnClientHello(fn func(*tls.ClientHelloInfo)) {
	m.onClientHello = fn
}

// GetTLSConfig 获取用于HTTPS服务器的TLS配置
func (m *Manager) GetTLSConfig() *tls.Config {
	// 若启用 ACME，优先使用 ACME 的证书获取逻辑（仅允许域名）
	if m.acmeMgr != nil {
		return &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if m.onClientHello != nil {
					m.onClientHello(hello)
				}
			host := hello.ServerName
			if host == "" {
				host = "localhost"
			}
			if m.isAllowedDomain(host) {
				if cert, err := m.acmeMgr.GetCertificate(hello); err == nil {
					domain := strings.ToLower(host)
					
					// 检查是否需要持久化（只在首次获取或证书更新时）
					needsPersist := false
					m.certMutex.RLock()
					existingCert, exists := m.certCache[domain]
					if !exists {
						// 首次获取，需要持久化
						needsPersist = true
					} else if existingCert != nil && len(existingCert.Certificate) > 0 && len(cert.Certificate) > 0 {
						// 检查证书是否更新（比较证书内容）
						if !bytes.Equal(existingCert.Certificate[0], cert.Certificate[0]) {
							needsPersist = true
						}
					}
					m.certMutex.RUnlock()
					
					// 将 autocert 获取的证书加载到内存缓存中
					m.certMutex.Lock()
					m.certCache[domain] = cert
					m.certMutex.Unlock()
					m.updateCertMetadata(domain, cert)
					
					// 只在需要时持久化到磁盘
					if needsPersist {
						go func(d string, certificate *tls.Certificate) {
							if err := m.saveCertificateToDisk(d, certificate); err != nil {
								m.log.Warnf("Failed to save certificate to disk for %s: %v", d, err)
							} else {
								m.log.Infof("Certificate saved to disk for %s", d)
							}
						}(domain, cert)
					}
					
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
			MaxVersion: tls.VersionTLS13,
		}
	}

	// 默认：使用本地缓存/磁盘并在缺失时自签
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if m.onClientHello != nil {
				m.onClientHello(hello)
			}
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
		MaxVersion: tls.VersionTLS13,
	}
}

// HTTPChallengeHandler 包裹 HTTP 服务器以处理 ACME HTTP-01 挑战
func (m *Manager) HTTPChallengeHandler(h http.Handler) http.Handler {
	if m.acmeMgr != nil {
		return m.acmeMgr.HTTPHandler(h)
	}
	return h
}

// EnableACME 运行中启用/重建 ACME 管理器（根据当前配置）
func (m *Manager) EnableACME() error {
	email := strings.TrimSpace(m.config.SSL.Email)
	if email == "" {
		return fmt.Errorf("empty acme email")
	}
	acmeCacheDir := filepath.Join(filepath.Dir(m.config.SSL.CertDir), "acme-cache")
	if err := os.MkdirAll(acmeCacheDir, 0755); err != nil {
		m.log.Warnf("Failed to create ACME cache directory: %v", err)
	}
	mgr := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(acmeCacheDir),
		Email:  email,
		HostPolicy: func(ctx context.Context, host string) error {
			host = strings.ToLower(host)
			if m.isAllowedDomain(host) {
				return nil
			}
			return fmt.Errorf("acme: host not allowed: %s", host)
		},
	}
	client := &acme.Client{}
	if m.config.SSL.Staging {
		client.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	} else {
		client.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	mgr.Client = client
	m.acmeMgr = mgr
	m.log.Infof("ACME enabled (email: %s, staging=%v)", email, m.config.SSL.Staging)
	return nil
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

	// 使用智能重试机制申请证书
	return m.ensureDomainCertWithRetry(domain, 3) // 最多重试3次
}

// ensureDomainCertWithRetry 带重试机制的证书申请
func (m *Manager) ensureDomainCertWithRetry(domain string, maxRetries int) error {
	var lastErr error
	startTime := time.Now()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		attemptStart := time.Now()
		m.log.Infof("Certificate request attempt %d/%d for domain: %s", attempt, maxRetries, domain)

		// 第一次尝试时检查域名解析
		if attempt == 1 {
			dnsCheckStart := time.Now()
			if resolved, info, err := m.checkDomainResolution(domain); err != nil {
				m.log.Warnf("Domain resolution check failed for %s: %v", domain, err)
			} else {
				dnsCheckDuration := time.Since(dnsCheckStart)
				m.log.Infof("Domain resolution check for %s: %s (耗时: %v)", domain, info, dnsCheckDuration)
				if !resolved {
					m.log.Warnf("Domain %s may not resolve to this server, HTTP-01 validation might fail", domain)
				}
			}
		}

		// 临时放行该域名以触发申请（避免必须写入配置）
		m.AllowDomainTemporary(domain, 24*time.Hour)

		// 尝试HTTP-01验证
		acmeStart := time.Now()
		_, err := m.acmeMgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		acmeDuration := time.Since(acmeStart)

		if err == nil {
			// 申请成功，同步证书
			syncStart := time.Now()
			if _, syncErr := m.SyncACMECertsToDisk(); syncErr != nil {
				m.log.Debugf("ACME post-issue sync failed: %v", syncErr)
			}
			syncDuration := time.Since(syncStart)

			totalDuration := time.Since(startTime)
			m.log.Infof("Certificate request successful for domain: %s (attempt %d, ACME耗时: %v, 同步耗时: %v, 总耗时: %v)",
				domain, attempt, acmeDuration, syncDuration, totalDuration)

			// 发送证书申请成功通知
			if m.notificationIntegrator != nil {
				m.notificationIntegrator.SendCertSuccessNotification(domain, attempt, totalDuration)
			}

			return nil
		}

		attemptDuration := time.Since(attemptStart)
		lastErr = err

		// 提供更详细的错误信息
		errMsg := err.Error()
		if strings.Contains(errMsg, "missing certificate") {
			m.log.Warnf("HTTP-01 validation failed for %s (attempt %d, 耗时: %v): %v", domain, attempt, attemptDuration, err)
			m.log.Warnf("可能原因: 1) 域名DNS未解析到此服务器 2) 防火墙阻止80端口 3) 服务器未在standard模式监听80端口 4) Let's Encrypt无法访问验证端点")
		} else {
			m.log.Warnf("HTTP-01 validation failed for %s (attempt %d, 耗时: %v): %v", domain, attempt, attemptDuration, err)
		}

		// 如果HTTP-01失败且配置了DNS服务商，尝试DNS-01验证
		if m.supportsDNSChallenge() && m.hasAvailableDNSProvider() {
			dnsStart := time.Now()
			m.log.Infof("Attempting DNS-01 validation for domain: %s", domain)
			if dnsErr := m.tryDNSValidation(domain); dnsErr == nil {
				dnsDuration := time.Since(dnsStart)
				totalDuration := time.Since(startTime)
				m.log.Infof("DNS-01 validation successful for domain: %s (DNS耗时: %v, 总耗时: %v)", domain, dnsDuration, totalDuration)

				// 发送证书申请成功通知
				if m.notificationIntegrator != nil {
					m.notificationIntegrator.SendCertSuccessNotification(domain, attempt, totalDuration)
				}

				return nil
			} else {
				dnsDuration := time.Since(dnsStart)
				m.log.Warnf("DNS-01 validation also failed for %s (耗时: %v): %v", domain, dnsDuration, dnsErr)
			}
		}

		// 如果不是最后一次尝试，等待一段时间后重试
		if attempt < maxRetries {
			waitTime := time.Duration(attempt*10) * time.Second // 递增等待时间
			m.log.Infof("Waiting %v before retry for domain: %s", waitTime, domain)
			time.Sleep(waitTime)
		}
	}

	totalDuration := time.Since(startTime)
	m.log.Errorf("All certificate request attempts failed for domain: %s, last error: %v (总耗时: %v)", domain, lastErr, totalDuration)

	// 提供诊断建议
	errMsg := lastErr.Error()
	var diagnosticTips string
	if strings.Contains(errMsg, "missing certificate") {
		diagnosticTips = "诊断建议: 1) 检查域名DNS解析: nslookup " + domain + " 2) 检查80端口可访问性: curl -I http://" + domain + "/.well-known/acme-challenge/test 3) 确认服务器在standard模式监听80/443端口 4) 检查防火墙规则"
		m.log.Warnf("证书申请失败诊断: %s", diagnosticTips)
	}

	// 发送证书申请失败通知
	if m.notificationIntegrator != nil {
		reason := fmt.Sprintf("申请失败，尝试了%d次，总耗时%v，最后错误: %v", maxRetries, totalDuration, lastErr)
		if diagnosticTips != "" {
			reason += " | " + diagnosticTips
		}
		m.notificationIntegrator.SendCertFailedNotification(domain, reason)
	}

	return fmt.Errorf("certificate request failed after %d attempts: %w", maxRetries, lastErr)
}

// hasAvailableDNSProvider 检查是否有可用的DNS服务商
func (m *Manager) hasAvailableDNSProvider() bool {
	providers := m.dnsManager.ListProviders()
	return len(providers) > 0
}

// tryDNSValidation 尝试使用DNS验证申请证书
func (m *Manager) tryDNSValidation(domain string) error {
	providers := m.dnsManager.ListProviders()
	if len(providers) == 0 {
		return fmt.Errorf("no DNS providers available")
	}

	// 使用第一个可用的DNS服务商
	providerName := providers[0]
	m.log.Infof("Using DNS provider: %s for domain: %s", providerName, domain)

	return m.RequestCertificateWithDNS(domain, providerName)
}

// checkDomainResolution 检查域名解析状态
func (m *Manager) checkDomainResolution(domain string) (bool, string, error) {
	// 使用带超时和 panic 恢复的 DNS 解析
	ips, err := func() ([]net.IP, error) {
		type result struct {
			ips []net.IP
			err error
		}
		ch := make(chan result, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					m.log.Warnf("DNS 解析时发生异常: %v", r)
					ch <- result{nil, fmt.Errorf("DNS 解析异常: %v", r)}
				}
			}()
			ips, err := net.LookupIP(domain)
			ch <- result{ips, err}
		}()

		select {
		case res := <-ch:
			return res.ips, res.err
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("DNS 解析超时")
		}
	}()

	if err != nil {
		return false, "", fmt.Errorf("domain resolution failed: %w", err)
	}

	if len(ips) == 0 {
		return false, "", fmt.Errorf("no IP addresses found for domain")
	}

	// 获取当前服务器IP
	serverIPs, err := m.getServerIPs()
	if err != nil {
		m.log.Warnf("Failed to get server IPs: %v", err)
		return true, fmt.Sprintf("Domain resolves to: %v", ips), nil // 仍然返回成功，但记录警告
	}

	// 检查域名是否解析到当前服务器
	for _, domainIP := range ips {
		for _, serverIP := range serverIPs {
			if domainIP.Equal(serverIP) {
				return true, fmt.Sprintf("Domain correctly resolves to server IP: %s", domainIP.String()), nil
			}
		}
	}

	return false, fmt.Sprintf("Domain resolves to: %v, but server IPs are: %v", ips, serverIPs), nil
}

// getServerIPs 获取当前服务器的IP地址
func (m *Manager) getServerIPs() ([]net.IP, error) {
	var ips []net.IP

	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		// 跳过回环接口和未启用的接口
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				// 只添加IPv4地址
				if ipNet.IP.To4() != nil {
					ips = append(ips, ipNet.IP)
				}
			}
		}
	}

	return ips, nil
}

// isAllowedDomain 仅允许配置中的域名（代理规则或 ssl.domains）
func (m *Manager) isAllowedDomain(host string) bool {
	host = strings.ToLower(host)
	// 临时允许域名（例如来自面板的手动申请），未过期则放行
	if m.tempAllowedDomains != nil {
		now := time.Now()
		if exp, ok := m.tempAllowedDomains[host]; ok && now.Before(exp) {
			return true
		}
		// 清理过期条目
		for d, e := range m.tempAllowedDomains {
			if now.After(e) {
				delete(m.tempAllowedDomains, d)
			}
		}
	}
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
	// 代理规则中的域名（无论是否启用，只要存在就允许申请证书）
	for _, r := range m.config.Proxy.Rules {
		d := strings.ToLower(strings.TrimSpace(r.Domain))
		if d == "" {
			continue
		}
		if host == d || matchDomain(host, d) {
			return true
		}
	}
	// 静态站点中启用的域名
	for _, s := range m.config.StaticSites {
		if !s.Enabled {
			continue
		}
		d := strings.ToLower(strings.TrimSpace(s.Domain))
		if d == "" {
			continue
		}
		if host == d || matchDomain(host, d) {
			return true
		}
	}
	// PHP 站点中启用的域名
	for _, p := range m.config.PHPSites {
		if !p.Enabled {
			continue
		}
		d := strings.ToLower(strings.TrimSpace(p.Domain))
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
		return nil, fmt.Errorf("domain list cannot be empty")
	}

	primaryDomain := domains[0]
	m.log.Infof("Generating multi-domain self-signed certificate for %v", domains)

	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
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
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
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
		m.log.Errorf("Failed to save certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		m.log.Errorf("Failed to save private key: %v", err)
	}

	// 加载证书到内存
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 为所有域名缓存同一个证书
	m.certMutex.Lock()
	for _, domain := range domains {
		m.certCache[domain] = &cert
	}
	m.certMutex.Unlock()
	// 更新所有域名的元数据缓存
	for _, domain := range domains {
		m.updateCertMetadata(domain, &cert)
	}

	m.log.Infof("Successfully generated and cached multi-domain certificate: %v", domains)
	return &cert, nil
}

// LoadCertificateFromDisk 从磁盘加载指定域名证书到缓存
func (m *Manager) LoadCertificateFromDisk(domain string) error {
	certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	if _, err := os.Stat(certPath); err != nil {
		return fmt.Errorf("certificate file not found: %s", certPath)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("private key file not found: %s", keyPath)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	m.certMutex.Lock()
	m.certCache[domain] = &cert
	m.certMutex.Unlock()
	m.updateCertMetadata(domain, &cert) // 更新元数据缓存
	m.log.Infof("Loaded certificate from disk into cache: %s", domain)
	return nil
}

// AllowDomainTemporary 将域名加入临时允许列表，用于绕过策略发起 ACME 申请
func (m *Manager) AllowDomainTemporary(domain string, ttl time.Duration) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if m.tempAllowedDomains == nil {
		m.tempAllowedDomains = make(map[string]time.Time)
	}
	m.tempAllowedDomains[domain] = time.Now().Add(ttl)
}

// ListCertificatesFromDisk 扫描证书目录获取证书信息
func (m *Manager) ListCertificatesFromDisk() []CertificateInfo {
	certDir := m.config.SSL.CertDir

	// #region agent log
	logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if logFile != nil {
		logData, _ := json.Marshal(map[string]interface{}{
			"sessionId":    "debug-session",
			"runId":        "run1",
			"hypothesisId": "D",
			"location":     "manager.go:1227",
			"message":      "ListCertificatesFromDisk starting",
			"data":         map[string]interface{}{"certDir": certDir},
			"timestamp":    time.Now().UnixMilli(),
		})
		logFile.WriteString(string(logData) + "\n")
		logFile.Close()
	}
	// #endregion

	entries, err := os.ReadDir(certDir)
	if err != nil {
		m.log.Warnf("Failed to read certificate directory %s: %v", certDir, err)
		// #region agent log
		if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
			logData, _ := json.Marshal(map[string]interface{}{
				"sessionId":    "debug-session",
				"runId":        "run1",
				"hypothesisId": "D",
				"location":     "manager.go:1234",
				"message":      "Failed to read cert directory",
				"data":         map[string]interface{}{"error": err.Error()},
				"timestamp":    time.Now().UnixMilli(),
			})
			logFile.WriteString(string(logData) + "\n")
			logFile.Close()
		}
		// #endregion
		return nil
	}

	var certs []CertificateInfo
	var fileNames []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		fileNames = append(fileNames, name)
		if !strings.HasSuffix(strings.ToLower(name), ".crt") {
			continue
		}
		domain := strings.TrimSuffix(name, ".crt")
		certPath := filepath.Join(certDir, name)

		// #region agent log
		if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
			logData, _ := json.Marshal(map[string]interface{}{
				"sessionId":    "debug-session",
				"runId":        "run1",
				"hypothesisId": "B",
				"location":     "manager.go:1250",
				"message":      "Processing cert file",
				"data":         map[string]interface{}{"fileName": name, "extractedDomain": domain, "certPath": certPath},
				"timestamp":    time.Now().UnixMilli(),
			})
			logFile.WriteString(string(logData) + "\n")
			logFile.Close()
		}
		// #endregion

		pemBytes, err := os.ReadFile(certPath)
		if err != nil {
			// #region agent log
			if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
				logData, _ := json.Marshal(map[string]interface{}{
					"sessionId":    "debug-session",
					"runId":        "run1",
					"hypothesisId": "C",
					"location":     "manager.go:1256",
					"message":      "Failed to read cert file",
					"data":         map[string]interface{}{"certPath": certPath, "error": err.Error()},
					"timestamp":    time.Now().UnixMilli(),
				})
				logFile.WriteString(string(logData) + "\n")
				logFile.Close()
			}
			// #endregion
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			// #region agent log
			if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
				logData, _ := json.Marshal(map[string]interface{}{
					"sessionId":    "debug-session",
					"runId":        "run1",
					"hypothesisId": "C",
					"location":     "manager.go:1263",
					"message":      "Failed to decode PEM block",
					"data": map[string]interface{}{"certPath": certPath, "blockNil": block == nil, "blockType": func() string {
						if block != nil {
							return block.Type
						}
						return ""
					}()},
					"timestamp": time.Now().UnixMilli(),
				})
				logFile.WriteString(string(logData) + "\n")
				logFile.Close()
			}
			// #endregion
			continue
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// #region agent log
			if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
				logData, _ := json.Marshal(map[string]interface{}{
					"sessionId":    "debug-session",
					"runId":        "run1",
					"hypothesisId": "C",
					"location":     "manager.go:1270",
					"message":      "Failed to parse certificate",
					"data":         map[string]interface{}{"certPath": certPath, "error": err.Error()},
					"timestamp":    time.Now().UnixMilli(),
				})
				logFile.WriteString(string(logData) + "\n")
				logFile.Close()
			}
			// #endregion
			continue
		}

		// #region agent log
		if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
			logData, _ := json.Marshal(map[string]interface{}{
				"sessionId":    "debug-session",
				"runId":        "run1",
				"hypothesisId": "B",
				"location":     "manager.go:1278",
				"message":      "Successfully parsed certificate",
				"data":         map[string]interface{}{"fileName": name, "extractedDomain": domain, "certDNSNames": x509Cert.DNSNames, "certCN": x509Cert.Subject.CommonName},
				"timestamp":    time.Now().UnixMilli(),
			})
			logFile.WriteString(string(logData) + "\n")
			logFile.Close()
		}
		// #endregion

		status := "有效"
		if time.Now().After(x509Cert.NotAfter) {
			status = "过期"
		} else if time.Now().Add(30 * 24 * time.Hour).After(x509Cert.NotAfter) {
			status = "即将过期"
		}

		selfSigned := x509Cert.Issuer.String() == x509Cert.Subject.String()

		// 获取颁发机构名称
		issuer := "未知"
		if selfSigned {
			issuer = "自签名证书"
		} else {
			// 尝试从证书中提取颁发机构名称
			if len(x509Cert.Issuer.Organization) > 0 {
				issuer = x509Cert.Issuer.Organization[0]
			} else if len(x509Cert.Issuer.CommonName) > 0 {
				issuer = x509Cert.Issuer.CommonName
			} else {
				issuer = "Let's Encrypt" // 默认假设是 Let's Encrypt
			}
		}

		certs = append(certs, CertificateInfo{
			Domain:     domain,
			IssuedAt:   x509Cert.NotBefore,
			ExpiresAt:  x509Cert.NotAfter,
			Status:     status,
			IsWildcard: strings.HasPrefix(domain, "*."),
			SelfSigned: selfSigned,
			Issuer:     issuer,
		})
	}

	// #region agent log
	if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
		logData, _ := json.Marshal(map[string]interface{}{
			"sessionId":    "debug-session",
			"runId":        "run1",
			"hypothesisId": "D",
			"location":     "manager.go:1295",
			"message":      "ListCertificatesFromDisk disk scan complete",
			"data": map[string]interface{}{"certCount": len(certs), "allFiles": fileNames, "foundDomains": func() []string {
				var d []string
				for _, c := range certs {
					d = append(d, c.Domain)
				}
				return d
			}()},
			"timestamp": time.Now().UnixMilli(),
		})
		logFile.WriteString(string(logData) + "\n")
		logFile.Close()
	}
	// #endregion

	// 合并内存缓存中的证书（如 ACME 刚获取）
	m.certMutex.RLock()
	for domain, cert := range m.certCache {
		if cert == nil || len(cert.Certificate) == 0 {
			continue
		}
		// 若磁盘已有则跳过
		exists := false
		for _, c := range certs {
			if strings.EqualFold(c.Domain, domain) {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
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

		// 获取颁发机构名称
		issuer := "未知"
		if selfSigned {
			issuer = "自签名证书"
		} else {
			// 尝试从证书中提取颁发机构名称
			if len(x509Cert.Issuer.Organization) > 0 {
				issuer = x509Cert.Issuer.Organization[0]
			} else if len(x509Cert.Issuer.CommonName) > 0 {
				issuer = x509Cert.Issuer.CommonName
			} else {
				issuer = "Let's Encrypt" // 默认假设是 Let's Encrypt
			}
		}

		certs = append(certs, CertificateInfo{
			Domain:     domain,
			IssuedAt:   x509Cert.NotBefore,
			ExpiresAt:  x509Cert.NotAfter,
			Status:     status,
			IsWildcard: strings.HasPrefix(domain, "*."),
			SelfSigned: selfSigned,
			Issuer:     issuer,
		})
	}
	m.certMutex.RUnlock()

	// #region agent log
	if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
		var allDomains []string
		for _, c := range certs {
			allDomains = append(allDomains, c.Domain)
		}
		logData, _ := json.Marshal(map[string]interface{}{
			"sessionId":    "debug-session",
			"runId":        "run1",
			"hypothesisId": "E",
			"location":     "manager.go:1352",
			"message":      "ListCertificatesFromDisk final result",
			"data":         map[string]interface{}{"totalCertCount": len(certs), "allDomains": allDomains},
			"timestamp":    time.Now().UnixMilli(),
		})
		logFile.WriteString(string(logData) + "\n")
		logFile.Close()
	}
	// #endregion

	return certs
}

// SyncACMECertsToDisk 扫描 acme-cache，将有效证书与私钥写入 certs/keys 目录
func (m *Manager) SyncACMECertsToDisk() (int, error) {
	acmeCacheDir := filepath.Join(filepath.Dir(m.config.SSL.CertDir), "acme-cache")

	// #region agent log
	if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
		logData, _ := json.Marshal(map[string]interface{}{
			"sessionId":    "debug-session",
			"runId":        "run1",
			"hypothesisId": "A",
			"location":     "manager.go:1355",
			"message":      "SyncACMECertsToDisk starting",
			"data":         map[string]interface{}{"acmeCacheDir": acmeCacheDir, "certDir": m.config.SSL.CertDir, "keyDir": m.config.SSL.KeyDir},
			"timestamp":    time.Now().UnixMilli(),
		})
		logFile.WriteString(string(logData) + "\n")
		logFile.Close()
	}
	// #endregion

	entries, err := os.ReadDir(acmeCacheDir)
	if err != nil {
		// #region agent log
		if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
			logData, _ := json.Marshal(map[string]interface{}{
				"sessionId":    "debug-session",
				"runId":        "run1",
				"hypothesisId": "A",
				"location":     "manager.go:1368",
				"message":      "Failed to read ACME cache directory",
				"data":         map[string]interface{}{"acmeCacheDir": acmeCacheDir, "error": err.Error()},
				"timestamp":    time.Now().UnixMilli(),
			})
			logFile.WriteString(string(logData) + "\n")
			logFile.Close()
		}
		// #endregion
		return 0, fmt.Errorf("failed to read ACME cache directory: %w", err)
	}
	if err := os.MkdirAll(m.config.SSL.CertDir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create certificate directory: %w", err)
	}
	if err := os.MkdirAll(m.config.SSL.KeyDir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create key directory: %w", err)
	}

	var synced int
	var acmeFileNames []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		acmeFileNames = append(acmeFileNames, e.Name())
		path := filepath.Join(acmeCacheDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		var certBlocks [][]byte
		var keyBlock []byte
		rest := data
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			t := strings.ToUpper(strings.TrimSpace(blk.Type))
			if t == "CERTIFICATE" {
				certBlocks = append(certBlocks, blk.Bytes)
			} else if strings.Contains(t, "PRIVATE KEY") {
				keyBlock = blk.Bytes
			}
		}
		if len(certBlocks) == 0 || len(keyBlock) == 0 {
			continue
		}
		x509Cert, err := x509.ParseCertificate(certBlocks[0])
		if err != nil {
			continue
		}
		if time.Now().After(x509Cert.NotAfter) {
			continue
		}
		domain := ""
		if len(x509Cert.DNSNames) > 0 {
			domain = x509Cert.DNSNames[0]
		}
		if domain == "" {
			domain = x509Cert.Subject.CommonName
		}
		domain = strings.ToLower(strings.TrimSpace(domain))

		// #region agent log
		if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
			logData, _ := json.Marshal(map[string]interface{}{
				"sessionId":    "debug-session",
				"runId":        "run1",
				"hypothesisId": "A",
				"location":     "manager.go:1415",
				"message":      "Extracted domain from ACME cert",
				"data":         map[string]interface{}{"acmeFile": e.Name(), "dnsNames": x509Cert.DNSNames, "cn": x509Cert.Subject.CommonName, "extractedDomain": domain},
				"timestamp":    time.Now().UnixMilli(),
			})
			logFile.WriteString(string(logData) + "\n")
			logFile.Close()
		}
		// #endregion

		if domain == "" {
			continue
		}

		var certPEM []byte
		for _, der := range certBlocks {
			certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBlock})

		certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
		keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

		// #region agent log
		if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
			logData, _ := json.Marshal(map[string]interface{}{
				"sessionId":    "debug-session",
				"runId":        "run1",
				"hypothesisId": "B",
				"location":     "manager.go:1433",
				"message":      "Writing cert files",
				"data":         map[string]interface{}{"domain": domain, "certPath": certPath, "keyPath": keyPath},
				"timestamp":    time.Now().UnixMilli(),
			})
			logFile.WriteString(string(logData) + "\n")
			logFile.Close()
		}
		// #endregion

		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			m.log.Warnf("Failed to write certificate %s: %v", certPath, err)
			// #region agent log
			if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
				logData, _ := json.Marshal(map[string]interface{}{
					"sessionId":    "debug-session",
					"runId":        "run1",
					"hypothesisId": "B",
					"location":     "manager.go:1445",
					"message":      "Failed to write cert file",
					"data":         map[string]interface{}{"certPath": certPath, "error": err.Error()},
					"timestamp":    time.Now().UnixMilli(),
				})
				logFile.WriteString(string(logData) + "\n")
				logFile.Close()
			}
			// #endregion
			continue
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			m.log.Warnf("Failed to write private key %s: %v", keyPath, err)
			continue
		}
		if err := m.LoadCertificateFromDisk(domain); err != nil {
			m.log.Warnf("Failed to load certificate after sync %s: %v", domain, err)
		}
		synced++
	}

	// #region agent log
	if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
		logData, _ := json.Marshal(map[string]interface{}{
			"sessionId":    "debug-session",
			"runId":        "run1",
			"hypothesisId": "A",
			"location":     "manager.go:1462",
			"message":      "SyncACMECertsToDisk complete",
			"data":         map[string]interface{}{"syncedCount": synced, "acmeFiles": acmeFileNames},
			"timestamp":    time.Now().UnixMilli(),
		})
		logFile.WriteString(string(logData) + "\n")
		logFile.Close()
	}
	// #endregion

	return synced, nil
}

// HasValidSSLCertificates 检查是否有有效的非自签名证书
func (m *Manager) HasValidSSLCertificates() bool {
	certs := m.GetCertificateList()
	for _, cert := range certs {
		if !cert.SelfSigned && cert.Status == "有效" {
			return true
		}
	}
	return false
}

// HasValidCertificate 检查指定域名是否有有效的非自签名证书
func (m *Manager) HasValidCertificate(domain string) bool {
	// 先尝试从缓存或磁盘加载证书
	cert, err := m.GetCertificate(domain)
	if err != nil || cert == nil || len(cert.Certificate) == 0 {
		return false
	}

	// 解析证书，检查是否为自签名
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// 检查是否自签名
	isSelfSigned := x509Cert.Issuer.String() == x509Cert.Subject.String()
	if isSelfSigned {
		return false
	}

	// 检查是否过期
	if time.Now().After(x509Cert.NotAfter) {
		return false
	}

	return true
}

// GetFirstValidSSLDomain 获取第一个有效的非自签名SSL证书域名
func (m *Manager) GetFirstValidSSLDomain() string {
	certs := m.GetCertificateList()
	for _, cert := range certs {
		if !cert.SelfSigned && cert.Status == "有效" {
			return cert.Domain
		}
	}
	return ""
}

// GetFirstValidLEDomain 获取第一个有效的由 Let's Encrypt 签发的域名
func (m *Manager) GetFirstValidLEDomain() string {
	// 先检查内存缓存
	m.certMutex.RLock()
	for domain, cert := range m.certCache {
		if cert == nil || len(cert.Certificate) == 0 {
			continue
		}
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			continue
		}
		if time.Now().After(x509Cert.NotAfter) {
			continue
		}
		// 非自签名且签发者包含 Let's Encrypt
		if x509Cert.Issuer.String() != x509Cert.Subject.String() &&
			(strings.Contains(strings.ToLower(x509Cert.Issuer.CommonName), "let's encrypt") ||
				strings.Contains(strings.ToLower(strings.Join(x509Cert.Issuer.Organization, ",")), "let's encrypt") ||
				strings.Contains(strings.ToLower(x509Cert.Issuer.String()), "let's encrypt")) {
			m.certMutex.RUnlock()
			return domain
		}
	}
	m.certMutex.RUnlock()

	// 再扫描磁盘证书目录
	certDir := m.config.SSL.CertDir
	entries, err := os.ReadDir(certDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".crt") {
			continue
		}
		pemBytes, err := os.ReadFile(filepath.Join(certDir, name))
		if err != nil {
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || time.Now().After(x509Cert.NotAfter) {
			continue
		}
		if x509Cert.Issuer.String() != x509Cert.Subject.String() &&
			(strings.Contains(strings.ToLower(x509Cert.Issuer.CommonName), "let's encrypt") ||
				strings.Contains(strings.ToLower(strings.Join(x509Cert.Issuer.Organization, ",")), "let's encrypt") ||
				strings.Contains(strings.ToLower(x509Cert.Issuer.String()), "let's encrypt")) {
			domain := strings.TrimSuffix(name, ".crt")
			return domain
		}
	}
	return ""
}

// initializeDNSProviders 初始化DNS服务商
func (m *Manager) initializeDNSProviders() {
	for _, provider := range m.config.SSL.DNSProviders {
		if !provider.Enabled {
			continue
		}

		var dnsProvider DNSProviderInterface

		switch strings.ToLower(provider.Type) {
		case "cloudflare":
			dnsProvider = NewCloudflareProvider(provider.APIKey, provider.ZoneID, m.log)
		case "aliyun":
			dnsProvider = NewAliyunProvider(provider.APIKey, provider.APISecret, m.log)
		case "tencent":
			dnsProvider = NewTencentProvider(provider.APIKey, provider.APISecret, m.log)
		case "godaddy":
			dnsProvider = NewGoDaddyProvider(provider.APIKey, provider.APISecret, m.log)
		case "namecheap":
			dnsProvider = NewNamecheapProvider(provider.APIKey, provider.APISecret, provider.ZoneID, m.log)
		case "aws":
			dnsProvider = NewAWSRoute53Provider(provider.APIKey, provider.APISecret, "us-east-1", m.log)
		case "custom":
			dnsProvider = NewCustomProvider(provider.Endpoint, provider.APIKey, m.log)
		default:
			m.log.Warnf("Unknown DNS provider type: %s", provider.Type)
			continue
		}

		if err := dnsProvider.Validate(); err != nil {
			m.log.Warnf("DNS provider %s validation failed: %v", provider.Name, err)
			continue
		}

		m.dnsManager.RegisterProviderWithPriority(provider.Name, dnsProvider, provider.Priority)
		m.log.Infof("Initialized DNS provider: %s (%s) with priority %d", provider.Name, provider.Type, provider.Priority)
	}
}

// RequestCertificateWithDNS 使用DNS验证申请证书
func (m *Manager) RequestCertificateWithDNS(domain, providerName string) error {
	return m.requestCertificateWithDNSRetry(domain, providerName, 2) // DNS验证最多重试2次
}

// requestCertificateWithDNSRetry 带重试机制的DNS验证证书申请
func (m *Manager) requestCertificateWithDNSRetry(domain, providerName string, maxRetries int) error {
	if m.acmeMgr == nil {
		return fmt.Errorf("ACME not enabled")
	}

	// 检查是否支持DNS验证
	if !m.supportsDNSChallenge() {
		return fmt.Errorf("DNS challenge not supported")
	}

	// 获取DNS服务商
	_, err := m.dnsManager.GetProvider(providerName)
	if err != nil {
		return fmt.Errorf("DNS provider not found: %s", providerName)
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		m.log.Infof("DNS certificate request attempt %d/%d for domain: %s using provider: %s", attempt, maxRetries, domain, providerName)

		err := m.performDNSChallenge(domain, providerName)
		if err == nil {
			m.log.Infof("DNS certificate request successful for domain: %s (attempt %d)", domain, attempt)
			return nil
		}

		lastErr = err
		m.log.Warnf("DNS certificate request failed for %s (attempt %d): %v", domain, attempt, err)

		// 如果不是最后一次尝试，等待一段时间后重试
		if attempt < maxRetries {
			waitTime := time.Duration(attempt*15) * time.Second // DNS验证等待时间稍长
			m.log.Infof("Waiting %v before DNS retry for domain: %s", waitTime, domain)
			time.Sleep(waitTime)
		}
	}

	return fmt.Errorf("DNS certificate request failed after %d attempts: %w", maxRetries, lastErr)
}

// performDNSChallenge 执行DNS挑战验证
func (m *Manager) performDNSChallenge(domain, providerName string) error {
	// 创建ACME客户端
	client := &acme.Client{}
	if m.config.SSL.Staging {
		client.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	} else {
		client.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}

	// 创建账户
	account := &acme.Account{
		Contact: []string{"mailto:" + m.config.SSL.Email},
	}

	ctx := context.Background()
	var err error
	account, err = client.Register(ctx, account, acme.AcceptTOS)
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %w", err)
	}

	// 创建订单
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("failed to create authorization order: %w", err)
	}

	// 处理授权
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("failed to get authorization: %w", err)
		}

		// 查找DNS挑战
		var challenge *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				challenge = c
				break
			}
		}

		if challenge == nil {
			return fmt.Errorf("no DNS challenge found for domain: %s", domain)
		}

		// 生成DNS挑战记录
		keyAuth, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return fmt.Errorf("failed to generate DNS challenge record: %w", err)
		}

		// 确定记录名称
		recordName := GetACMEChallengeRecordNameForWildcard(domain)

		// 创建DNS挑战，使用故障转移机制
		challengeInfo, err := m.dnsManager.CreateDNSChallengeWithFailover(ctx, domain, recordName, keyAuth)
		if err != nil {
			return fmt.Errorf("failed to create DNS challenge: %w", err)
		}

		// 清理函数
		defer func() {
			if cleanupErr := m.dnsManager.CleanupDNSChallenge(ctx, challengeInfo); cleanupErr != nil {
				m.log.Warnf("Failed to cleanup DNS challenge: %v", cleanupErr)
			}
		}()

		// 接受挑战
		_, err = client.Accept(ctx, challenge)
		if err != nil {
			return fmt.Errorf("failed to accept challenge: %w", err)
		}

		// 等待挑战完成
		_, err = client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			return fmt.Errorf("authorization failed: %w", err)
		}
	}

	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// 创建CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// 提交CSR
	cert, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// 保存证书
	err = m.saveCertificate(domain, cert, privateKey)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	m.log.Infof("Successfully obtained certificate for domain: %s using DNS provider: %s", domain, providerName)
	return nil
}

// supportsDNSChallenge 检查是否支持DNS验证
func (m *Manager) supportsDNSChallenge() bool {
	for _, method := range m.config.SSL.ChallengeMethods {
		if method == "dns-01" {
			return true
		}
	}
	return false
}

// saveCertificate 保存证书到文件
func (m *Manager) saveCertificate(domain string, certDER [][]byte, privateKey *rsa.PrivateKey) error {
	// 编码私钥
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 编码证书
	var certPEM []byte
	for _, der := range certDER {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})...)
	}

	// 保存文件
	certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate file: %w", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key file: %w", err)
	}

	// 加载到缓存
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	m.certMutex.Lock()
	m.certCache[domain] = &cert
	m.certMutex.Unlock()

	m.updateCertMetadata(domain, &cert) // 更新元数据缓存

	return nil
}

// saveCertificateToDisk 将 tls.Certificate 持久化到磁盘
func (m *Manager) saveCertificateToDisk(domain string, cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return fmt.Errorf("invalid certificate")
	}

	// 编码证书链
	var certPEM []byte
	for _, derBytes := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		})...)
	}

	// 编码私钥
	var keyPEM []byte
	if cert.PrivateKey != nil {
		switch key := cert.PrivateKey.(type) {
		case *rsa.PrivateKey:
			keyPEM = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			})
		case *ecdsa.PrivateKey:
			keyBytes, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				return fmt.Errorf("failed to marshal EC private key: %w", err)
			}
			keyPEM = pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: keyBytes,
			})
		default:
			return fmt.Errorf("unsupported private key type: %T", key)
		}
	} else {
		return fmt.Errorf("certificate has no private key")
	}

	// 确保目录存在
	if err := os.MkdirAll(m.config.SSL.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}
	if err := os.MkdirAll(m.config.SSL.KeyDir, 0755); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// 保存文件
	certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	m.log.Infof("Certificate persisted to disk: %s (cert: %s, key: %s)", domain, certPath, keyPath)
	return nil
}

// GetDNSProviders 获取可用的DNS服务商列表
func (m *Manager) GetDNSProviders() []string {
	return m.dnsManager.ListProviders()
}

// ValidateDNSProvider 验证DNS服务商配置
func (m *Manager) ValidateDNSProvider(providerName string) error {
	return m.dnsManager.ValidateProvider(providerName)
}

// GetDNSProviderHealth 获取DNS提供程序健康状态
func (m *Manager) GetDNSProviderHealth() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return m.dnsManager.GetDNSProviderHealth(ctx)
}

// TestDNSProvider 测试DNS提供程序连接
func (m *Manager) TestDNSProvider(name string) error {
	return m.dnsManager.TestProvider(name)
}

// CreateDNSChallenge 创建DNS挑战记录
func (m *Manager) CreateDNSChallenge(domain, recordName, recordValue, providerName string) (*DNSChallengeInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return m.dnsManager.CreateDNSChallenge(ctx, domain, recordName, recordValue, providerName)
}

// CreateDNSChallengeWithFailover 使用故障转移创建DNS挑战记录
func (m *Manager) CreateDNSChallengeWithFailover(domain, recordName, recordValue string) (interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return m.dnsManager.CreateDNSChallengeWithFailover(ctx, domain, recordName, recordValue)
}

// GetDNSProviderDomains 获取DNS提供商的域名列表
func (m *Manager) GetDNSProviderDomains(providerName string) ([]DomainInfo, error) {
	provider, err := m.dnsManager.GetProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("DNS provider not found: %s", providerName)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	domains, err := provider.ListDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get domains from provider %s: %w", providerName, err)
	}

	return domains, nil
}
