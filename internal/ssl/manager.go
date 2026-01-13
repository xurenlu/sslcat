package ssl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	// 证书申请进度事件通道：用于实时推送申请进度
	progressChannels map[string]chan CertProgressEvent
	progressMutex   sync.RWMutex
}

// CertProgressEvent 证书申请进度事件
type CertProgressEvent struct {
	Domain      string    `json:"domain"`
	Status      string    `json:"status"`      // "started", "checking_dns", "using_dns01", "using_http01", "success", "failed", "retrying"
	Message     string    `json:"message"`     // 进度消息
	Attempt     int       `json:"attempt"`     // 当前尝试次数
	MaxAttempts int       `json:"max_attempts"` // 最大尝试次数
	Progress    int       `json:"progress"`     // 进度百分比 0-100
	Error       string    `json:"error,omitempty"` // 错误信息（如果有）
	Timestamp   time.Time `json:"timestamp"`
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
		progressChannels:   make(map[string]chan CertProgressEvent),
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

	// 删除 certs/ 和 keys/ 目录中的证书文件
	certFile := filepath.Join(m.config.SSL.CertDir, domain+".crt")
	keyFile := filepath.Join(m.config.SSL.KeyDir, domain+".key")

	if err := os.Remove(certFile); err != nil && !os.IsNotExist(err) {
		m.log.Warnf("Failed to remove certificate file %s: %v", certFile, err)
	}

	if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
		m.log.Warnf("Failed to remove private key file %s: %v", keyFile, err)
	}

	// 删除 acme-cache 目录中的证书缓存（防止重启后自动恢复）
	acmeCacheDir := filepath.Join(filepath.Dir(m.config.SSL.CertDir), "acme-cache")
	if m.acmeMgr != nil {
		// 尝试从 autocert 缓存中删除
		ctx := context.Background()
		if err := m.acmeMgr.Cache.Delete(ctx, domain); err != nil {
			m.log.Warnf("Failed to delete certificate from ACME cache for %s: %v", domain, err)
		} else {
			m.log.Infof("Deleted certificate from ACME cache for domain %s", domain)
		}
		
		// 同时删除可能存在的通配符域名缓存（*.domain）
		wildcardDomain := "*." + domain
		if err := m.acmeMgr.Cache.Delete(ctx, wildcardDomain); err == nil {
			m.log.Infof("Deleted wildcard certificate from ACME cache for domain %s", wildcardDomain)
		}
		
		// 删除子域名的情况（如果是子域名，也尝试删除主域名）
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			// 可能是子域名，尝试删除对应的通配符证书
			parentDomain := strings.Join(parts[1:], ".")
			wildcardParent := "*." + parentDomain
			if err := m.acmeMgr.Cache.Delete(ctx, wildcardParent); err == nil {
				m.log.Infof("Deleted parent wildcard certificate from ACME cache for domain %s", wildcardParent)
			}
		}
	} else {
		// 如果没有 acmeMgr，尝试直接删除文件
		acmeCacheFile := filepath.Join(acmeCacheDir, domain)
		if err := os.Remove(acmeCacheFile); err != nil && !os.IsNotExist(err) {
			m.log.Warnf("Failed to remove ACME cache file %s: %v", acmeCacheFile, err)
		}
	}

	// 清除元数据缓存
	m.metadataMutex.Lock()
	delete(m.certMetadataCache, domain)
	m.metadataMutex.Unlock()

	// 清除失败缓存
	m.failedCacheMutex.Lock()
	delete(m.failedDomainCache, domain)
	m.failedCacheMutex.Unlock()

	m.log.Infof("Deleted certificate for domain %s (including ACME cache)", domain)
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

	// 尝试查找通配符证书（例如 *.facev.app 匹配 f.facev.app）
	if wildcardCert := m.findWildcardCert(domain); wildcardCert != nil {
		m.log.Debugf("Domain %s matched wildcard certificate", domain)
		return wildcardCert, nil
	}

	// 尝试从磁盘加载通配符证书
	if cert := m.loadWildcardCertFromDisk(domain); cert != nil {
		m.log.Debugf("Loaded wildcard certificate from disk for domain %s", domain)
		return cert, nil
	}

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
					cert, err := m.acmeMgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
					if err != nil {
						m.log.Errorf("ACME renewal failed %s: %v", domain, err)

						// 发送证书续期失败通知
						if m.notificationIntegrator != nil {
							m.notificationIntegrator.SendCertFailedNotification(domain, fmt.Sprintf("自动续期失败: %v", err))
						}
					} else if cert != nil {
						m.log.Infof("ACME renewal triggered: %s", domain)

						// 立即保存证书到磁盘并加载到缓存
						if saveErr := m.saveCertificateToDisk(domain, cert); saveErr != nil {
							m.log.Warnf("Failed to save renewed certificate to disk for %s: %v", domain, saveErr)
						} else {
							// 保存成功后，加载到缓存
							if loadErr := m.LoadCertificateFromDisk(domain); loadErr != nil {
								m.log.Warnf("Failed to load renewed certificate from disk for %s: %v", domain, loadErr)
								// 如果从磁盘加载失败，直接缓存内存中的证书
								m.certMutex.Lock()
								m.certCache[domain] = cert
								m.certMutex.Unlock()
								m.updateCertMetadata(domain, cert)
							}
							// 清除失败缓存
							m.failedCacheMutex.Lock()
							delete(m.failedDomainCache, domain)
							m.failedCacheMutex.Unlock()
						}

						// 同时尝试同步 ACME 缓存中的其他证书
						if _, syncErr := m.SyncACMECertsToDisk(); syncErr != nil {
							m.log.Debugf("ACME post-renewal sync failed: %v", syncErr)
						}

						// 发送证书续期成功通知
						if m.notificationIntegrator != nil {
							m.notificationIntegrator.SendCertSuccessNotification(domain, 1, 0)
						}
					} else {
						m.log.Warnf("ACME renewal returned nil certificate for %s", domain)
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

// loadWildcardCertFromDisk 从磁盘加载通配符证书
func (m *Manager) loadWildcardCertFromDisk(domain string) *tls.Certificate {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil
	}

	// 尝试匹配 *.domain.com 格式的通配符证书文件名
	wildcardDomain := "*." + strings.Join(parts[1:], ".")
	certPath := filepath.Join(m.config.SSL.CertDir, wildcardDomain+".crt")
	keyPath := filepath.Join(m.config.SSL.KeyDir, wildcardDomain+".key")

	// 检查文件是否存在
	if _, err := os.Stat(certPath); err != nil {
		return nil
	}
	if _, err := os.Stat(keyPath); err != nil {
		return nil
	}

	// 加载证书
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		m.log.Errorf("Failed to load wildcard certificate %s: %v", wildcardDomain, err)
		return nil
	}

	// 验证证书是否匹配域名
	if !m.domainMatchesCert(domain, &cert) {
		m.log.Debugf("Wildcard certificate %s does not match domain %s", wildcardDomain, domain)
		return nil
	}

	// 加载成功，更新证书缓存
	m.certMutex.Lock()
	m.certCache[wildcardDomain] = &cert
	m.certMutex.Unlock()
	m.updateCertMetadata(wildcardDomain, &cert)

	m.log.Debugf("Loaded wildcard certificate from disk: %s for domain %s", wildcardDomain, domain)
	return &cert
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
	// 若启用 ACME，使用 ACME 的 HTTP-01 验证处理器，但不自动申请证书
	// 证书必须通过后台手动申请，访问时只使用已存在的证书
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
				
				// 只使用已存在的证书，不自动申请
				// 证书必须通过后台手动申请，访问时只使用已存在的证书
				if cert, err := m.GetCertificate(host); err == nil {
					return cert, nil
				}
				
				// 如果没有证书，回退到默认自签证书
				if m.defaultCert != nil {
					return m.defaultCert, nil
				}
				return nil, fmt.Errorf("no certificate available for %s (certificate must be requested manually from admin panel)", host)
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

	// 记录证书续期/申请请求的详细信息
	m.log.Infof("Certificate request initiated for domain: %s", domain)
	
	// 检查是否已有证书，记录旧证书的有效期
	if existingCert := m.getCertificateFromCache(domain); existingCert != nil {
		if x509Cert, err := x509.ParseCertificate(existingCert.Certificate[0]); err == nil {
			m.log.Infof("Existing certificate found for %s: NotBefore=%v, NotAfter=%v, DaysRemaining=%.1f",
				domain, x509Cert.NotBefore, x509Cert.NotAfter, time.Until(x509Cert.NotAfter).Hours()/24)
			
			// 强制删除ACME缓存中的旧证书，以触发重新申请
			if m.acmeMgr.Cache != nil {
				m.log.Infof("Deleting ACME cache for %s to force renewal", domain)
				if err := m.acmeMgr.Cache.Delete(context.Background(), domain); err != nil {
					m.log.Warnf("Failed to delete ACME cache for %s: %v (will continue anyway)", domain, err)
				} else {
					m.log.Infof("ACME cache deleted successfully for %s", domain)
				}
			}
		}
	} else {
		m.log.Infof("No existing certificate found for %s, will request new certificate", domain)
	}

	// 不重试，一次失败就结束
	return m.ensureDomainCertWithRetry(domain, 1)
}

// ensureDomainCertWithRetry 带重试机制的证书申请
func (m *Manager) ensureDomainCertWithRetry(domain string, maxRetries int) error {
	var lastErr error
	startTime := time.Now()

	// 发送开始事件
	m.sendProgressEvent(domain, CertProgressEvent{
		Domain:      domain,
		Status:      "started",
		Message:     fmt.Sprintf("开始申请证书: %s", domain),
		Attempt:     0,
		MaxAttempts: maxRetries,
		Progress:    0,
		Timestamp:   time.Now(),
	})

	for attempt := 1; attempt <= maxRetries; attempt++ {
		attemptStart := time.Now()
		m.log.Infof("Certificate request attempt %d/%d for domain: %s", attempt, maxRetries, domain)

		// 发送重试事件
		if attempt > 1 {
			m.sendProgressEvent(domain, CertProgressEvent{
				Domain:      domain,
				Status:      "retrying",
				Message:     fmt.Sprintf("第 %d/%d 次尝试申请证书", attempt, maxRetries),
				Attempt:     attempt,
				MaxAttempts: maxRetries,
				Progress:    (attempt - 1) * 30, // 每次尝试约30%进度
				Timestamp:   time.Now(),
			})
		}

		// 第一次尝试时检查域名解析
		if attempt == 1 {
			m.sendProgressEvent(domain, CertProgressEvent{
				Domain:      domain,
				Status:      "checking_dns",
				Message:     "正在检查域名解析...",
				Attempt:     attempt,
				MaxAttempts: maxRetries,
				Progress:    10,
				Timestamp:   time.Now(),
			})

			dnsCheckStart := time.Now()
			if resolved, info, err := m.checkDomainResolution(domain); err != nil {
				m.log.Warnf("Domain resolution check failed for %s: %v", domain, err)
				m.sendProgressEvent(domain, CertProgressEvent{
					Domain:      domain,
					Status:      "checking_dns",
					Message:     fmt.Sprintf("DNS解析检查失败: %v", err),
					Attempt:     attempt,
					MaxAttempts: maxRetries,
					Progress:    15,
					Error:       err.Error(),
					Timestamp:   time.Now(),
				})
			} else {
				dnsCheckDuration := time.Since(dnsCheckStart)
				m.log.Infof("Domain resolution check for %s: %s (耗时: %v)", domain, info, dnsCheckDuration)
				resolvedMsg := "DNS解析检查完成"
				if !resolved {
					resolvedMsg = "DNS解析检查完成，但域名可能未指向本服务器"
					m.log.Warnf("Domain %s may not resolve to this server, HTTP-01 validation might fail", domain)
				}
				m.sendProgressEvent(domain, CertProgressEvent{
					Domain:      domain,
					Status:      "checking_dns",
					Message:     resolvedMsg + ": " + info,
					Attempt:     attempt,
					MaxAttempts: maxRetries,
					Progress:    15,
					Timestamp:   time.Now(),
				})
			}
		}

		// 临时放行该域名以触发申请（避免必须写入配置）
		m.AllowDomainTemporary(domain, 24*time.Hour)

		// 优先使用DNS-01验证（如果配置了DNS提供商且域名属于某个提供商）
		supportsDNS := m.supportsDNSChallenge()
		hasProvider := m.hasAvailableDNSProvider()
		m.log.Infof("Certificate request for %s: supportsDNSChallenge=%v, hasAvailableDNSProvider=%v", domain, supportsDNS, hasProvider)
		
		if supportsDNS && hasProvider {
			providerName := m.findDNSProviderForDomain(domain)
			m.log.Infof("findDNSProviderForDomain(%s) returned: %s", domain, providerName)
			
			if providerName != "" {
				m.sendProgressEvent(domain, CertProgressEvent{
					Domain:      domain,
					Status:      "using_dns01",
					Message:     fmt.Sprintf("使用 DNS-01 验证，DNS服务商: %s", providerName),
					Attempt:     attempt,
					MaxAttempts: maxRetries,
					Progress:    30,
					Timestamp:   time.Now(),
				})

				dnsStart := time.Now()
				m.log.Infof("Domain %s found in DNS provider %s, using DNS-01 validation", domain, providerName)
				if dnsErr := m.RequestCertificateWithDNS(domain, providerName); dnsErr == nil {
					dnsDuration := time.Since(dnsStart)
					totalDuration := time.Since(startTime)
					m.log.Infof("DNS-01 validation successful for domain: %s (DNS耗时: %v, 总耗时: %v)", domain, dnsDuration, totalDuration)

					m.sendProgressEvent(domain, CertProgressEvent{
						Domain:      domain,
						Status:      "success",
						Message:     fmt.Sprintf("证书申请成功！耗时: %v", totalDuration),
						Attempt:     attempt,
						MaxAttempts: maxRetries,
						Progress:    100,
						Timestamp:   time.Now(),
					})

					// 发送证书申请成功通知
					if m.notificationIntegrator != nil {
						m.notificationIntegrator.SendCertSuccessNotification(domain, attempt, totalDuration)
					}

					return nil
				} else {
					dnsDuration := time.Since(dnsStart)
					m.log.Warnf("DNS-01 validation failed for %s (耗时: %v): %v, will try HTTP-01 as fallback", domain, dnsDuration, dnsErr)
					
					m.sendProgressEvent(domain, CertProgressEvent{
						Domain:      domain,
						Status:      "using_dns01",
						Message:     fmt.Sprintf("DNS-01 验证失败，将尝试 HTTP-01: %v", dnsErr),
						Attempt:     attempt,
						MaxAttempts: maxRetries,
						Progress:    50,
						Error:       dnsErr.Error(),
						Timestamp:   time.Now(),
					})
					// DNS-01失败，继续尝试HTTP-01作为备选
				}
			} else {
				m.log.Warnf("Domain %s not found in any DNS provider, will use HTTP-01", domain)
			}
		} else {
			// 详细说明为什么没有使用 DNS-01
			var reasons []string
			if !supportsDNS {
				if len(m.config.SSL.ChallengeMethods) > 0 {
					reasons = append(reasons, fmt.Sprintf("DNS-01 未在配置的挑战方法中 (当前配置: %v)", m.config.SSL.ChallengeMethods))
				} else {
					reasons = append(reasons, "未配置挑战方法且没有可用的 DNS 提供商")
				}
			}
			if !hasProvider {
				reasons = append(reasons, "没有可用的 DNS 提供商")
			}
			if supportsDNS && hasProvider {
				// 这种情况说明 findDNSProviderForDomain 返回了空字符串
				reasons = append(reasons, fmt.Sprintf("域名 %s 不在任何已配置的 DNS 提供商管理的域名列表中", domain))
			}
			
			if len(reasons) > 0 {
				reasonMsg := strings.Join(reasons, "; ")
				m.log.Warnf("将使用 HTTP-01 验证申请证书 %s，原因: %s", domain, reasonMsg)
				
				m.sendProgressEvent(domain, CertProgressEvent{
					Domain:      domain,
					Status:      "using_http01",
					Message:     fmt.Sprintf("将使用 HTTP-01 验证，原因: %s", reasonMsg),
					Attempt:     attempt,
					MaxAttempts: maxRetries,
					Progress:    30,
					Timestamp:   time.Now(),
				})
			}
		}

		// 尝试HTTP-01验证（作为备选或主要方式）
		m.log.Infof("开始使用 HTTP-01 验证申请证书: %s", domain)
		
		m.sendProgressEvent(domain, CertProgressEvent{
			Domain:      domain,
			Status:      "using_http01",
			Message:     "正在使用 HTTP-01 验证申请证书...",
			Attempt:     attempt,
			MaxAttempts: maxRetries,
			Progress:    50,
			Timestamp:   time.Now(),
		})
		acmeStart := time.Now()
		cert, err := m.acmeMgr.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		acmeDuration := time.Since(acmeStart)

		if err == nil && cert != nil {
			// 申请成功，立即将证书保存到缓存和磁盘
			m.sendProgressEvent(domain, CertProgressEvent{
				Domain:      domain,
				Status:      "using_http01",
				Message:     "证书申请成功，正在保存证书...",
				Attempt:     attempt,
				MaxAttempts: maxRetries,
				Progress:    90,
				Timestamp:   time.Now(),
			})

			syncStart := time.Now()
			
			// 记录新证书的有效期信息
			if x509Cert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				m.log.Infof("New certificate obtained for %s: NotBefore=%v, NotAfter=%v, ValidDays=%.1f",
					domain, x509Cert.NotBefore, x509Cert.NotAfter, x509Cert.NotAfter.Sub(x509Cert.NotBefore).Hours()/24)
			}
			
			// 先保存证书到磁盘
			if saveErr := m.saveCertificateToDisk(domain, cert); saveErr != nil {
				m.log.Errorf("Failed to save certificate to disk for %s: %v", domain, saveErr)
				// 即使保存失败，也尝试直接缓存内存中的证书
				m.certMutex.Lock()
				m.certCache[domain] = cert
				m.certMutex.Unlock()
				m.updateCertMetadata(domain, cert)
				m.log.Infof("Certificate cached in memory for %s (disk save failed)", domain)
				// 清除失败缓存
				m.failedCacheMutex.Lock()
				delete(m.failedDomainCache, domain)
				m.failedCacheMutex.Unlock()
			} else {
				certPath := filepath.Join(m.config.SSL.CertDir, domain+".crt")
				keyPath := filepath.Join(m.config.SSL.KeyDir, domain+".key")
				m.log.Infof("Certificate saved to disk: cert=%s, key=%s", certPath, keyPath)
				
				// 保存成功后，强制从磁盘重新加载证书以确保缓存是最新的
				m.log.Infof("Reloading certificate from disk to ensure cache is up-to-date: %s", domain)
				
				// 先清除旧的缓存
				m.certMutex.Lock()
				delete(m.certCache, domain)
				m.certMutex.Unlock()
				
				if loadErr := m.LoadCertificateFromDisk(domain); loadErr != nil {
					m.log.Errorf("Failed to load certificate from disk for %s: %v", domain, loadErr)
					// 如果从磁盘加载失败，直接缓存内存中的证书
					m.certMutex.Lock()
					m.certCache[domain] = cert
					m.certMutex.Unlock()
					m.updateCertMetadata(domain, cert)
					m.log.Infof("Certificate cached in memory for %s (disk load failed)", domain)
				} else {
					m.log.Infof("Certificate successfully loaded from disk to cache: %s", domain)
					// 验证加载的证书有效期
					if loadedCert := m.getCertificateFromCache(domain); loadedCert != nil {
						if x509Cert, err := x509.ParseCertificate(loadedCert.Certificate[0]); err == nil {
							m.log.Infof("Loaded certificate verification for %s: NotAfter=%v, DaysRemaining=%.1f",
								domain, x509Cert.NotAfter, time.Until(x509Cert.NotAfter).Hours()/24)
						}
					}
				}
				// 清除失败缓存（LoadCertificateFromDisk 内部应该已经处理了，但为了安全还是清除一下）
				m.failedCacheMutex.Lock()
				delete(m.failedDomainCache, domain)
				m.failedCacheMutex.Unlock()
			}
			
			// 同时尝试同步 ACME 缓存中的其他证书
			if _, syncErr := m.SyncACMECertsToDisk(); syncErr != nil {
				m.log.Debugf("ACME post-issue sync failed: %v", syncErr)
			}
			syncDuration := time.Since(syncStart)

			totalDuration := time.Since(startTime)
			m.log.Infof("Certificate request successful for domain: %s (attempt %d, ACME耗时: %v, 同步耗时: %v, 总耗时: %v)",
				domain, attempt, acmeDuration, syncDuration, totalDuration)

			m.sendProgressEvent(domain, CertProgressEvent{
				Domain:      domain,
				Status:      "success",
				Message:     fmt.Sprintf("证书申请成功！总耗时: %v", totalDuration),
				Attempt:     attempt,
				MaxAttempts: maxRetries,
				Progress:    100,
				Timestamp:   time.Now(),
			})

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
		var errorDetails string
		if strings.Contains(errMsg, "missing certificate") {
			errorDetails = "可能原因: 1) 域名DNS未解析到此服务器 2) 防火墙阻止80端口 3) 服务器未在standard模式监听80端口 4) Let's Encrypt无法访问验证端点"
			m.log.Warnf("HTTP-01 validation failed for %s (attempt %d, 耗时: %v): %v", domain, attempt, attemptDuration, err)
			m.log.Warnf(errorDetails)
		} else {
			m.log.Warnf("HTTP-01 validation failed for %s (attempt %d, 耗时: %v): %v", domain, attempt, attemptDuration, err)
			errorDetails = errMsg
		}

		m.sendProgressEvent(domain, CertProgressEvent{
			Domain:      domain,
			Status:      "failed",
			Message:     fmt.Sprintf("HTTP-01 验证失败 (第 %d/%d 次尝试)", attempt, maxRetries),
			Attempt:     attempt,
			MaxAttempts: maxRetries,
			Progress:    50 + (attempt-1)*15, // 每次失败增加15%进度
			Error:       errorDetails,
			Timestamp:   time.Now(),
		})

		// 不重试，一次失败就结束
		// 注释掉重试逻辑，因为 maxRetries 已设置为 1
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

// findDNSProviderForDomain 查找域名属于哪个DNS提供商
func (m *Manager) findDNSProviderForDomain(domain string) string {
	// 处理通配符域名：*.example.com -> example.com
	searchDomain := domain
	if strings.HasPrefix(domain, "*.") {
		searchDomain = domain[2:]
		m.log.Debugf("Wildcard domain detected: %s, using root domain: %s", domain, searchDomain)
	}

	// 提取主域名（例如：www.example.com -> example.com）
	domainParts := strings.Split(searchDomain, ".")
	if len(domainParts) < 2 {
		m.log.Debugf("Invalid domain format: %s", searchDomain)
		return ""
	}

	// 尝试匹配主域名和子域名
	// 例如：example.com, www.example.com, api.example.com 都应该匹配到 example.com
	var mainDomain string
	if len(domainParts) >= 2 {
		mainDomain = strings.Join(domainParts[len(domainParts)-2:], ".")
	}
	m.log.Infof("Looking for DNS provider for domain: %s (main domain: %s)", domain, mainDomain)

	// 按优先级顺序检查所有DNS提供商
	providers := m.dnsManager.GetProvidersSortedByPriority()
	m.log.Infof("Available DNS providers: %v", providers)
	
	for _, providerName := range providers {
		provider, err := m.dnsManager.GetProvider(providerName)
		if err != nil {
			m.log.Debugf("Failed to get provider %s: %v", providerName, err)
			continue
		}

		// 获取该提供商管理的域名列表
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		domains, err := provider.ListDomains(ctx)
		cancel()

		if err != nil {
			m.log.Warnf("Failed to list domains from provider %s: %v", providerName, err)
			continue
		}

		m.log.Infof("Provider %s has %d total records", providerName, len(domains))

		// 检查域名是否在该提供商的域名列表中
		for _, d := range domains {
			if d.Type == "domain" {
				// 精确匹配或主域名匹配
				if strings.EqualFold(d.Name, domain) || strings.EqualFold(d.Name, mainDomain) {
					m.log.Infof("Domain %s matched provider %s (matched domain: %s)", domain, providerName, d.Name)
					return providerName
				}
			}
		}
		
		// 记录该提供商的所有域名以便调试
		domainNames := make([]string, 0)
		for _, d := range domains {
			if d.Type == "domain" {
				domainNames = append(domainNames, d.Name)
			}
		}
		m.log.Infof("Provider %s manages domains: %v", providerName, domainNames)
	}

	// 如果没有找到匹配的提供商，使用默认提供商（如果配置了）
	if m.config.SSL.DefaultDNSProvider != "" {
		_, err := m.dnsManager.GetProvider(m.config.SSL.DefaultDNSProvider)
		if err == nil {
			m.log.Infof("Using default DNS provider %s for domain %s (no exact match found)", m.config.SSL.DefaultDNSProvider, domain)
			return m.config.SSL.DefaultDNSProvider
		}
	}

	// 收集所有已检查的域名列表，用于错误提示
	allCheckedDomains := make([]string, 0)
	for _, providerName := range providers {
		provider, err := m.dnsManager.GetProvider(providerName)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		domains, err := provider.ListDomains(ctx)
		cancel()
		if err == nil {
			for _, d := range domains {
				if d.Type == "domain" && !contains(allCheckedDomains, d.Name) {
					allCheckedDomains = append(allCheckedDomains, d.Name)
				}
			}
		}
	}
	
	m.log.Warnf("未找到域名 %s 对应的 DNS 提供商。主域名: %s，已检查的提供商: %v，这些提供商管理的域名: %v", 
		domain, mainDomain, providers, allCheckedDomains)
	return ""
}

// contains 检查字符串切片中是否包含指定字符串
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// supportsHTTPChallenge 检查是否支持HTTP验证
func (m *Manager) supportsHTTPChallenge() bool {
	for _, method := range m.config.SSL.ChallengeMethods {
		if method == "http-01" {
			return true
		}
	}
	// 如果没有配置挑战方法，默认支持HTTP-01
	return len(m.config.SSL.ChallengeMethods) == 0
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

		// 检查磁盘上是否已有证书，如果已有，比较过期时间，避免用旧证书覆盖新证书
		if existingCertData, err := os.ReadFile(certPath); err == nil {
			if existingBlock, _ := pem.Decode(existingCertData); existingBlock != nil {
				if existingX509Cert, err := x509.ParseCertificate(existingBlock.Bytes); err == nil {
					// 比较过期时间：只有当 acme-cache 中的证书比磁盘上的证书更新（过期时间更晚）时才覆盖
					if x509Cert.NotAfter.Before(existingX509Cert.NotAfter) || x509Cert.NotAfter.Equal(existingX509Cert.NotAfter) {
						m.log.Debugf("Skipping sync for %s: ACME cache cert (expires %v) is not newer than disk cert (expires %v)",
							domain, x509Cert.NotAfter, existingX509Cert.NotAfter)
						continue
					}
					m.log.Infof("ACME cache cert for %s (expires %v) is newer than disk cert (expires %v), will sync",
						domain, x509Cert.NotAfter, existingX509Cert.NotAfter)
				}
			}
		}

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
	return m.requestCertificateWithDNSRetry(domain, providerName, 1) // 不重试，一次失败就结束
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

		// 不重试，一次失败就结束
		// 注释掉重试逻辑，因为 maxRetries 已设置为 1
	}

	return fmt.Errorf("DNS certificate request failed after %d attempts: %w", maxRetries, lastErr)
}

// performDNSChallenge 执行DNS挑战验证
func (m *Manager) performDNSChallenge(domain, providerName string) error {
	m.sendProgressEvent(domain, CertProgressEvent{
		Status:  "dns_init",
		Message: fmt.Sprintf("正在初始化 DNS-01 验证，使用 %s", providerName),
	})

	// 生成账户密钥（如果还没有）
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate account key: %w", err)
	}

	// 创建ACME客户端
	client := &acme.Client{
		Key: accountKey,
	}
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
	account, err = client.Register(ctx, account, acme.AcceptTOS)
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %w", err)
	}

	m.sendProgressEvent(domain, CertProgressEvent{
		Status:  "dns_order",
		Message: "正在创建证书订单...",
	})

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

		// 确定记录名称和DNS记录的域名
		// 对于通配符域名（*.example.com），DNS记录需要在根域名（example.com）下创建
		recordName := GetACMEChallengeRecordNameForWildcard(domain)
		dnsDomain := domain
		if strings.HasPrefix(domain, "*.") {
			// 提取根域名：*.example.com -> example.com
			dnsDomain = domain[2:]
			m.log.Infof("Wildcard domain detected: %s, using root domain for DNS challenge: %s", domain, dnsDomain)
		}

		m.sendProgressEvent(domain, CertProgressEvent{
			Status:  "dns_create_record",
			Message: fmt.Sprintf("正在创建 DNS TXT 记录: %s (在 %s 下)", recordName, dnsDomain),
		})

		// 创建DNS挑战，使用故障转移机制（使用根域名创建DNS记录）
		challengeInfo, err := m.dnsManager.CreateDNSChallengeWithFailover(ctx, dnsDomain, recordName, keyAuth)
		if err != nil {
			return fmt.Errorf("failed to create DNS challenge: %w", err)
		}

		// 清理函数
		defer func() {
			if cleanupErr := m.dnsManager.CleanupDNSChallenge(ctx, challengeInfo); cleanupErr != nil {
				m.log.Warnf("Failed to cleanup DNS challenge: %v", cleanupErr)
			}
		}()

		m.sendProgressEvent(domain, CertProgressEvent{
			Status:  "dns_propagation",
			Message: "等待 DNS 记录传播 (约10秒)...",
		})

		// 等待 DNS 记录传播（简化版：固定等待 10 秒）
		m.log.Infof("Waiting 10 seconds for DNS propagation...")
		time.Sleep(10 * time.Second)

		m.sendProgressEvent(domain, CertProgressEvent{
			Status:  "dns_verify",
			Message: "正在等待 Let's Encrypt 验证 DNS 记录...",
		})

		// 接受挑战
		_, err = client.Accept(ctx, challenge)
		if err != nil {
			return fmt.Errorf("failed to accept challenge: %w", err)
		}

		// 等待挑战完成
		_, err = client.WaitAuthorization(ctx, authz.URI)
		if err != nil {
			// 尝试提取 ACME 错误详情
			errMsg := extractACMEErrorDetails(err)
			m.sendProgressEvent(domain, CertProgressEvent{
				Status:  "dns_verify_failed",
				Message: fmt.Sprintf("Let's Encrypt 验证失败: %s", errMsg),
				Error:   errMsg,
			})
			return fmt.Errorf("authorization failed: %s", errMsg)
		}

		m.sendProgressEvent(domain, CertProgressEvent{
			Status:  "dns_verified",
			Message: "DNS 验证成功!",
		})
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

// GetName 获取组件名称
func (m *Manager) GetName() string {
	return "SSLManager"
}

// Reload 重载 SSL 管理器配置
func (m *Manager) Reload(newConfig *config.Config) error {
	m.log.Info("Reloading SSL manager configuration")
	
	// 更新配置引用
	m.config = newConfig
	
	// 清空旧的 DNS 提供商并重新初始化
	if m.dnsManager != nil {
		m.dnsManager.ClearProviders()
	}
	m.initializeDNSProviders()
	
	// 如果配置了 Email，重新启用/更新 ACME
	if strings.TrimSpace(newConfig.SSL.Email) != "" {
		if err := m.EnableACME(); err != nil {
			m.log.Warnf("Failed to reload ACME configuration: %v", err)
		}
	}
	
	return nil
}

// Validate 验证配置是否适用于此组件
func (m *Manager) Validate(newConfig *config.Config) error {
	// 基本验证已经在 config.Validate() 中完成
	return nil
}

// supportsDNSChallenge 检查是否支持DNS验证
func (m *Manager) supportsDNSChallenge() bool {
	// 如果明确配置了 challenge_methods，检查是否包含 dns-01
	if len(m.config.SSL.ChallengeMethods) > 0 {
		for _, method := range m.config.SSL.ChallengeMethods {
			if method == "dns-01" {
				return true
			}
		}
		return false
	}
	
	// 如果没有配置 challenge_methods，但有可用的 DNS 提供商，默认支持 DNS-01
	// 这样可以自动使用 DNS-01，无需手动配置
	if m.hasAvailableDNSProvider() {
		return true
	}
	
	return false
}

// SupportsDNSChallenge 公开方法：检查是否支持DNS验证
func (m *Manager) SupportsDNSChallenge() bool {
	return m.supportsDNSChallenge()
}

// HasAvailableDNSProvider 公开方法：检查是否有可用的DNS服务商
func (m *Manager) HasAvailableDNSProvider() bool {
	return m.hasAvailableDNSProvider()
}

// FindDNSProviderForDomain 公开方法：查找域名属于哪个DNS提供商
func (m *Manager) FindDNSProviderForDomain(domain string) string {
	return m.findDNSProviderForDomain(domain)
}

// CheckDomainResolution 公开方法：检查域名解析状态
func (m *Manager) CheckDomainResolution(domain string) (bool, string, error) {
	return m.checkDomainResolution(domain)
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

// RegisterDNSProvider 注册DNS provider（公开方法，用于动态注册）
func (m *Manager) RegisterDNSProvider(name string, provider DNSProviderInterface, priority int) {
	m.dnsManager.RegisterProviderWithPriority(name, provider, priority)
	m.log.Infof("Registered DNS provider: %s with priority %d", name, priority)
}

// UnregisterDNSProvider 注销DNS provider（公开方法，用于动态注销）
func (m *Manager) UnregisterDNSProvider(name string) {
	m.dnsManager.UnregisterProvider(name)
	m.log.Infof("Unregistered DNS provider: %s", name)
}

// CreateProgressChannel 为域名创建进度通道
func (m *Manager) CreateProgressChannel(domain string) chan CertProgressEvent {
	m.progressMutex.Lock()
	defer m.progressMutex.Unlock()
	
	ch := make(chan CertProgressEvent, 10) // 缓冲10个事件
	m.progressChannels[domain] = ch
	return ch
}

// GetProgressChannel 获取域名的进度通道
func (m *Manager) GetProgressChannel(domain string) (chan CertProgressEvent, bool) {
	m.progressMutex.RLock()
	defer m.progressMutex.RUnlock()
	
	ch, ok := m.progressChannels[domain]
	return ch, ok
}

// CloseProgressChannel 关闭并删除进度通道
func (m *Manager) CloseProgressChannel(domain string) {
	m.progressMutex.Lock()
	defer m.progressMutex.Unlock()
	
	if ch, ok := m.progressChannels[domain]; ok {
		close(ch)
		delete(m.progressChannels, domain)
	}
}

// sendProgressEvent 发送进度事件（非阻塞）
func (m *Manager) sendProgressEvent(domain string, event CertProgressEvent) {
	m.progressMutex.RLock()
	ch, ok := m.progressChannels[domain]
	m.progressMutex.RUnlock()
	
	if ok {
		select {
		case ch <- event:
		default:
			// 通道已满，跳过（避免阻塞）
		}
	}
}

// getCertificateFromCache 从缓存中获取证书（线程安全）
func (m *Manager) getCertificateFromCache(domain string) *tls.Certificate {
	m.certMutex.RLock()
	defer m.certMutex.RUnlock()
	return m.certCache[domain]
}

// extractACMEErrorDetails 从 ACME 错误中提取详细信息
func extractACMEErrorDetails(err error) string {
	if err == nil {
		return ""
	}

	// 尝试提取 acme.Error 类型的详情
	var acmeErr *acme.Error
	if errors.As(err, &acmeErr) {
		// ACME 错误包含类型、状态码和详细描述
		details := fmt.Sprintf("[%s] %s", acmeErr.ProblemType, acmeErr.Detail)
		if len(acmeErr.Subproblems) > 0 {
			for _, sub := range acmeErr.Subproblems {
				details += fmt.Sprintf(" | 子问题[%s]: %s", sub.Identifier.Value, sub.Detail)
			}
		}
		return details
	}

	// 尝试提取 acme.AuthorizationError 类型的详情
	var authzErr *acme.AuthorizationError
	if errors.As(err, &authzErr) {
		details := fmt.Sprintf("域名 %s 授权失败", authzErr.Identifier)
		if authzErr.Errors != nil {
			for _, e := range authzErr.Errors {
				// Errors 中的元素可能是 *acme.Error
				var subErr *acme.Error
				if errors.As(e, &subErr) {
					details += fmt.Sprintf(" | [%s] %s", subErr.ProblemType, subErr.Detail)
				} else {
					details += fmt.Sprintf(" | %s", e.Error())
				}
			}
		}
		return details
	}

	// 返回原始错误信息
	return err.Error()
}
