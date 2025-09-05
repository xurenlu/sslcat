package ssl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"withssl/internal/config"

	"github.com/sirupsen/logrus"
)

// Manager SSL证书管理器
type Manager struct {
	config    *config.Config
	certCache map[string]*tls.Certificate
	certMutex sync.RWMutex
	stopChan  chan struct{}
	log       *logrus.Entry
}

// NewManager 创建SSL管理器
func NewManager(cfg *config.Config) (*Manager, error) {
	log := logrus.WithFields(logrus.Fields{
		"component": "ssl_manager",
	})

	manager := &Manager{
		config:    cfg,
		certCache: make(map[string]*tls.Certificate),
		stopChan:  make(chan struct{}),
		log:       log,
	}

	return manager, nil
}

// Start 启动SSL管理器
func (m *Manager) Start() error {
	m.log.Info("启动SSL管理器")

	// 启动证书自动续期
	if m.config.SSL.AutoRenew {
		go m.autoRenewCerts()
	}

	return nil
}

// Stop 停止SSL管理器
func (m *Manager) Stop() {
	m.log.Info("停止SSL管理器")
	close(m.stopChan)
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
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			domain := hello.ServerName
			if domain == "" {
				domain = "localhost"
			}
			
			m.log.Debugf("请求域名: %s 的SSL证书", domain)
			cert, err := m.GetCertificate(domain)
			if err != nil {
				m.log.Errorf("获取证书失败 %s: %v", domain, err)
				return nil, err
			}
			
			return cert, nil
		},
		NextProtos: []string{"h2", "http/1.1"}, // 支持 HTTP/2
		MinVersion: tls.VersionTLS12,           // 最低 TLS 1.2
	}
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
