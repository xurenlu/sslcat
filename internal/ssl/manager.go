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
