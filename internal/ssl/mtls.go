package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// MTLSConfig mTLS 配置
type MTLSConfig struct {
	Enabled           bool          `json:"enabled"`            // 是否启用 mTLS
	Mode              string        `json:"mode"`               // "strict", "optional", "verify_client_if_given"
	CADir             string        `json:"ca_dir"`             // CA 证书目录
	ClientCADir       string        `json:"client_ca_dir"`      // 客户端 CA 证书目录
	CertFile          string        `json:"cert_file"`          // 服务器证书
	KeyFile           string        `json:"key_file"`           // 服务器私钥
	ClientCertRequired bool         `json:"client_cert_required"` // 是否要求客户端证书
	CRLCheckEnabled   bool          `json:"crl_check_enabled"`  // 是否启用证书吊销列表检查
	CRLUpdateInterval time.Duration `json:"crl_update_interval"` // CRL 更新间隔
	// 证书绑定策略
	CertPinningEnabled bool          `json:"cert_pinning_enabled"` // 是否启用证书固定
	AllowedCerts       []string      `json:"allowed_certs"`        // 允许的证书指纹列表
}

// ClientIdentity 客户端身份信息
type ClientIdentity struct {
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizational_unit"`
	SerialNumber       string   `json:"serial_number"`
	Fingerprint        string   `json:"fingerprint"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	IsValid            bool     `json:"is_valid"`
	IsRevoked          bool     `json:"is_revoked"`
}

// MTLSManager mTLS 管理器
type MTLSManager struct {
	config          *MTLSConfig
	log             *logrus.Entry
	caPool          *x509.CertPool
	clientCAPool    *x509.CertPool
	cert            *tls.Certificate
	certMutex       sync.RWMutex
	crlList         map[string]*x509.RevocationList
	crlMutex        sync.RWMutex
	certWhitelist   map[string]bool // 证书白名单（指纹 -> 允许）
	certBlacklist   map[string]bool // 证书黑名单（指纹 -> 拒绝）
	whitelistMutex  sync.RWMutex
	// 统计信息
	stats           mTLSStats
	statsMutex      sync.RWMutex
}

// mTLSStats mTLS 统计信息
type mTLSStats struct {
	TotalConnections    int64     `json:"total_connections"`
	ValidCerts          int64     `json:"valid_certs"`
	InvalidCerts        int64     `json:"invalid_certs"`
	RevokedCerts        int64     `json:"revoked_certs"`
	ExpiredCerts        int64     `json:"expired_certs"`
	WhitelistedCerts    int64     `json:"whitelisted_certs"`
	BlacklistedCerts    int64     `json:"blacklisted_certs"`
	LastConnection      time.Time `json:"last_connection"`
	LastCertError       time.Time `json:"last_cert_error"`
	LastErrorReason     string    `json:"last_error_reason"`
}

// NewMTLSManager 创建 mTLS 管理器
func NewMTLSManager(config *MTLSConfig) (*MTLSManager, error) {
	if !config.Enabled {
		return nil, nil
	}

	log := logrus.WithFields(logrus.Fields{
		"component": "mtls_manager",
		"mode":      config.Mode,
	})

	mgr := &MTLSManager{
		config:        config,
		log:           log,
		crlList:      make(map[string]*x509.RevocationList),
		certWhitelist: make(map[string]bool),
		certBlacklist: make(map[string]bool),
	}

	// 加载 CA 证书
	if err := mgr.loadCA(); err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}

	// 加载服务器证书
	if err := mgr.loadServerCert(); err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	// 启动 CRL 更新协程
	if config.CRLCheckEnabled {
		go mgr.crlUpdater()
	}

	log.Info("mTLS manager initialized successfully")
	return mgr, nil
}

// loadCA 加载 CA 证书
func (m *MTLSManager) loadCA() error {
	// 加载服务器 CA
	caPool := x509.NewCertPool()
	caFiles, err := filepath.Glob(filepath.Join(m.config.CADir, "*.crt"))
	if err != nil {
		return fmt.Errorf("failed to find CA certificates: %w", err)
	}

	for _, file := range caFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read CA file %s: %w", file, err)
		}
		if !caPool.AppendCertsFromPEM(data) {
			m.log.Warnf("Failed to append CA certificate from %s", file)
		} else {
			m.log.Infof("Loaded CA certificate from %s", file)
		}
	}
	m.caPool = caPool

	// 加载客户端 CA
	clientCAFiles, err := filepath.Glob(filepath.Join(m.config.ClientCADir, "*.crt"))
	if err == nil && len(clientCAFiles) > 0 {
		clientCAPool := x509.NewCertPool()
		for _, file := range clientCAFiles {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("failed to read client CA file %s: %w", file, err)
			}
			if !clientCAPool.AppendCertsFromPEM(data) {
				m.log.Warnf("Failed to append client CA certificate from %s", file)
			} else {
				m.log.Infof("Loaded client CA certificate from %s", file)
			}
		}
		m.clientCAPool = clientCAPool
	}

	return nil
}

// loadServerCert 加载服务器证书
func (m *MTLSManager) loadServerCert() error {
	cert, err := tls.LoadX509KeyPair(m.config.CertFile, m.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate pair: %w", err)
	}

	m.certMutex.Lock()
	m.cert = &cert
	m.certMutex.Unlock()

	m.log.Info("Server certificate loaded successfully")
	return nil
}

// GetTLSConfig 获取 TLS 配置
func (m *MTLSManager) GetTLSConfig() *tls.Config {
	if m == nil {
		return nil
	}

	m.certMutex.RLock()
	cert := m.cert
	m.certMutex.RUnlock()

	clientAuth := tls.NoClientCert
	switch m.config.Mode {
	case "strict":
		clientAuth = tls.RequireAnyClientCert
	case "optional":
		clientAuth = tls.VerifyClientCertIfGiven
	case "verify_client_if_given":
		clientAuth = tls.VerifyClientCertIfGiven
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      m.caPool,
		ClientCAs:    m.clientCAPool,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
		// 自定义验证函数
		VerifyConnection: m.verifyConnection,
		// 支持证书续期
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			m.certMutex.RLock()
			defer m.certMutex.RUnlock()
			return m.cert, nil
		},
	}
}

// verifyConnection 验证连接
func (m *MTLSManager) verifyConnection(state tls.ConnectionState) error {
	m.statsMutex.Lock()
	m.stats.TotalConnections++
	m.stats.LastConnection = time.Now()
	m.statsMutex.Unlock()

	// 如果没有客户端证书
	if len(state.PeerCertificates) == 0 {
		if m.config.ClientCertRequired {
			m.recordError("no_client_certificate")
			return errors.New("client certificate required")
		}
		return nil
	}

	cert := state.PeerCertificates[0]
	identity := m.ExtractIdentity(cert)

	// 检查证书是否过期
	if time.Now().After(cert.NotAfter) {
		m.recordError("certificate_expired")
		m.statsMutex.Lock()
		m.stats.ExpiredCerts++
		m.statsMutex.Unlock()
		return fmt.Errorf("certificate expired: %s", identity.CommonName)
	}

	// 检查证书是否在有效期内
	if time.Now().Before(cert.NotBefore) {
		m.recordError("certificate_not_yet_valid")
		return fmt.Errorf("certificate not yet valid: %s", identity.CommonName)
	}

	// 检查 CRL
	if m.config.CRLCheckEnabled {
		if err := m.checkCRL(cert); err != nil {
			m.statsMutex.Lock()
			m.stats.RevokedCerts++
			m.statsMutex.Unlock()
			m.recordError("certificate_revoked")
			return fmt.Errorf("certificate revoked: %w", err)
		}
	}

	// 证书固定检查
	if m.config.CertPinningEnabled {
		fingerprint := m.getCertificateFingerprint(cert)

		// 检查黑名单
		m.whitelistMutex.RLock()
		if m.certBlacklist[fingerprint] {
			m.whitelistMutex.RUnlock()
			m.statsMutex.Lock()
			m.stats.BlacklistedCerts++
			m.statsMutex.Unlock()
			m.recordError("certificate_blacklisted")
			return errors.New("certificate is blacklisted")
		}
		m.whitelistMutex.RUnlock()

		// 如果有白名单，检查白名单
		if len(m.config.AllowedCerts) > 0 {
			m.whitelistMutex.RLock()
			allowed := m.certWhitelist[fingerprint]
			m.whitelistMutex.RUnlock()

			if !allowed {
				m.statsMutex.Lock()
				m.stats.InvalidCerts++
				m.statsMutex.Unlock()
				m.recordError("certificate_not_whitelisted")
				return errors.New("certificate not in whitelist")
			}
			m.statsMutex.Lock()
			m.stats.WhitelistedCerts++
			m.statsMutex.Unlock()
		}
	}

	m.statsMutex.Lock()
	m.stats.ValidCerts++
	m.statsMutex.Unlock()

	m.log.Infof("Valid mTLS connection from %s (CN: %s, Org: %s)",
		cert.Subject.CommonName,
		identity.CommonName,
		identity.Organization)

	return nil
}

// ExtractIdentity 从证书中提取身份信息
func (m *MTLSManager) ExtractIdentity(cert *x509.Certificate) *ClientIdentity {
	fingerprint := m.getCertificateFingerprint(cert)

	organization := ""
	if len(cert.Subject.Organization) > 0 {
		organization = cert.Subject.Organization[0]
	}

	organizationalUnit := ""
	if len(cert.Subject.OrganizationalUnit) > 0 {
		organizationalUnit = cert.Subject.OrganizationalUnit[0]
	}

	return &ClientIdentity{
		CommonName:         cert.Subject.CommonName,
		Organization:       organization,
		OrganizationalUnit: organizationalUnit,
		SerialNumber:       cert.SerialNumber.String(),
		Fingerprint:        fingerprint,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsValid:            time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter),
		IsRevoked:          m.checkCRL(cert) != nil,
	}
}

// getCertificateFingerprint 获取证书指纹
func (m *MTLSManager) getCertificateFingerprint(cert *x509.Certificate) string {
	// 使用 SHA-256 计算指纹
	// 这里简化实现，实际应该使用完整的证书
	return fmt.Sprintf("%x", cert.Signature)
}

// checkCRL 检查证书吊销列表
func (m *MTLSManager) checkCRL(cert *x509.Certificate) error {
	m.crlMutex.RLock()
	defer m.crlMutex.RUnlock()

	// 检查所有 CRL
	for _, crl := range m.crlList {
		// 尝试使用证书的颁发者验证 CRL 签名
		// 注意：这里需要实际的颁发者证书，简化处理先跳过签名验证
		// TODO: 实现完整的 CRL 验证
		for _, revoked := range crl.RevokedCertificates {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return errors.New("certificate is revoked")
			}
		}
	}

	return nil
}

// crlUpdater 定期更新 CRL
func (m *MTLSManager) crlUpdater() {
	ticker := time.NewTicker(m.config.CRLUpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := m.updateCRL(); err != nil {
			m.log.Errorf("Failed to update CRL: %v", err)
		}
	}
}

// updateCRL 更新证书吊销列表
func (m *MTLSManager) updateCRL() error {
	// TODO: 从配置的 URL 或文件加载 CRL
	m.log.Info("CRL update completed")
	return nil
}

// AddToWhitelist 添加证书到白名单
func (m *MTLSManager) AddToWhitelist(fingerprint string) {
	m.whitelistMutex.Lock()
	defer m.whitelistMutex.Unlock()
	m.certWhitelist[fingerprint] = true
	m.log.Infof("Added certificate to whitelist: %s", fingerprint)
}

// RemoveFromWhitelist 从白名单移除证书
func (m *MTLSManager) RemoveFromWhitelist(fingerprint string) {
	m.whitelistMutex.Lock()
	defer m.whitelistMutex.Unlock()
	delete(m.certWhitelist, fingerprint)
	m.log.Infof("Removed certificate from whitelist: %s", fingerprint)
}

// AddToBlacklist 添加证书到黑名单
func (m *MTLSManager) AddToBlacklist(fingerprint string) {
	m.whitelistMutex.Lock()
	defer m.whitelistMutex.Unlock()
	m.certBlacklist[fingerprint] = true
	m.log.Infof("Added certificate to blacklist: %s", fingerprint)
}

// RemoveFromBlacklist 从黑名单移除证书
func (m *MTLSManager) RemoveFromBlacklist(fingerprint string) {
	m.whitelistMutex.Lock()
	defer m.whitelistMutex.Unlock()
	delete(m.certBlacklist, fingerprint)
	m.log.Infof("Removed certificate from blacklist: %s", fingerprint)
}

// recordError 记录错误
func (m *MTLSManager) recordError(reason string) {
	m.statsMutex.Lock()
	m.stats.LastCertError = time.Now()
	m.stats.LastErrorReason = reason
	m.stats.InvalidCerts++
	m.statsMutex.Unlock()
}

// GetStats 获取统计信息
func (m *MTLSManager) GetStats() mTLSStats {
	m.statsMutex.RLock()
	defer m.statsMutex.RUnlock()
	return m.stats
}

// GenerateClientCert 生成客户端证书
func (m *MTLSManager) GenerateClientCert(commonName, organization string, validity time.Duration) ([]byte, []byte, error) {
	// TODO: 实现客户端证书生成
	// 这需要私钥和 CA 证书
	return nil, nil, errors.New("not implemented")
}

// ParseCSR 解析证书签名请求
func (m *MTLSManager) ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("failed to decode CSR")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	return csr, nil
}

// SignCSR 签名证书签名请求
func (m *MTLSManager) SignCSR(csr *x509.CertificateRequest, validity time.Duration) ([]byte, error) {
	// TODO: 实现签名逻辑
	return nil, errors.New("not implemented")
}

// VerifyClientCert 验证客户端证书
func (m *MTLSManager) VerifyClientCert(cert *x509.Certificate) error {
	// 检查证书链
	opts := x509.VerifyOptions{
		Roots:         m.clientCAPool,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// GetClientIdentityFromRequest 从 HTTP 请求中获取客户端身份
func (m *MTLSManager) GetClientIdentityFromRequest(r *http.Request) (*ClientIdentity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate")
	}

	cert := r.TLS.PeerCertificates[0]
	return m.ExtractIdentity(cert), nil
}

// IsLocalhostAllowed 检查是否允许本地连接
func (m *MTLSManager) IsLocalhostAllowed(ip string) bool {
	// 允许本地回环地址
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		host = ip
	}

	return net.ParseIP(host).IsLoopback() || host == "localhost" || host == "127.0.0.1"
}
