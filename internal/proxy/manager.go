package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"

	"github.com/sirupsen/logrus"
)

// Manager 代理管理器
type Manager struct {
	config          *config.Config
	sslManager      *ssl.Manager
	securityManager *security.Manager
	proxyCache      map[string]*httputil.ReverseProxy
	cacheMutex      sync.RWMutex
	log             *logrus.Entry
}

// NewManager 创建代理管理器
func NewManager(cfg *config.Config, sslMgr *ssl.Manager, secMgr *security.Manager) *Manager {
	return &Manager{
		config:          cfg,
		sslManager:      sslMgr,
		securityManager: secMgr,
		proxyCache:      make(map[string]*httputil.ReverseProxy),
		log: logrus.WithFields(logrus.Fields{
			"component": "proxy_manager",
		}),
	}
}

// Start 启动代理管理器
func (m *Manager) Start() error {
	m.log.Info("Starting proxy manager")
	return nil
}

// Stop 停止代理管理器
func (m *Manager) Stop() {
	m.log.Info("Stopping proxy manager")
}

// GetProxyConfig 获取指定域名的代理配置
func (m *Manager) GetProxyConfig(domain string) *config.ProxyRule {
	return m.config.GetProxyRule(domain)
}

// ProxyRequest 代理请求
func (m *Manager) ProxyRequest(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 获取或创建反向代理
	proxy := m.getOrCreateProxy(rule)

	// 获取真实客户端IP
	clientIP := m.getClientIP(r)

	// 透明代理 - 正确设置所有必要的头部
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	// 设置标准的代理头部
	r.Header.Set("X-Forwarded-Proto", scheme)
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-Port", m.getPort(r))
	r.Header.Set("X-Real-IP", clientIP)

	// 正确处理 X-Forwarded-For 链
	if existing := r.Header.Get("X-Forwarded-For"); existing != "" {
		r.Header.Set("X-Forwarded-For", existing+", "+clientIP)
	} else {
		r.Header.Set("X-Forwarded-For", clientIP)
	}

	// 设置原始请求信息
	r.Header.Set("X-Forwarded-Server", "sslcat")
	r.Header.Set("X-Original-URI", r.RequestURI)
	r.Header.Set("X-Original-Method", r.Method)

	// 执行代理
	proxy.ServeHTTP(w, r)
}

// getOrCreateProxy 获取或创建反向代理
func (m *Manager) getOrCreateProxy(rule *config.ProxyRule) *httputil.ReverseProxy {
	key := fmt.Sprintf("%s:%d", rule.Target, rule.Port)

	m.cacheMutex.RLock()
	if proxy, exists := m.proxyCache[key]; exists {
		m.cacheMutex.RUnlock()
		return proxy
	}
	m.cacheMutex.RUnlock()

	// 创建新的反向代理
	// 允许在配置中直接写入完整URL（包含协议与端口）或仅写主机名/IP
	targetURL := rule.Target
	if !strings.HasPrefix(strings.ToLower(targetURL), "http://") && !strings.HasPrefix(strings.ToLower(targetURL), "https://") {
		if rule.Port > 0 {
			targetURL = "http://" + net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port))
		} else {
			targetURL = "http://" + rule.Target
		}
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		m.log.Errorf("Failed to parse target URL: %v", err)
		return nil
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// 自定义 Director 函数以实现真正的透明代理
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// 调用原始 Director
		originalDirector(req)

		// 保持原始的 Host 头，实现透明代理
		req.Header.Set("Host", req.Host)

		// 移除 Hop-by-hop 头部
		hopHeaders := []string{
			"Connection",
			"Proxy-Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"Te",
			"Trailers",
			"Transfer-Encoding",
			"Upgrade",
		}
		for _, header := range hopHeaders {
			req.Header.Del(header)
		}
	}

	// 自定义传输配置
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// 不验证后端证书，允许自签名证书
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 自定义错误处理
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		m.log.Errorf("Proxy error %s -> %s: %v", r.Host, targetURL, err)

		// 返回错误页面
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `
		<html>
		<head><title>Proxy Error</title></head>
		<body>
			<h1>502 Bad Gateway</h1>
			<p>Unable to connect to upstream: %s</p>
			<p>Error: %v</p>
		</body>
		</html>
		`, targetURL, err)
	}

	// 修改响应
	proxy.ModifyResponse = func(resp *http.Response) error {
		// 移除可能的安全头，让目标服务器自己设置
		resp.Header.Del("Strict-Transport-Security")
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("X-Content-Type-Options")

		// 添加代理标识
		resp.Header.Set("X-Proxy-By", "SSLcat")

		return nil
	}

	// 缓存代理
	m.cacheMutex.Lock()
	m.proxyCache[key] = proxy
	m.cacheMutex.Unlock()

	return proxy
}

// getClientIP 获取客户端真实IP
func (m *Manager) getClientIP(r *http.Request) string {
	// 1. 首先检查 CF-Connecting-IP (Cloudflare)
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" && m.isValidIP(cfIP) {
		return cfIP
	}

	// 2. 检查 X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" && m.isValidIP(xri) {
		return xri
	}

	// 3. 检查 X-Forwarded-For (取第一个非内网IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if m.isValidIP(ip) && !m.isPrivateIP(ip) {
				return ip
			}
		}
		// 如果没有公网IP，返回第一个有效IP
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if m.isValidIP(ip) {
				return ip
			}
		}
	}

	// 4. 检查其他常见头部
	headers := []string{
		"X-Client-IP",
		"X-Forwarded",
		"X-Cluster-Client-IP",
		"Forwarded-For",
		"Forwarded",
	}

	for _, header := range headers {
		if ip := r.Header.Get(header); ip != "" && m.isValidIP(ip) {
			return ip
		}
	}

	// 5. 最后使用RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// isValidIP 检查是否为有效IP地址
func (m *Manager) isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// isPrivateIP 检查是否为内网IP
func (m *Manager) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 检查IPv4内网地址
	if parsedIP.To4() != nil {
		// 10.0.0.0/8
		if parsedIP[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if parsedIP[0] == 172 && parsedIP[1] >= 16 && parsedIP[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if parsedIP[0] == 192 && parsedIP[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (localhost)
		if parsedIP[0] == 127 {
			return true
		}
	}

	// 检查IPv6内网地址
	if parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast() {
		return true
	}

	return false
}

// getPort 获取请求端口
func (m *Manager) getPort(r *http.Request) string {
	if r.TLS != nil {
		return "443"
	}
	return "80"
}

// HandleWebSocket 处理WebSocket代理
func (m *Manager) HandleWebSocket(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 建立WebSocket连接
	conn, err := net.Dial("tcp", net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port)))
	if err != nil {
		http.Error(w, "无法连接到目标服务器", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// 获取客户端连接
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "无法劫持连接", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "无法劫持连接", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// 发送HTTP响应
	clientConn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n"))
	clientConn.Write([]byte("Upgrade: websocket\r\n"))
	clientConn.Write([]byte("Connection: Upgrade\r\n"))
	clientConn.Write([]byte("\r\n"))

	// 开始双向数据转发
	go m.copyData(clientConn, conn)
	m.copyData(conn, clientConn)
}

// copyData 复制数据
func (m *Manager) copyData(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	buffer := make([]byte, 32*1024)
	for {
		n, err := src.Read(buffer)
		if err != nil {
			if err != io.EOF {
				m.log.Debugf("Error reading data: %v", err)
			}
			break
		}

		if n > 0 {
			_, err := dst.Write(buffer[:n])
			if err != nil {
				m.log.Debugf("Error writing data: %v", err)
				break
			}
		}
	}
}

// TestConnection 测试到目标服务器的连接
func (m *Manager) TestConnection(rule *config.ProxyRule) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port)), 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s:%d: %w", rule.Target, rule.Port, err)
	}
	defer conn.Close()

	return nil
}

// GetProxyStats 获取代理统计信息
func (m *Manager) GetProxyStats() map[string]interface{} {
	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()

	stats := map[string]interface{}{
		"cached_proxies": len(m.proxyCache),
		"active_rules":   len(m.config.Proxy.Rules),
	}

	return stats
}
