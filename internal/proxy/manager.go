package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"withssl/internal/config"
	"withssl/internal/security"
	"withssl/internal/ssl"

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
	m.log.Info("启动代理管理器")
	return nil
}

// Stop 停止代理管理器
func (m *Manager) Stop() {
	m.log.Info("停止代理管理器")
}

// GetProxyConfig 获取指定域名的代理配置
func (m *Manager) GetProxyConfig(domain string) *config.ProxyRule {
	return m.config.GetProxyRule(domain)
}

// ProxyRequest 代理请求
func (m *Manager) ProxyRequest(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 获取或创建反向代理
	proxy := m.getOrCreateProxy(rule)

	// 修改请求头
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", m.getClientIP(r))
	r.Header.Set("X-Real-IP", m.getClientIP(r))

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
	targetURL := fmt.Sprintf("http://%s:%d", rule.Target, rule.Port)
	target, err := url.Parse(targetURL)
	if err != nil {
		m.log.Errorf("解析目标URL失败: %v", err)
		return nil
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

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
	}

	// 自定义错误处理
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		m.log.Errorf("代理错误 %s -> %s: %v", r.Host, targetURL, err)

		// 返回错误页面
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `
		<html>
		<head><title>代理错误</title></head>
		<body>
			<h1>502 Bad Gateway</h1>
			<p>无法连接到目标服务器: %s</p>
			<p>错误: %v</p>
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
		resp.Header.Set("X-Proxy-By", "WithSSL")

		return nil
	}

	// 缓存代理
	m.cacheMutex.Lock()
	m.proxyCache[key] = proxy
	m.cacheMutex.Unlock()

	return proxy
}

// getClientIP 获取客户端IP
func (m *Manager) getClientIP(r *http.Request) string {
	// 优先使用X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 使用X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 使用RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// HandleWebSocket 处理WebSocket代理
func (m *Manager) HandleWebSocket(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 建立WebSocket连接
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", rule.Target, rule.Port))
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
				m.log.Debugf("读取数据错误: %v", err)
			}
			break
		}

		if n > 0 {
			_, err := dst.Write(buffer[:n])
			if err != nil {
				m.log.Debugf("写入数据错误: %v", err)
				break
			}
		}
	}
}

// TestConnection 测试到目标服务器的连接
func (m *Manager) TestConnection(rule *config.ProxyRule) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", rule.Target, rule.Port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("无法连接到 %s:%d: %w", rule.Target, rule.Port, err)
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
