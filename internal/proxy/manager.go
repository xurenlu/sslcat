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

	"github.com/xurenlu/sslcat/internal/cache"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"

	"github.com/sirupsen/logrus"
)

// loggingTransport 包装Transport以记录实际发送的请求
type loggingTransport struct {
	base http.RoundTripper
	log  *logrus.Entry
}

// Manager 代理管理器
type Manager struct {
	config          *config.Config
	sslManager      *ssl.Manager
	securityManager *security.Manager
	proxyCache      map[string]*httputil.ReverseProxy
	cacheMutex      sync.RWMutex
	cdnCache        *cache.CDNCache
	log             *logrus.Entry
}

// NewManager 创建代理管理器
func NewManager(cfg *config.Config, sslMgr *ssl.Manager, secMgr *security.Manager, cdn *cache.CDNCache) *Manager {
	return &Manager{
		config:          cfg,
		sslManager:      sslMgr,
		securityManager: secMgr,
		proxyCache:      make(map[string]*httputil.ReverseProxy),
		cdnCache:        cdn,
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

// PurgeCDN 清理 CDN 缓存
func (m *Manager) PurgeCDN(matchType, pattern, mediaCSV string) error {
	if m.cdnCache == nil {
		return nil
	}
	if matchType == "" || strings.EqualFold(matchType, "all") {
		return m.cdnCache.PurgeAll()
	}
	return m.cdnCache.PurgeByCondition(matchType, pattern, mediaCSV)
}

// GetProxyConfig 获取指定域名的代理配置
func (m *Manager) GetProxyConfig(domain string) *config.ProxyRule {
	return m.config.GetProxyRule(domain)
}

// GetCDNCache 返回缓存器（只读访问）
func (m *Manager) GetCDNCache() interface{ Stats() map[string]any } {
	return m.cdnCache
}

// ProxyRequest 代理请求
func (m *Manager) ProxyRequest(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	// 记录原始请求信息
	m.logRequestDetails(r, "INCOMING_REQUEST", rule)

	// CDN 缓存直出（仅 GET/HEAD，且全局或域名启用）
	cdnEnabled := m.config.CDNCache.Enabled || (rule != nil && rule.CDNEnabled)
	if m.cdnCache != nil && cdnEnabled {
		// 临时修改请求Host为后端域名，确保缓存路径一致性
		originalHost := r.Host
		if rule != nil {
			backendHost := m.extractHostFromTarget(rule.Target, rule.Port)
			r.Host = backendHost
		}
		served := m.cdnCache.ServeIfFreshWithConfig(w, r, cdnEnabled)
		// 恢复原始Host
		r.Host = originalHost
		if served {
			m.log.Debugf("Served from CDN cache for %s %s", r.Method, r.URL.Path)
			return
		}
	}
	// 获取或创建反向代理
	proxy := m.getOrCreateProxy(rule)

	// 获取真实客户端IP
	clientIP := m.getClientIP(r)

	// 透明代理 - 正确设置所有必要的头部
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}

	// 检查是否启用了CDN缓存（全局或域名级别）
	// cdnEnabled 已在上面定义
	isCloudStorage := m.isCloudStorageService(rule.Target)

	// 在CDN模式或云存储模式下，预先清理可能存在的代理头部
	if cdnEnabled || isCloudStorage {
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Forwarded-Host")
		r.Header.Del("X-Forwarded-Proto")
		r.Header.Del("X-Forwarded-Port")
		r.Header.Del("X-Real-IP")
		r.Header.Del("X-Forwarded-Server")
		r.Header.Del("X-Original-URI")
		r.Header.Del("X-Original-Method")

		// 对于云服务，进行更彻底的头部清理
		if isCloudStorage {
			r.Header.Del("X-Forwarded")
			r.Header.Del("X-Client-IP")
			r.Header.Del("X-Cluster-Client-IP")
			r.Header.Del("Forwarded-For")
			r.Header.Del("Forwarded")
			r.Header.Del("CF-Connecting-IP")

			// 处理可能导致防盗链问题的Referer
			if referer := r.Header.Get("Referer"); referer != "" && strings.Contains(referer, "local.") {
				r.Header.Del("Referer")
				m.log.Debugf("Pre-removed local Referer for cloud service: %s", referer)
			}
		}

		m.log.Debugf("Pre-cleaned proxy headers for %s (CDN: %v, 云服务: %v)", r.Host, cdnEnabled, isCloudStorage)
	}

	if !cdnEnabled && !isCloudStorage {
		// 非CDN且非云服务模式：设置标准的代理头部
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

		m.log.Debugf("Added proxy headers (non-CDN, non-cloud mode) for %s", r.Host)
	} else {
		// CDN模式或云服务模式：最小化头部，避免干扰
		if cdnEnabled && isCloudStorage {
			m.log.Infof("云服务 + CDN mode enabled for %s, skipping proxy headers", r.Host)
		} else if isCloudStorage {
			m.log.Infof("云服务模式 enabled for %s, skipping proxy headers", r.Host)
		} else if cdnEnabled {
			m.log.Infof("CDN mode enabled for %s, skipping proxy headers", r.Host)
		}
	}

	// 执行代理
	// 在 ModifyResponse 中做缓存落盘（全局或域名启用）
	originalModify := proxy.ModifyResponse
	proxy.ModifyResponse = func(resp *http.Response) error {
		// 记录响应详情
		m.logResponseDetails(resp, rule)

		if originalModify != nil {
			if err := originalModify(resp); err != nil {
				return err
			}
		}
		// 移除可能的安全头，让目标服务器自己设置
		resp.Header.Del("Strict-Transport-Security")
		resp.Header.Del("X-Frame-Options")
		resp.Header.Del("X-Content-Type-Options")
		// 添加代理标识
		resp.Header.Set("X-Proxy-By", "SSLcat")
		// CDN 缓存落盘（全局或域名启用）
		// 使用之前定义的cdnEnabled变量
		if m.cdnCache != nil && cdnEnabled {
			if rule != nil && rule.CDNDefaultTTLSeconds > 0 {
				resp.Header.Set("X-SSLcat-CDN-Default-TTL", strconv.Itoa(rule.CDNDefaultTTLSeconds))
			}
			// 临时修改请求Host为后端域名，确保缓存路径一致性
			originalHost := resp.Request.Host
			if rule != nil {
				backendHost := m.extractHostFromTarget(rule.Target, rule.Port)
				resp.Request.Host = backendHost
			}
			m.cdnCache.MaybeStoreWithConfig(resp, cdnEnabled)
			// 恢复原始Host
			resp.Request.Host = originalHost
			if rule != nil {
				resp.Header.Del("X-SSLcat-CDN-Default-TTL")
			}
		}
		return nil
	}

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
		// 只有当target不包含协议时才添加协议和端口
		if rule.Port > 0 {
			targetURL = "http://" + net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port))
		} else {
			targetURL = "http://" + rule.Target
		}
	} else {
		// target已经包含完整URL，检查是否需要添加端口
		// 只有当URL中没有端口且rule.Port > 0时才添加端口
		if rule.Port > 0 {
			// 检查URL是否已经包含端口
			parsedURL, err := url.Parse(targetURL)
			if err == nil && parsedURL.Port() == "" {
				// URL中没有端口，添加端口
				if strings.Contains(targetURL, ":") {
					// 处理IPv6地址格式 [::1]:8080
					if strings.Contains(targetURL, "[") && strings.Contains(targetURL, "]:") {
						// 已经是IPv6格式，不需要修改
					} else {
						// 普通格式，添加端口
						targetURL = targetURL + ":" + strconv.Itoa(rule.Port)
					}
				} else {
					// 没有冒号，直接添加端口
					targetURL = targetURL + ":" + strconv.Itoa(rule.Port)
				}
			}
		}
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		m.log.Errorf("Failed to parse target URL: %v", err)
		return nil
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// 自定义 Director 函数以实现智能Host头转发
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		// 保存原始Host，因为原始Director会修改它
		originalHost := req.Host

		// 调用原始 Director
		originalDirector(req)

		// 智能Host头转发逻辑
		// 如果后端配置的是IP地址，则转发原始的Host名
		// 如果后端配置的是域名，则使用后端原有的域名作为Host
		if m.isIPAddress(rule.Target) {
			// 后端是IP地址，保持原始的Host头，实现透明代理
			req.Host = originalHost
			req.Header.Set("Host", originalHost)
			m.log.Debugf("Backend is IP (%s), forwarding original Host: %s", rule.Target, originalHost)
		} else {
			// 后端是域名，根据配置决定Host头部处理方式
			if rule.OptimizeHostHeader {
				// 启用Host头部优化：使用后端配置的域名作为Host
				m.log.Infof("开始Host头部优化: target=%s, port=%d", rule.Target, rule.Port)
				backendHost := m.extractHostFromTarget(rule.Target, rule.Port)
				m.log.Infof("extractHostFromTarget返回: %s", backendHost)

				// 如果是云存储服务，根据配置决定Host头部
				if m.isCloudStorageService(rule.Target) {
					m.log.Infof("检测到云存储服务: %s", rule.Target)
					// 对于云存储，优先使用配置的端点，否则使用检测到的端点
					if rule.CloudStorageEndpoint != "" {
						backendHost = rule.CloudStorageEndpoint
						m.log.Infof("使用配置的云存储端点: %s", backendHost)
					} else if cloudInfo := m.detectCloudStorageInfo(rule.Target); cloudInfo != nil {
						backendHost = cloudInfo.Endpoint
						m.log.Infof("使用检测到的云存储端点: %s", backendHost)
					}
					m.log.Infof("云存储模式: 使用端点 %s (配置: %s)", backendHost, rule.CloudStorageEndpoint)
				}

				// 关键修复：同时设置 req.Host 和 Header，覆盖原始Director的设置
				req.Host = backendHost
				req.Header.Set("Host", backendHost)

				m.log.Infof("Host头部优化已启用: 设置Host为 %s (原: %s)", backendHost, originalHost)
			} else {
				// 禁用Host头部优化：保持原始的Host头，实现透明代理
				req.Host = originalHost
				req.Header.Set("Host", originalHost)
				m.log.Infof("Host头部优化已禁用: 保持原始Host %s", originalHost)
			}
		}

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

		// 检查是否为云存储服务
		isCloudStorage := m.isCloudStorageService(rule.Target)
		cdnEnabled := m.config.CDNCache.Enabled || (rule != nil && rule.CDNEnabled)

		if isCloudStorage || cdnEnabled {
			// 移除所有可能干扰的代理头部
			req.Header.Del("X-Forwarded-Host")
			req.Header.Del("X-Forwarded-Server")
			req.Header.Del("X-Original-Uri")
			req.Header.Del("X-Original-Method")
			req.Header.Del("X-Forwarded-For")
			req.Header.Del("X-Real-IP")
			req.Header.Del("X-Forwarded-Proto")
			req.Header.Del("X-Forwarded-Port")

			// 对于云服务，还需要移除一些额外的头部
			if isCloudStorage {
				req.Header.Del("X-Forwarded")
				req.Header.Del("X-Client-IP")
				req.Header.Del("X-Cluster-Client-IP")
				req.Header.Del("Forwarded-For")
				req.Header.Del("Forwarded")
				req.Header.Del("CF-Connecting-IP")
				// 对于防盗链敏感的服务，可选择性移除或修改Referer
				if referer := req.Header.Get("Referer"); referer != "" && strings.Contains(referer, "local.") {
					// 移除指向本地域名的Referer，避免触发防盗链
					req.Header.Del("Referer")
					m.log.Debugf("Removed local Referer for OSS: %s", referer)
				}
			}

			if isCloudStorage && cdnEnabled {
				m.log.Infof("云服务 + CDN mode: removed all proxy headers for target: %s", rule.Target)
			} else if isCloudStorage {
				m.log.Infof("云服务模式: 已移除防盗链和代理头部 for target: %s", rule.Target)
			} else if cdnEnabled {
				m.log.Infof("CDN mode: removed proxy headers for target: %s", rule.Target)
			}
		}

		// 记录Host字段的最终状态
		m.log.Infof("最终发送的Host信息 - req.Host: %s, Header['Host']: %s", req.Host, req.Header.Get("Host"))

		// 记录向上游发送的请求详情
		m.logRequestDetails(req, "OUTGOING_REQUEST", rule)
	}

	// 自定义传输配置
	baseTransport := &http.Transport{
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

	// 包装Transport以记录实际发送的请求
	proxy.Transport = &loggingTransport{
		base: baseTransport,
		log:  m.log,
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

	// 检查是否为内网IP段
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // 链路本地地址
		"::1/128",        // IPv6 本地回环
		"fc00::/7",       // IPv6 私有地址
		"fe80::/10",      // IPv6 链路本地地址
	}

	for _, block := range privateBlocks {
		_, network, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// isIPAddress 检查目标是否为IP地址（包括IPv4和IPv6）
func (m *Manager) isIPAddress(target string) bool {
	// 移除可能的协议前缀
	if strings.HasPrefix(strings.ToLower(target), "http://") {
		target = target[7:]
	} else if strings.HasPrefix(strings.ToLower(target), "https://") {
		target = target[8:]
	}

	// 处理IPv6地址格式 [2001:db8::1]:8080
	if strings.HasPrefix(target, "[") && strings.Contains(target, "]:") {
		idx := strings.Index(target, "]:")
		if idx != -1 {
			target = target[1:idx] // 移除方括号
		}
	} else if strings.Contains(target, ":") {
		// 处理普通端口号格式
		idx := strings.LastIndex(target, ":")
		if idx != -1 {
			portPart := target[idx+1:]
			if _, err := strconv.Atoi(portPart); err == nil {
				target = target[:idx]
			}
		}
	}

	// 尝试解析为IP地址
	return net.ParseIP(target) != nil
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

// logRequestDetails 记录请求详情
func (m *Manager) logRequestDetails(r *http.Request, requestType string, rule *config.ProxyRule) {
	// 构建目标地址信息
	targetInfo := "unknown"
	if rule != nil {
		targetInfo = m.buildTargetInfo(rule)
	}

	// 获取实际的Host头（可能已经被Director函数修改）
	actualHost := r.Header.Get("Host")
	if actualHost == "" {
		actualHost = r.Host
	}

	// 记录基本请求信息
	m.log.WithFields(logrus.Fields{
		"type":           requestType,
		"method":         r.Method,
		"url":            r.URL.String(),
		"host":           actualHost,
		"target":         targetInfo,
		"user_agent":     r.Header.Get("User-Agent"),
		"client_ip":      m.getClientIP(r),
		"content_type":   r.Header.Get("Content-Type"),
		"content_length": r.ContentLength,
	}).Info("HTTP请求详情")

	// 记录重要的请求头部
	importantHeaders := []string{
		"Authorization",
		"Cookie",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Forwarded-Proto",
		"X-Forwarded-Host",
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
		"Cache-Control",
		"Referer",
	}

	headers := make(map[string]string)
	for _, header := range importantHeaders {
		if value := r.Header.Get(header); value != "" {
			// 对敏感信息进行脱敏处理
			if header == "Authorization" || header == "Cookie" {
				if len(value) > 20 {
					headers[header] = value[:20] + "..."
				} else {
					headers[header] = "***"
				}
			} else {
				headers[header] = value
			}
		}
	}

	if len(headers) > 0 {
		m.log.WithFields(logrus.Fields{
			"type":    requestType,
			"headers": headers,
		}).Debug("请求头部信息")
	}

	// 记录请求体（仅对POST/PUT等有body的请求，且限制大小）
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		if r.ContentLength > 0 && r.ContentLength < 1024 { // 只记录小于1KB的请求体
			body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
			if err == nil && len(body) > 0 {
				// 重新设置请求体，因为ReadAll会消耗掉原始body
				r.Body = io.NopCloser(strings.NewReader(string(body)))
				m.log.WithFields(logrus.Fields{
					"type": requestType,
					"body": string(body),
				}).Debug("请求体内容")
			}
		}
	}
}

// logResponseDetails 记录响应详情
func (m *Manager) logResponseDetails(resp *http.Response, rule *config.ProxyRule) {
	// 构建目标地址信息
	targetInfo := "unknown"
	if rule != nil {
		targetInfo = m.buildTargetInfo(rule)
	}

	// 记录基本响应信息
	m.log.WithFields(logrus.Fields{
		"type":           "RESPONSE",
		"status_code":    resp.StatusCode,
		"status":         resp.Status,
		"target":         targetInfo,
		"content_type":   resp.Header.Get("Content-Type"),
		"content_length": resp.ContentLength,
		"server":         resp.Header.Get("Server"),
	}).Info("HTTP响应详情")

	// 记录重要的响应头部
	importantHeaders := []string{
		"Set-Cookie",
		"Location",
		"Cache-Control",
		"Expires",
		"Last-Modified",
		"ETag",
		"Content-Encoding",
		"Transfer-Encoding",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Strict-Transport-Security",
	}

	headers := make(map[string]string)
	for _, header := range importantHeaders {
		if value := resp.Header.Get(header); value != "" {
			// 对敏感信息进行脱敏处理
			if header == "Set-Cookie" {
				if len(value) > 50 {
					headers[header] = value[:50] + "..."
				} else {
					headers[header] = "***"
				}
			} else {
				headers[header] = value
			}
		}
	}

	if len(headers) > 0 {
		m.log.WithFields(logrus.Fields{
			"type":    "RESPONSE",
			"headers": headers,
		}).Debug("响应头部信息")
	}
}

// buildTargetInfo 构建目标地址信息用于日志记录
func (m *Manager) buildTargetInfo(rule *config.ProxyRule) string {
	if rule == nil {
		return "unknown"
	}

	// 如果target已经包含完整URL，直接使用
	if strings.HasPrefix(strings.ToLower(rule.Target), "http://") || strings.HasPrefix(strings.ToLower(rule.Target), "https://") {
		return rule.Target
	}

	// 如果target不包含协议，构建完整的目标信息
	if rule.Port > 0 {
		return fmt.Sprintf("%s:%d", rule.Target, rule.Port)
	}
	return rule.Target
}

// extractHostFromTarget 从目标配置中提取Host头信息
func (m *Manager) extractHostFromTarget(target string, port int) string {
	m.log.Infof("extractHostFromTarget调用: target=%s, port=%d", target, port)

	// 如果target包含完整URL，解析出域名和端口
	if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
		m.log.Infof("target包含协议，开始解析URL")
		parsedURL, err := url.Parse(target)
		if err == nil {
			// 检查是否为OSS或其他云服务，对于这些服务，Host头部不应包含标准端口号
			hostname := parsedURL.Hostname()
			m.log.Infof("解析URL成功: hostname=%s, port=%s", hostname, parsedURL.Port())
			isCloudService := strings.Contains(strings.ToLower(hostname), "aliyuncs.com") ||
				strings.Contains(strings.ToLower(hostname), "amazonaws.com") ||
				strings.Contains(strings.ToLower(hostname), "qcloud.com") ||
				strings.Contains(strings.ToLower(hostname), "myqcloud.com")
			m.log.Infof("云服务检测结果: %v", isCloudService)

			// 如果URL中已经有端口
			if parsedURL.Port() != "" {
				urlPort, _ := strconv.Atoi(parsedURL.Port())

				// 对于云服务，如果是标准端口（80/443），则不包含端口号
				if isCloudService && (urlPort == 80 || urlPort == 443) {
					m.log.Infof("云服务标准端口，返回hostname: %s", hostname)
					return hostname
				}

				// 对于云服务，即使是非标准端口，也不包含端口号（云服务通常只支持标准端口）
				if isCloudService {
					m.log.Infof("云服务非标准端口，仍返回hostname: %s", hostname)
					return hostname
				}

				// 对于非云服务，保留端口号
				m.log.Infof("非云服务，返回完整Host: %s", parsedURL.Host)
				return parsedURL.Host
			}

			// 如果URL中没有端口，使用配置中的端口
			if port > 0 && port != 80 && port != 443 {
				// 对于云服务，即使配置了非标准端口，也不包含端口号（云服务通常只支持标准端口）
				if isCloudService {
					m.log.Infof("云服务，配置了非标准端口，仍返回hostname: %s", hostname)
					return hostname
				}
				result := net.JoinHostPort(hostname, strconv.Itoa(port))
				m.log.Infof("非云服务，添加配置端口，返回: %s", result)
				return result
			}
			m.log.Infof("无需添加端口，返回hostname: %s", hostname)
			return hostname
		}
	}

	// 如果target不包含协议，直接使用target和port
	// 检查是否为云服务域名
	isCloudService := strings.Contains(strings.ToLower(target), "aliyuncs.com") ||
		strings.Contains(strings.ToLower(target), "amazonaws.com") ||
		strings.Contains(strings.ToLower(target), "qcloud.com") ||
		strings.Contains(strings.ToLower(target), "myqcloud.com")

	if port > 0 && port != 80 && port != 443 {
		// 对于云服务，不包含端口号
		if isCloudService {
			return target
		}
		return net.JoinHostPort(target, strconv.Itoa(port))
	}
	return target
}

// RoundTrip 实现http.RoundTripper接口，记录实际发送的请求
func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 构造等效的curl命令
	curlCmd := lt.buildCurlCommand(req)

	// 记录实际发送的请求
	lt.log.WithFields(logrus.Fields{
		"type":           "ACTUAL_OUTGOING_REQUEST",
		"method":         req.Method,
		"url":            req.URL.String(),
		"host":           req.Header.Get("Host"),
		"user_agent":     req.Header.Get("User-Agent"),
		"content_type":   req.Header.Get("Content-Type"),
		"content_length": req.ContentLength,
		"all_headers":    req.Header,
		"curl_command":   curlCmd,
	}).Info("实际发送给上游的HTTP请求")

	// 单独记录curl命令，便于复制
	lt.log.Infof("等效的curl命令: %s", curlCmd)

	// 记录重要的请求头部
	importantHeaders := []string{
		"Authorization",
		"Cookie",
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Forwarded-Proto",
		"X-Forwarded-Host",
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
		"Cache-Control",
		"Referer",
	}

	headers := make(map[string]string)
	for _, header := range importantHeaders {
		if value := req.Header.Get(header); value != "" {
			// 对敏感信息进行脱敏处理
			if header == "Authorization" || header == "Cookie" {
				if len(value) > 20 {
					headers[header] = value[:20] + "..."
				} else {
					headers[header] = "***"
				}
			} else {
				headers[header] = value
			}
		}
	}

	if len(headers) > 0 {
		lt.log.WithFields(logrus.Fields{
			"type":    "ACTUAL_OUTGOING_REQUEST",
			"headers": headers,
		}).Debug("实际发送的请求头部信息")
	}

	// 执行实际的请求
	resp, err := lt.base.RoundTrip(req)

	// 记录响应
	if resp != nil {
		lt.log.WithFields(logrus.Fields{
			"type":           "ACTUAL_RESPONSE",
			"status_code":    resp.StatusCode,
			"status":         resp.Status,
			"content_type":   resp.Header.Get("Content-Type"),
			"content_length": resp.ContentLength,
			"server":         resp.Header.Get("Server"),
		}).Info("上游服务器实际返回的HTTP响应")
	}

	return resp, err
}

// buildCurlCommand 构造等效的curl命令
func (lt *loggingTransport) buildCurlCommand(req *http.Request) string {
	var parts []string

	// 基础curl命令
	parts = append(parts, "curl")

	// HTTP方法
	if req.Method != "GET" {
		parts = append(parts, "-X", req.Method)
	}

	// 添加所有请求头
	for name, values := range req.Header {
		for _, value := range values {
			// 对特殊字符进行转义
			escapedValue := strings.ReplaceAll(value, "'", "'\\''")
			parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", name, escapedValue))
		}
	}

	// 如果有请求体
	if req.Body != nil && req.ContentLength > 0 {
		// 注意：这里无法读取Body内容，因为Body已经被消费了
		// 只能提示用户手动添加
		if req.ContentLength > 0 {
			parts = append(parts, "-d", "'[REQUEST_BODY]'")
		}
	}

	// 添加URL（使用单引号包围以避免shell解释）
	parts = append(parts, fmt.Sprintf("'%s'", req.URL.String()))

	// 添加一些常用选项
	parts = append(parts, "-v")         // 详细输出
	parts = append(parts, "--insecure") // 忽略SSL证书验证（如果需要）

	return strings.Join(parts, " ")
}

// CloudStorageInfo 云存储服务信息
type CloudStorageInfo struct {
	Type     string `json:"type"`     // aliyun_oss, aws_s3, tencent_cos
	Name     string `json:"name"`     // 服务名称
	Region   string `json:"region"`   // 区域
	Bucket   string `json:"bucket"`   // 存储桶
	Endpoint string `json:"endpoint"` // 端点
}

// isCloudStorageService 检测是否为云存储服务
func (m *Manager) isCloudStorageService(target string) bool {
	targetLower := strings.ToLower(target)
	return strings.Contains(targetLower, "aliyuncs.com") ||
		strings.Contains(targetLower, "amazonaws.com") ||
		strings.Contains(targetLower, "qcloud.com") ||
		strings.Contains(targetLower, "myqcloud.com") ||
		strings.Contains(targetLower, "oss-") ||
		strings.Contains(targetLower, ".s3.") ||
		strings.Contains(targetLower, ".cos.")
}

// detectCloudStorageInfo 检测云存储服务详细信息
func (m *Manager) detectCloudStorageInfo(target string) *CloudStorageInfo {
	targetLower := strings.ToLower(target)

	// 提取hostname（去除协议）
	extractHostname := func(target string) string {
		if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
			if parsedURL, err := url.Parse(target); err == nil {
				return parsedURL.Hostname()
			}
		}
		return target
	}

	// 阿里云OSS检测
	if strings.Contains(targetLower, "aliyuncs.com") || strings.Contains(targetLower, "oss-") {
		hostname := extractHostname(target)
		// 解析bucket.oss-region.aliyuncs.com格式
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{
				Type:     "aliyun_oss",
				Name:     "阿里云OSS",
				Bucket:   parts[0],
				Region:   extractRegionFromOSS(parts),
				Endpoint: hostname,
			}
		}
		return &CloudStorageInfo{
			Type:     "aliyun_oss",
			Name:     "阿里云OSS",
			Endpoint: hostname,
		}
	}

	// AWS S3检测
	if strings.Contains(targetLower, "amazonaws.com") || strings.Contains(targetLower, ".s3.") {
		hostname := extractHostname(target)
		// 解析bucket.s3-region.amazonaws.com格式
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{
				Type:     "aws_s3",
				Name:     "AWS S3",
				Bucket:   parts[0],
				Region:   extractRegionFromS3(parts),
				Endpoint: hostname,
			}
		}
		return &CloudStorageInfo{
			Type:     "aws_s3",
			Name:     "AWS S3",
			Endpoint: hostname,
		}
	}

	// 腾讯云COS检测
	if strings.Contains(targetLower, "qcloud.com") || strings.Contains(targetLower, "myqcloud.com") || strings.Contains(targetLower, ".cos.") {
		hostname := extractHostname(target)
		// 解析bucket.cos-region.myqcloud.com格式
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{
				Type:     "tencent_cos",
				Name:     "腾讯云COS",
				Bucket:   parts[0],
				Region:   extractRegionFromCOS(parts),
				Endpoint: hostname,
			}
		}
		return &CloudStorageInfo{
			Type:     "tencent_cos",
			Name:     "腾讯云COS",
			Endpoint: hostname,
		}
	}

	return nil
}

// extractRegionFromOSS 从阿里云OSS域名中提取区域信息
func extractRegionFromOSS(parts []string) string {
	if len(parts) < 2 {
		return ""
	}
	// 格式: bucket.oss-region.aliyuncs.com
	ossPart := parts[1]
	if strings.HasPrefix(ossPart, "oss-") {
		return strings.TrimPrefix(ossPart, "oss-")
	}
	return ""
}

// extractRegionFromS3 从AWS S3域名中提取区域信息
func extractRegionFromS3(parts []string) string {
	if len(parts) < 2 {
		return ""
	}
	// 格式: bucket.s3-region.amazonaws.com
	s3Part := parts[1]
	if strings.HasPrefix(s3Part, "s3-") {
		return strings.TrimPrefix(s3Part, "s3-")
	}
	return ""
}

// extractRegionFromCOS 从腾讯云COS域名中提取区域信息
func extractRegionFromCOS(parts []string) string {
	if len(parts) < 2 {
		return ""
	}
	// 格式: bucket.cos-region.myqcloud.com
	cosPart := parts[1]
	if strings.HasPrefix(cosPart, "cos-") {
		return strings.TrimPrefix(cosPart, "cos-")
	}
	return ""
}
