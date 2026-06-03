package web

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/cache"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/httputil"
	"github.com/xurenlu/sslcat/internal/i18n"
	"github.com/xurenlu/sslcat/internal/logger"
	"github.com/xurenlu/sslcat/internal/monitor"
)

// isSupportedLanguage 检查是否为受支持的语言
func (s *Server) isSupportedLanguage(lang string) bool {
	langs := s.translator.GetSupportedLanguages()
	if _, ok := langs[i18n.SupportedLanguage(lang)]; ok {
		return true
	}
	return false
}

// hasValidCertificate 检查域名是否有有效的非自签名证书
func (s *Server) hasValidCertificate(domain string) bool {
	cert, err := s.sslManager.GetCertificate(domain)
	if err != nil || cert == nil || len(cert.Certificate) == 0 {
		return false
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	if time.Now().After(x509Cert.NotAfter) {
		return false
	}
	isSelfSigned := x509Cert.Issuer.String() == x509Cert.Subject.String()
	if isSelfSigned {
		return false
	}
	if !s.domainMatchesCert(domain, x509Cert) {
		return false
	}
	return true
}

// shouldEnableHTTP3ForHost 检查是否应该为指定域名启用 HTTP/3
func (s *Server) shouldEnableHTTP3ForHost(host string) bool {
	if !s.config.Server.HTTP3Enabled {
		return s.checkSiteLevelHTTP3Override(host, true)
	}
	if s.checkSiteLevelHTTP3Override(host, false) {
		return false
	}
	return true
}

// checkSiteLevelHTTP3Override 检查站点级 HTTP/3 覆盖配置
func (s *Server) checkSiteLevelHTTP3Override(host string, lookForEnabled bool) bool {
	host = strings.ToLower(host)
	for _, rule := range s.config.Proxy.Rules {
		if !rule.Enabled {
			continue
		}
		if strings.ToLower(rule.Domain) == host {
			if rule.HTTP3Enabled != nil {
				if lookForEnabled && *rule.HTTP3Enabled {
					return true
				}
				if !lookForEnabled && !*rule.HTTP3Enabled {
					return true
				}
			}
			break
		}
	}
	for _, site := range s.config.StaticSites {
		if !site.Enabled {
			continue
		}
		if strings.ToLower(site.Domain) == host {
			if site.HTTP3Enabled != nil {
				if lookForEnabled && *site.HTTP3Enabled {
					return true
				}
				if !lookForEnabled && !*site.HTTP3Enabled {
					return true
				}
			}
			break
		}
	}
	for _, site := range s.config.PHPSites {
		if !site.Enabled {
			continue
		}
		if strings.ToLower(site.Domain) == host {
			if site.HTTP3Enabled != nil {
				if lookForEnabled && *site.HTTP3Enabled {
					return true
				}
				if !lookForEnabled && !*site.HTTP3Enabled {
					return true
				}
			}
			break
		}
	}
	return false
}

// domainMatchesCert 检查域名是否匹配证书
func (s *Server) domainMatchesCert(domain string, cert *x509.Certificate) bool {
	if cert.Subject.CommonName == domain {
		return true
	}
	for _, san := range cert.DNSNames {
		if san == domain {
			return true
		}
		if strings.HasPrefix(san, "*.") {
			wildcardDomain := san[2:]
			if strings.HasSuffix(domain, "."+wildcardDomain) || domain == wildcardDomain {
				return true
			}
		}
	}
	return false
}

// getClientIP 获取客户端真实 IP（带反伪造保护）
func (s *Server) getClientIP(r *http.Request) string {
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}
	isTrustedSource := s.isPrivateIP(remoteIP) || remoteIP == "127.0.0.1" || remoteIP == "::1"
	if isTrustedSource {
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			cfIP = strings.TrimSpace(cfIP)
			if !s.isLocalhostIP(cfIP) {
				return cfIP
			}
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			realIP = strings.TrimSpace(realIP)
			if !s.isLocalhostIP(realIP) {
				return realIP
			}
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				ip := strings.TrimSpace(ips[0])
				if !s.isPrivateIP(ip) && !s.isLocalhostIP(ip) {
					return ip
				}
			}
		}
	}
	return remoteIP
}

// extractTLSFingerprint 从 TLS 连接提取指纹
func (s *Server) extractTLSFingerprint(r *http.Request) string {
	if r.TLS == nil {
		return ""
	}
	version := r.TLS.Version
	cipherSuite := r.TLS.CipherSuite
	serverName := r.TLS.ServerName
	raw := fmt.Sprintf("v=%d;cs=%d;sni=%s", version, cipherSuite, serverName)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

func (s *Server) isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.16.") ||
		strings.HasPrefix(ip, "127.") ||
		ip == "::1"
}

func (s *Server) isLocalhostIP(ip string) bool {
	return ip == "127.0.0.1" ||
		ip == "::1" ||
		strings.HasPrefix(ip, "127.") ||
		ip == "localhost"
}

func (s *Server) isLocalhostRequest(r *http.Request) bool {
	remoteAddr := r.RemoteAddr
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		remoteAddr = remoteAddr[:idx]
	}
	remoteAddr = strings.Trim(remoteAddr, "[]")
	if remoteAddr == "127.0.0.1" ||
		remoteAddr == "::1" ||
		remoteAddr == "localhost" ||
		strings.HasPrefix(remoteAddr, "127.") {
		return true
	}
	return false
}

func (s *Server) isCommonBotUserAgent(ua string) bool {
	botUAs := []string{
		"bot", "crawler", "spider", "scraper", "curl", "wget",
	}
	uaLower := strings.ToLower(ua)
	for _, bot := range botUAs {
		if strings.Contains(uaLower, bot) {
			return true
		}
	}
	return false
}

func (s *Server) isStrictBotUserAgent(ua string) bool {
	strictBotUAs := []string{
		"bot", "crawler", "spider", "scraper",
		"googlebot", "bingbot", "slurp", "duckduckbot",
		"baiduspider", "yandexbot", "facebookexternalhit",
		"twitterbot", "linkedinbot", "whatsapp", "telegram",
	}
	uaLower := strings.ToLower(ua)
	for _, bot := range strictBotUAs {
		if strings.Contains(uaLower, bot) {
			return true
		}
	}
	return false
}

func (s *Server) getCurrentUser(r *http.Request) *User {
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		return nil
	}
	user, err := s.userManager.GetUserByUsername(session.Username)
	if err == nil {
		return user
	}
	if session.Username == s.config.Admin.Username {
		return &User{
			Username: session.Username,
			Role:     session.Role,
			IsActive: true,
		}
	}
	s.log.Warnf("获取用户信息失败: %v", err)
	return nil
}

func (s *Server) getSystemStats() map[string]interface{} {
	proxyStats := s.proxyManager.GetProxyStats()
	uptime := time.Since(s.startTime)

	getInt64 := func(key string, defaultValue int64) int64 {
		if v, ok := proxyStats[key]; ok {
			if val, ok := v.(int64); ok {
				return val
			}
			if val, ok := v.(int); ok {
				return int64(val)
			}
		}
		return defaultValue
	}
	getFloat64 := func(key string, defaultValue float64) float64 {
		if v, ok := proxyStats[key]; ok {
			if val, ok := v.(float64); ok {
				return val
			}
			if val, ok := v.(int); ok {
				return float64(val)
			}
			if val, ok := v.(int64); ok {
				return float64(val)
			}
		}
		return defaultValue
	}

	var publicIP string
	func() {
		defer func() {
			if r := recover(); r != nil {
				s.log.Warnf("获取公网IP时发生异常: %v", r)
				publicIP = ""
			}
		}()
		publicIP = s.fetchPublicIPv4()
	}()

	totalRequests := getInt64("total_requests", 0)
	if totalRequests == 0 {
		totalRequests = getInt64("cached_proxies", 0)
	}

	ver := strings.TrimPrefix(s.version, "v")
	return map[string]interface{}{
		"activeRules":   len(s.config.Proxy.Rules),
		"cachedProxies": totalRequests,
		"publicIP":      publicIP,
		"goVersion":     runtime.Version(),
		"version":       ver,
		"ActiveRules":     len(s.config.Proxy.Rules),
		"CachedProxies":   getInt64("cached_proxies", 0),
		"TotalRequests":   totalRequests,
		"ErrorRate":       getFloat64("error_rate", 0),
		"QPS":             getFloat64("qps", 0),
		"AvgResponseTime": getFloat64("avg_response_time", 0),
		"Uptime":          int64(uptime.Seconds()),
		"UptimeString":    s.formatDuration(uptime),
		"SSLCertificates": len(s.sslManager.GetCertificateList()),
		"BlockedIPs":      len(s.securityManager.GetBlockedIPs()),
		"PublicIP":        publicIP,
		"Version":         ver,
	}
}

func (s *Server) formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if hours > 0 {
		return fmt.Sprintf("%d小时%d分钟", hours, minutes)
	} else if minutes > 0 {
		return fmt.Sprintf("%d分钟%d秒", minutes, seconds)
	} else {
		return fmt.Sprintf("%d秒", seconds)
	}
}

// audit 简单审计：写入 data/audit.log 为 JSON Lines
func (s *Server) audit(action, detail string) {
	t := time.Now().Format(time.RFC3339)
	rec := map[string]string{"time": t, "user": s.config.Admin.Username, "action": action, "detail": detail}
	b, _ := json.Marshal(rec)
	_ = os.MkdirAll("./data", 0755)
	if s.auditRotator != nil {
		_, _ = s.auditRotator.Write(append(b, '\n'))
	} else {
		f, err := os.OpenFile("./data/audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer f.Close()
			f.Write(append(b, '\n'))
		}
	}
	if s.notifier != nil && s.notifier.Enabled() {
		m := map[string]any{"ts": t, "level": "info", "action": action, "detail": detail}
		s.notifier.SendJSON(m)
	}
}

// dnsLookupNameForCertDomain 返回可用于 net.LookupIP 的主机名。
// 通配符证书在存储/文件名中常为 "*.example.com"，该字符串不是合法 DNS 主机名，应解析其根域 example.com。
func dnsLookupNameForCertDomain(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return domain[2:]
	}
	return domain
}

// refreshLEPreferredHostLoop 每31秒刷新一次首选LE域名
func (s *Server) refreshLEPreferredHostLoop() {
	ticker := time.NewTicker(31 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Errorf("refreshLEPreferredHost 发生 panic: %v", r)
				}
			}()
			s.refreshLEPreferredHost()
		}()
	}
}

func (s *Server) refreshLEPreferredHost() {
	if s.sslManager == nil {
		s.leRedirectHost = ""
		return
	}
	domain := s.sslManager.GetFirstValidLEDomain()
	if domain == "" {
		s.leRedirectHost = ""
		return
	}
	lookupName := dnsLookupNameForCertDomain(domain)
	redirectHost := domain
	if strings.HasPrefix(domain, "*.") {
		redirectHost = lookupName
	}
	publicIP := s.fetchPublicIPv4()
	if publicIP == "" {
		s.leRedirectHost = ""
		return
	}
	ips, err := func() ([]net.IP, error) {
		type result struct {
			ips []net.IP
			err error
		}
		ch := make(chan result, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Warnf("DNS 解析时发生异常: %v", r)
					ch <- result{nil, fmt.Errorf("DNS 解析异常: %v", r)}
				}
			}()
			ips, err := net.LookupIP(lookupName)
			ch <- result{ips, err}
		}()
		select {
		case res := <-ch:
			return res.ips, res.err
		case <-time.After(2 * time.Second):
			return nil, fmt.Errorf("DNS 解析超时")
		}
	}()
	if err != nil {
		s.log.Warnf("DNS 解析失败: %v", err)
		s.leRedirectHost = ""
		return
	}
	for _, ip := range ips {
		if ip.To4() != nil && ip.String() == publicIP {
			s.leRedirectHost = redirectHost
			return
		}
	}
	s.leRedirectHost = ""
}

func (s *Server) fetchPublicIPv4() string {
	client := httputil.GetShortLivedClient(2 * time.Second)
	req, err := http.NewRequest("GET", "https://ip4.dev/myip", nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// handleFavicon 处理 favicon.ico 请求
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	favicon := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF,
		0x61, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
		0x42, 0x60, 0x82,
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(favicon)
}

// findMatchingProxyRule 查找匹配的转发规则
func (s *Server) findMatchingProxyRule(r *http.Request) *config.ProxyRule {
	host := r.Host
	path := r.URL.Path
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	for i := range s.config.Proxy.Rules {
		rule := &s.config.Proxy.Rules[i]
		if !rule.Enabled {
			continue
		}
		if rule.Domain != host {
			continue
		}
		if len(rule.PathPrefixes) > 0 {
			matched := false
			for _, prefix := range rule.PathPrefixes {
				if rule.PathExact {
					if path == prefix {
						matched = true
						break
					}
				} else {
					if strings.HasPrefix(path, prefix) {
						matched = true
						break
					}
				}
			}
			if !matched {
				continue
			}
		}
		if len(rule.PathPrefixRules) > 0 {
			matched := false
			for _, pathRule := range rule.PathPrefixRules {
				if !pathRule.Enabled {
					continue
				}
				for _, prefix := range pathRule.Prefixes {
					if pathRule.Exact {
						if path == prefix {
							matched = true
							break
						}
					} else {
						if strings.HasPrefix(path, prefix) {
							matched = true
							break
						}
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
		}
		return rule
	}
	return nil
}

// getAccessLogConfig 返回当前请求是否记录访问日志及使用的路径
func (s *Server) getAccessLogConfig(r *http.Request, matchedRule *config.ProxyRule) (enabled bool, path string) {
	host := r.Host
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	if matchedRule != nil {
		if matchedRule.AccessLogEnabled != nil && !*matchedRule.AccessLogEnabled {
			return false, ""
		}
		if matchedRule.AccessLogPath != "" {
			return true, matchedRule.AccessLogPath
		}
		return s.config.Server.AccessLogEnabled, ""
	}
	for i := range s.config.StaticSites {
		site := &s.config.StaticSites[i]
		if !site.Enabled {
			continue
		}
		if !strings.EqualFold(site.Domain, host) {
			continue
		}
		if site.AccessLogEnabled != nil && !*site.AccessLogEnabled {
			return false, ""
		}
		if site.AccessLogPath != "" {
			return true, site.AccessLogPath
		}
		return s.config.Server.AccessLogEnabled, ""
	}
	for i := range s.config.PHPSites {
		site := &s.config.PHPSites[i]
		if !site.Enabled {
			continue
		}
		if !strings.EqualFold(site.Domain, host) {
			continue
		}
		if site.AccessLogEnabled != nil && !*site.AccessLogEnabled {
			return false, ""
		}
		if site.AccessLogPath != "" {
			return true, site.AccessLogPath
		}
		return s.config.Server.AccessLogEnabled, ""
	}
	return s.config.Server.AccessLogEnabled, ""
}

func (s *Server) getOrCreateAccessLogger(logPath string) *logger.AccessLogger {
	if logPath == "" {
		return nil
	}
	s.accessLoggersMu.RLock()
	al, ok := s.accessLoggers[logPath]
	s.accessLoggersMu.RUnlock()
	if ok && al != nil {
		return al
	}
	s.accessLoggersMu.Lock()
	defer s.accessLoggersMu.Unlock()
	if al, ok = s.accessLoggers[logPath]; ok && al != nil {
		return al
	}
	format := logger.FormatNginx
	switch strings.ToLower(s.config.Server.AccessLogFormat) {
	case "apache":
		format = logger.FormatApache
	case "json":
		format = logger.FormatJSON
	}
	newAl, err := logger.NewAccessLogger(format, logPath, true)
	if err != nil {
		s.log.Warnf("创建站点访问日志记录器失败 path=%s: %v", logPath, err)
		return nil
	}
	if s.config.Server.AccessLogMaxSize > 0 {
		newAl.SetMaxSize(s.config.Server.AccessLogMaxSize)
	}
	if s.config.Server.AccessLogMaxFiles > 0 {
		newAl.SetMaxFiles(s.config.Server.AccessLogMaxFiles)
	}
	s.accessLoggers[logPath] = newAl
	return newAl
}

func (s *Server) updateSharedCache(sizeMB int) {
	if sizeMB < 8 {
		sizeMB = 8
	}
	maxBytes := int64(sizeMB) * 1024 * 1024
	s.log.Infof("更新共享缓存容量为 %d MB", sizeMB)
	newCache := cache.NewMemoryCache(&cache.MemoryCacheConfig{
		Name:            "shared_cache",
		MaxEntries:      400,
		MaxSizeBytes:    maxBytes,
		MaxItemSize:     2 * 1024 * 1024,
		DefaultTTL:      24 * time.Hour,
		CleanupInterval: 5 * time.Minute,
	})
	oldCache := s.sharedCache
	s.sharedCache = newCache
	if s.compressionCache != nil {
		s.compressionCache.SetMemoryCache(newCache)
	}
	if s.imageOptimizer != nil {
		s.imageOptimizer.SetMemoryCache(newCache)
	}
	if oldCache != nil && oldCache != newCache {
		oldCache.Close()
	}
}

func (s *Server) updateMemoryMonitor(maxUsagePercent float64, cooldownSec int) {
	if s.monitorManager == nil {
		return
	}
	if maxUsagePercent < 5 {
		maxUsagePercent = 5
	}
	if maxUsagePercent > 90 {
		maxUsagePercent = 90
	}
	if cooldownSec < 60 {
		cooldownSec = 60
	}
	opts := monitor.MemoryMonitorOptions{
		CheckInterval:       time.Minute,
		MaxSystemUsageRatio: maxUsagePercent / 100.0,
		ReleaseCooldown:     time.Duration(cooldownSec) * time.Second,
	}
	s.monitorManager.UpdateMemoryMonitorOptions(opts)
}
