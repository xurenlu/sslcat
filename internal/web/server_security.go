package web

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/statistics"
)

// proxyRecordingWriter 包装 ResponseWriter，在代理响应时记录访问统计
type proxyRecordingWriter struct {
	http.ResponseWriter
	req        *http.Request
	collector  *statistics.Collector
	recorded   bool
	statusCode int
}

func newProxyRecordingWriter(w http.ResponseWriter, r *http.Request, c *statistics.Collector) *proxyRecordingWriter {
	return &proxyRecordingWriter{
		ResponseWriter: w,
		req:            r,
		collector:      c,
		statusCode:     200,
	}
}

func (p *proxyRecordingWriter) WriteHeader(code int) {
	p.statusCode = code
	if !p.recorded {
		p.recorded = true
		p.collector.RecordAccessFromHTTP(p.req, code)
	}
	p.ResponseWriter.WriteHeader(code)
}

func (p *proxyRecordingWriter) Write(b []byte) (int, error) {
	if !p.recorded {
		p.recorded = true
		p.collector.RecordAccessFromHTTP(p.req, p.statusCode)
	}
	return p.ResponseWriter.Write(b)
}

func (p *proxyRecordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if !p.recorded {
		p.recorded = true
		p.collector.RecordAccessFromHTTP(p.req, 101)
	}
	if h, ok := p.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("responseWriter does not implement http.Hijacker")
}

func (p *proxyRecordingWriter) Flush() {
	if f, ok := p.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *proxyRecordingWriter) Unwrap() http.ResponseWriter {
	return p.ResponseWriter
}

func (p *proxyRecordingWriter) ReadFrom(r io.Reader) (int64, error) {
	if !p.recorded {
		p.recorded = true
		p.collector.RecordAccessFromHTTP(p.req, p.statusCode)
	}
	if readerFrom, ok := p.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(p.ResponseWriter, r)
}

func (p *proxyRecordingWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := p.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (p *proxyRecordingWriter) CloseNotify() <-chan bool {
	if notifier, ok := p.ResponseWriter.(http.CloseNotifier); ok {
		return notifier.CloseNotify()
	}
	ch := make(chan bool)
	return ch
}

// ProxyRequestWithAuth 带访问控制的代理请求处理
func (s *Server) ProxyRequestWithAuth(w http.ResponseWriter, r *http.Request, rule *config.ProxyRule) {
	if !rule.AuthEnabled {
		s.proxyManager.ProxyRequest(w, r, rule)
		return
	}
	if s.proxyAuthManager.CheckAuth(r, rule) {
		s.proxyManager.ProxyRequest(w, r, rule)
		return
	}
	if s.proxyAuthManager.ProcessLogin(w, r, rule) {
		return
	}
	s.proxyAuthManager.ShowLoginPage(w, r, rule, "")
}

// securityMiddleware 安全中间件
func (s *Server) securityMiddleware(w http.ResponseWriter, r *http.Request) bool {
	clientIP := s.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")
	path := r.URL.Path

	if s.securityManager != nil && s.securityManager.IsWhitelisted(clientIP) {
		s.securityManager.LogAccess(clientIP, userAgent, path, true)
		return true
	}

	if s.securityManager.IsBlocked(clientIP) {
		s.log.Warnf("Blocked IP attempted to access: %s", clientIP)
		http.Error(w, "IP address blocked", http.StatusForbidden)
		return false
	}

	if s.securityManager.IsUserAgentBlocked(userAgent) {
		s.log.Warnf("Blocked User-Agent attempted to access: %s from %s", userAgent, clientIP)
		http.Error(w, "User-Agent blocked", http.StatusForbidden)
		return false
	}

	if !s.isLocalhostRequest(r) && s.config.Security.OutdatedBrowser.Enabled && s.config.Security.OutdatedBrowser.BlockVeryOutdated {
		if userAgent != "" && security.IsVeryOutdatedBrowser(userAgent) {
			s.log.Warnf("Very outdated browser User-Agent blocked: %s from %s", userAgent, clientIP)
			s.securityManager.LogAccess(clientIP, userAgent, path, false)
			http.Error(w, "Access denied: outdated browser", http.StatusForbidden)
			return false
		}
	}

	if strings.HasPrefix(path, s.config.AdminPrefix) && !s.isLocalhostRequest(r) {
		if userAgent == "" {
			s.log.Debugf("Empty User-Agent accessing admin panel from %s", clientIP)
		} else if s.isStrictBotUserAgent(userAgent) {
			s.log.Warnf("Suspicious bot User-Agent attempted to access admin panel: %s from %s", userAgent, clientIP)
			s.securityManager.LogAccess(clientIP, userAgent, path, false)
			http.Error(w, "Access denied", http.StatusForbidden)
			return false
		}
	}

	s.securityManager.LogAccess(clientIP, userAgent, path, true)
	return true
}

// proxyMiddleware 代理中间件
func (s *Server) proxyMiddleware(w http.ResponseWriter, r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, s.config.AdminPrefix) {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/debug/") {
		return false
	}
	if s.tryServePHP(w, r) {
		return true
	}
	if s.serveStatic(w, r) {
		return true
	}

	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	rule := s.proxyManager.GetProxyConfig(host)
	if rule != nil && rule.Enabled {
		if !rule.MatchesPath(r.URL.Path) {
			s.log.Debugf("Request path %s does not match any prefix for domain %s", r.URL.Path, host)
		} else {
			s.log.Debugf("Request path %s matches prefix for domain %s", r.URL.Path, host)
			if s.statisticsCollector != nil {
				w = newProxyRecordingWriter(w, r, s.statisticsCollector)
			}
			if rule.SSLOnly && r.TLS == nil {
				if net.ParseIP(host) != nil || host == "localhost" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "::1") {
					s.log.Debugf("SSL-only rule ignored for local IP/hostname: %s", host)
				} else {
					if s.hasValidCertificate(host) {
						target := "https://" + host + r.URL.RequestURI()
						s.log.Warnf("SSL-only rule, redirecting http->https for host=%s", host)
						http.Redirect(w, r, target, http.StatusMovedPermanently)
						return true
					}
					s.log.Debugf("SSL-only rule ignored for %s: no valid certificate found", host)
				}
			}
			s.ProxyRequestWithAuth(w, r, rule)
			return true
		}
	}

	switch s.config.Proxy.UnmatchedBehavior {
	case "302":
		target := s.config.Proxy.UnmatchedRedirectURL
		if target == "" {
			target = "https://sslcat.com"
		}
		s.log.Warnf("Unmatched proxy for host=%s path=%s, redirecting to %s", host, r.URL.Path, target)
		http.Redirect(w, r, target, http.StatusFound)
	case "503":
		s.log.Debugf("Unmatched proxy for host=%s path=%s, returning 503", host, r.URL.Path)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>503 Service Unavailable</title></head><body><h1>503 Service Unavailable</h1><p><small>Powered by <a href=\"https://sslcat.com\">sslcat</a>-" + s.version + "</small></p></body></html>"))
		return true
	case "blank":
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning blank", host, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	case "404":
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning 404", host, r.URL.Path)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>404 Not Found</title></head><body><h1>404 Not Found</h1><p><small>Powered by <a href=\"https://sslcat.com\">sslcat</a>-" + s.version + "</small></p></body></html>"))
		return true
	default:
		s.log.Warnf("Unmatched proxy for host=%s path=%s, returning 502", host, r.URL.Path)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1><p><small>Powered by <a href=\"https://sslcat.com\">sslcat</a>-" + s.version + "</small></p></body></html>"))
	}
	return true
}

// checkAuth 检查管理面板访问的会话认证
func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if !exists {
		http.Redirect(w, r, s.config.AdminPrefix+"/login", http.StatusFound)
		return false
	}
	go s.userManager.LogUserAction(
		session.Username,
		"page_access",
		r.URL.Path,
		fmt.Sprintf("访问页面: %s", r.URL.Path),
		s.getClientIP(r),
		r.Header.Get("User-Agent"),
	)
	return true
}
