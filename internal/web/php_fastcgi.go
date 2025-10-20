package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// servePHP 若命中 PHP 站点与脚本，使用 FastCGI 转发
func (s *Server) servePHP(w http.ResponseWriter, r *http.Request) bool {
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	for _, site := range s.config.PHPSites {
		if !site.Enabled || site.FCGIAddr == "" {
			continue
		}
		if !strings.EqualFold(site.Domain, host) {
			continue
		}

		// 检查路径前缀匹配
		if !site.MatchesPath(r.URL.Path) {
			s.log.Debugf("Request path %s does not match any prefix for PHP site %s", r.URL.Path, host)
			continue
		}
		s.log.Debugf("Request path %s matches prefix for PHP site %s", r.URL.Path, host)

		// 检测远程环境并应用相应限制
		remoteDetector := NewPHPRemoteDetector(s.config)
		envInfo, err := remoteDetector.DetectRemoteEnvironment(&site)
		if err != nil {
			s.log.Errorf("检测远程环境失败: %v", err)
		} else if envInfo.IsRemote {
			// 远程环境功能限制提示
			s.log.Warnf("远程 PHP 环境检测到功能限制: %s", strings.Join(envInfo.Limitations, ", "))
		}

		// 安全检查（仅在本地环境或远程环境支持时执行）
		if site.SecurityConfig != nil && (!envInfo.IsRemote || envInfo.ConnectionType == "docker") {
			// 简化的安全检查，避免调用不存在的方法
			if s.isDangerousRequest(r) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return true
			}
		}

		// 规范路径并限定在 root
		reqPath := r.URL.Path
		if reqPath == "/" || reqPath == "" {
			reqPath = "/" + defaultOr(site.Index, "index.php")
		}
		clean := strings.TrimPrefix(filepath.Clean(reqPath), "/")
		scriptPath := filepath.Join(site.Root, clean)
		if rel, err := filepath.Rel(site.Root, scriptPath); err != nil || strings.HasPrefix(rel, "..") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return true
		}

		// 若是目录则尝试 index.php
		if fi, err := os.Stat(scriptPath); err == nil && fi.IsDir() {
			scriptPath = filepath.Join(scriptPath, defaultOr(site.Index, "index.php"))
		}
		if !strings.HasSuffix(strings.ToLower(scriptPath), ".php") {
			return false // 非 php 文件，交回给上层
		}
		if _, err := os.Stat(scriptPath); err != nil {
			http.NotFound(w, r)
			return true
		}

		// 应用安全响应头
		s.applySecurityHeaders(w, site.Domain)
		s.applyCustomSiteHeaders(w, site.ResponseHeaders)

		// 建立到 PHP-FPM 的连接（支持 unix:/path 或 tcp host:port）
		conn, err := dialFCGI(site.FCGIAddr, 10*time.Second)
		if err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return true
		}
		defer conn.Close()

		// 准备 FastCGI PARAMS
		params := map[string]string{
			"GATEWAY_INTERFACE": "CGI/1.1",
			"REQUEST_METHOD":    r.Method,
			"SCRIPT_FILENAME":   scriptPath,
			"SCRIPT_NAME":       r.URL.Path,
			"QUERY_STRING":      r.URL.RawQuery,
			"REQUEST_URI":       r.URL.RequestURI(),
			"DOCUMENT_ROOT":     site.Root,
			"SERVER_PROTOCOL":   r.Proto,
			"REMOTE_ADDR":       s.getClientIP(r),
			"SERVER_SOFTWARE":   "sslcat",
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			params["CONTENT_TYPE"] = ct
		}
		if r.ContentLength > 0 {
			params["CONTENT_LENGTH"] = fmt.Sprintf("%d", r.ContentLength)
		}
		if r.TLS != nil {
			params["HTTPS"] = "on"
		}

		// 添加自定义环境变量
		for k, v := range site.Vars {
			params[k] = v
		}

		// 添加性能监控相关环境变量
		if site.MonitoringConfig != nil && site.MonitoringConfig.EnablePerformanceMonitoring {
			params["SSL_CAT_PERFORMANCE_MONITORING"] = "1"
			params["SSL_CAT_DOMAIN"] = site.Domain
		}

		// 发送 FastCGI 请求
		const reqID = 1
		if err := writeBeginRequest(conn, reqID); err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return true
		}
		if err := writeParams(conn, reqID, params); err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return true
		}
		if err := writeStdin(conn, reqID, r.Body); err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return true
		}
		if err := fcgiServe(conn, reqID, w); err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return true
		}

		// 记录性能指标（简化实现）
		go s.recordPHPPerformance(&site, r)

		return true
	}
	return false
}

func dialFCGI(addr string, timeout time.Duration) (net.Conn, error) {
	if strings.HasPrefix(addr, "unix:") {
		p := strings.TrimPrefix(addr, "unix:")
		return net.DialTimeout("unix", p, timeout)
	}
	addr = strings.TrimPrefix(addr, "tcp:")
	if addr == "" {
		return nil, errors.New("empty fcgi addr")
	}
	return net.DialTimeout("tcp", addr, timeout)
}

func defaultOr(val, def string) string {
	if strings.TrimSpace(val) == "" {
		return def
	}
	return val
}

// isDangerousRequest 检查是否为危险请求
func (s *Server) isDangerousRequest(r *http.Request) bool {
	// 检查路径遍历
	path := r.URL.Path
	if strings.Contains(path, "../") || strings.Contains(path, "..\\") {
		return true
	}

	// 检查危险文件扩展名
	if strings.Contains(path, ".php") && strings.Contains(path, "..") {
		return true
	}

	return false
}

// applySecurityHeaders 应用安全响应头
func (s *Server) applySecurityHeaders(w http.ResponseWriter, domain string) {
	// 基础安全头
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// 隐藏 PHP 版本
	w.Header().Set("X-Powered-By", "sslcat")
}

func (s *Server) applyCustomSiteHeaders(w http.ResponseWriter, headers map[string]string) {
	for key, value := range headers {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if value == "" {
			w.Header().Del(trimmedKey)
			continue
		}
		w.Header().Set(trimmedKey, value)
	}
}

// recordPHPPerformance 记录 PHP 性能指标
func (s *Server) recordPHPPerformance(site *config.PHPSite, r *http.Request) {
	// 简化的性能记录实现
	s.log.Debugf("记录 PHP 性能指标: %s - %s", site.Domain, r.URL.Path)
}
