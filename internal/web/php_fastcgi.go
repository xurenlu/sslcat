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
		for k, v := range site.Vars {
			params[k] = v
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
		return true
	}
	return false
}

func dialFCGI(addr string, timeout time.Duration) (net.Conn, error) {
	if strings.HasPrefix(addr, "unix:") {
		p := strings.TrimPrefix(addr, "unix:")
		return net.DialTimeout("unix", p, timeout)
	}
	if strings.HasPrefix(addr, "tcp:") {
		addr = strings.TrimPrefix(addr, "tcp:")
	}
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
