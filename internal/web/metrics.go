package web

import (
	"fmt"
	"net/http"
	"time"
)

// handleMetrics 处理 Prometheus 指标输出
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// 系统统计
	stats := s.getSystemStats()
	uptime := time.Since(s.startTime).Seconds()

	// 安全统计
	secStats := s.securityManager.GetSecurityStats()
	blockedIPs := 0
	if v, ok := secStats["blocked_ips"].(int); ok {
		blockedIPs = v
	}
	recentAttempts := 0
	if v, ok := secStats["recent_attempts"].(int); ok {
		recentAttempts = v
	}
	totalAccessIPs := 0
	if v, ok := secStats["total_access_ips"].(int); ok {
		totalAccessIPs = v
	}

	// TLS 指纹统计
	tlsStats := s.securityManager.GetTLSFingerprintStats()
	tlsFPCount := len(tlsStats)

	// DDoS 统计
	ddosStats := map[string]interface{}{}
	if s.ddosProtector != nil {
		ddosStats = s.ddosProtector.GetStats()
	}
	ddosBlocked := 0
	ddosTotal := 0
	if v, ok := ddosStats["blocked_attacks"].(int); ok {
		ddosBlocked = v
	}
	if v, ok := ddosStats["total_attacks"].(int); ok {
		ddosTotal = v
	}

	// CDN 缓存统计
	cdnStats := map[string]interface{}{}
	if pm, ok := interface{}(s.proxyManager).(interface {
		GetCDNCache() interface{ Stats() map[string]interface{} }
	}); ok {
		if cache := pm.GetCDNCache(); cache != nil {
			cdnStats = cache.Stats()
		}
	}
	cdnHits := int64(0)
	cdnMisses := int64(0)
	cdnSize := int64(0)
	if v, ok := cdnStats["hits"].(int64); ok {
		cdnHits = v
	}
	if v, ok := cdnStats["misses"].(int64); ok {
		cdnMisses = v
	}
	if v, ok := cdnStats["total_size"].(int64); ok {
		cdnSize = v
	}

	// 代理统计
	proxyStats := s.proxyManager.GetProxyStats()
	totalRequests := int64(0)
	if v, ok := proxyStats["total_requests"].(int64); ok {
		totalRequests = v
	}
	qps := float64(0)
	if v, ok := proxyStats["qps"].(float64); ok {
		qps = v
	}
	avgResponseTime := float64(0)
	if v, ok := proxyStats["avg_response_time"].(float64); ok {
		avgResponseTime = v
	}

	// 获取压缩缓存统计
	compressionHits := int64(0)
	compressionMisses := int64(0)
	compressionSize := int64(0)
	if s.compressionCache != nil {
		cStats := s.compressionCache.Stats()
		if v, ok := cStats["hits"].(int64); ok {
			compressionHits = v
		}
		if v, ok := cStats["misses"].(int64); ok {
			compressionMisses = v
		}
		if v, ok := cStats["total_size"].(int64); ok {
			compressionSize = v
		}
	}

	// 获取图片优化统计
	imgOptTotal := int64(0)
	imgOptOptimized := int64(0)
	imgOptCacheHits := int64(0)
	if s.imageOptimizer != nil {
		imgStats := s.imageOptimizer.GetStats()
		if v, ok := imgStats["total_requests"].(int64); ok {
			imgOptTotal = v
		}
		if v, ok := imgStats["optimized_count"].(int64); ok {
			imgOptOptimized = v
		}
		if v, ok := imgStats["cache_hits"].(int64); ok {
			imgOptCacheHits = v
		}
	}

	// 输出 Prometheus 格式指标（增强版）
	fmt.Fprintf(w, `# HELP sslcat_uptime_seconds Server uptime in seconds
# TYPE sslcat_uptime_seconds counter
sslcat_uptime_seconds %.2f

# HELP sslcat_proxy_rules_total Total number of proxy rules
# TYPE sslcat_proxy_rules_total gauge
sslcat_proxy_rules_total %d

# HELP sslcat_ssl_certificates_total Total number of SSL certificates
# TYPE sslcat_ssl_certificates_total gauge
sslcat_ssl_certificates_total %d

# HELP sslcat_requests_total Total number of proxy requests
# TYPE sslcat_requests_total counter
sslcat_requests_total %d

# HELP sslcat_requests_per_second Current requests per second
# TYPE sslcat_requests_per_second gauge
sslcat_requests_per_second %.2f

# HELP sslcat_response_time_seconds Average response time in seconds
# TYPE sslcat_response_time_seconds gauge
sslcat_response_time_seconds %.6f

# HELP sslcat_security_blocked_ips Total number of blocked IPs
# TYPE sslcat_security_blocked_ips gauge
sslcat_security_blocked_ips %d

# HELP sslcat_security_recent_attempts Recent failed login attempts (1h)
# TYPE sslcat_security_recent_attempts gauge
sslcat_security_recent_attempts %d

# HELP sslcat_security_access_ips Total number of IPs with access logs
# TYPE sslcat_security_access_ips gauge
sslcat_security_access_ips %d

# HELP sslcat_tls_fingerprints_active Active TLS fingerprints in window
# TYPE sslcat_tls_fingerprints_active gauge
sslcat_tls_fingerprints_active %d

# HELP sslcat_ddos_attacks_total Total DDoS attacks detected
# TYPE sslcat_ddos_attacks_total counter
sslcat_ddos_attacks_total %d

# HELP sslcat_ddos_attacks_blocked DDoS attacks blocked
# TYPE sslcat_ddos_attacks_blocked counter
sslcat_ddos_attacks_blocked %d

# HELP sslcat_cdn_cache_hits_total CDN cache hits
# TYPE sslcat_cdn_cache_hits_total counter
sslcat_cdn_cache_hits_total %d

# HELP sslcat_cdn_cache_misses_total CDN cache misses
# TYPE sslcat_cdn_cache_misses_total counter
sslcat_cdn_cache_misses_total %d

# HELP sslcat_cdn_cache_size_bytes CDN cache total size in bytes
# TYPE sslcat_cdn_cache_size_bytes gauge
sslcat_cdn_cache_size_bytes %d

# HELP sslcat_compression_cache_hits_total Compression cache hits
# TYPE sslcat_compression_cache_hits_total counter
sslcat_compression_cache_hits_total %d

# HELP sslcat_compression_cache_misses_total Compression cache misses
# TYPE sslcat_compression_cache_misses_total counter
sslcat_compression_cache_misses_total %d

# HELP sslcat_compression_cache_size_bytes Compression cache total size in bytes
# TYPE sslcat_compression_cache_size_bytes gauge
sslcat_compression_cache_size_bytes %d

# HELP sslcat_compression_cache_hit_rate Compression cache hit rate (0-1)
# TYPE sslcat_compression_cache_hit_rate gauge
sslcat_compression_cache_hit_rate %.4f

# HELP sslcat_image_optimization_total Total image optimization requests
# TYPE sslcat_image_optimization_total counter
sslcat_image_optimization_total %d

# HELP sslcat_image_optimization_optimized Images actually optimized
# TYPE sslcat_image_optimization_optimized counter
sslcat_image_optimization_optimized %d

# HELP sslcat_image_optimization_cache_hits Image optimization cache hits
# TYPE sslcat_image_optimization_cache_hits counter
sslcat_image_optimization_cache_hits %d

# HELP sslcat_image_optimization_rate Image optimization rate (0-1)
# TYPE sslcat_image_optimization_rate gauge
sslcat_image_optimization_rate %.4f

# HELP sslcat_config_enabled Security feature flags
# TYPE sslcat_config_enabled gauge
sslcat_config_enabled{feature="captcha"} %d
sslcat_config_enabled{feature="pow"} %d
sslcat_config_enabled{feature="ddos"} %d
sslcat_config_enabled{feature="waf"} %d
sslcat_config_enabled{feature="ua_filter"} %d
sslcat_config_enabled{feature="compression"} %d
sslcat_config_enabled{feature="image_optimization"} %d
`,
		uptime,
		stats["ActiveRules"].(int),
		stats["SSLCertificates"].(int),
		totalRequests,
		qps,
		avgResponseTime/1000.0, // 转换为秒
		blockedIPs,
		recentAttempts,
		totalAccessIPs,
		tlsFPCount,
		ddosTotal,
		ddosBlocked,
		cdnHits,
		cdnMisses,
		cdnSize,
		compressionHits,
		compressionMisses,
		compressionSize,
		func() float64 {
			total := compressionHits + compressionMisses
			if total == 0 {
				return 0
			}
			return float64(compressionHits) / float64(total)
		}(),
		imgOptTotal,
		imgOptOptimized,
		imgOptCacheHits,
		func() float64 {
			if imgOptTotal == 0 {
				return 0
			}
			return float64(imgOptOptimized) / float64(imgOptTotal)
		}(),
		map[bool]int{true: 1, false: 0}[s.config.Security.EnableCaptcha],
		0, // PoW功能已移除
		map[bool]int{true: 1, false: 0}[s.config.Security.EnableDDOS],
		map[bool]int{true: 1, false: 0}[s.config.Security.EnableWAF],
		map[bool]int{true: 1, false: 0}[s.config.Security.EnableUAFilter],
		map[bool]int{true: 1, false: 0}[s.config.Compression.Enabled],
		map[bool]int{true: 1, false: 0}[s.config.ImageOptimization.Enabled])
}
