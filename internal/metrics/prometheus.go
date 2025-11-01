package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// PrometheusMetrics Prometheus指标收集器
type PrometheusMetrics struct {
	// HTTP请求指标
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec

	// 负载均衡指标
	backendRequests *prometheus.CounterVec
	backendDuration *prometheus.HistogramVec
	backendStatus   *prometheus.GaugeVec

	// 压缩指标
	compressionRatio *prometheus.HistogramVec
	compressionTotal *prometheus.CounterVec

	// 缓存指标
	cacheHits   *prometheus.CounterVec
	cacheMisses *prometheus.CounterVec
	cacheSize   *prometheus.GaugeVec

	// SSL证书指标
	certificateExpiry *prometheus.GaugeVec
	certificateStatus *prometheus.GaugeVec

	// 安全指标
	blockedRequests *prometheus.CounterVec
	securityEvents  *prometheus.CounterVec

	// 首次设置指标
	firstSetupEvents *prometheus.CounterVec

	// 系统指标
	uptime        prometheus.Gauge
	configReloads *prometheus.CounterVec

	log *logrus.Entry
}

// NewPrometheusMetrics 创建Prometheus指标收集器
func NewPrometheusMetrics() *PrometheusMetrics {
	pm := &PrometheusMetrics{
		log: logrus.WithFields(logrus.Fields{
			"component": "prometheus_metrics",
		}),
	}

	// 初始化指标
	pm.initMetrics()

	// 注册指标
	pm.registerMetrics()

	return pm
}

// initMetrics 初始化指标
func (pm *PrometheusMetrics) initMetrics() {
	// HTTP请求指标
	pm.requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"domain", "method", "status_code"},
	)

	pm.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sslcat_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"domain", "method"},
	)

	pm.responseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sslcat_http_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: []float64{100, 1000, 10000, 100000, 1000000, 10000000},
		},
		[]string{"domain", "content_type"},
	)

	// 负载均衡指标
	pm.backendRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_backend_requests_total",
			Help: "Total number of backend requests",
		},
		[]string{"domain", "backend_id", "backend_address", "status"},
	)

	pm.backendDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sslcat_backend_request_duration_seconds",
			Help:    "Backend request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"domain", "backend_id"},
	)

	pm.backendStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sslcat_backend_healthy",
			Help: "Backend health status (1 = healthy, 0 = unhealthy)",
		},
		[]string{"domain", "backend_id", "backend_address"},
	)

	// 压缩指标
	pm.compressionRatio = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sslcat_compression_ratio",
			Help:    "Compression ratio (original_size / compressed_size)",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100},
		},
		[]string{"algorithm", "content_type"},
	)

	pm.compressionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_compression_total",
			Help: "Total number of compressions",
		},
		[]string{"algorithm", "result"},
	)

	// 缓存指标
	pm.cacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_cache_hits_total",
			Help: "Total number of cache hits",
		},
		[]string{"cache_type", "domain"},
	)

	pm.cacheMisses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_cache_misses_total",
			Help: "Total number of cache misses",
		},
		[]string{"cache_type", "domain"},
	)

	pm.cacheSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sslcat_cache_size_bytes",
			Help: "Cache size in bytes",
		},
		[]string{"cache_type"},
	)

	// SSL证书指标
	pm.certificateExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sslcat_certificate_expiry_timestamp",
			Help: "Certificate expiry timestamp",
		},
		[]string{"domain", "issuer"},
	)

	pm.certificateStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sslcat_certificate_valid",
			Help: "Certificate validity (1 = valid, 0 = invalid/expired)",
		},
		[]string{"domain", "issuer"},
	)

	// 安全指标
	pm.blockedRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_blocked_requests_total",
			Help: "Total number of blocked requests",
		},
		[]string{"reason", "source_ip"},
	)

	pm.securityEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_security_events_total",
			Help: "Total number of security events",
		},
		[]string{"event_type", "severity"},
	)

	// 首次设置指标
	pm.firstSetupEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_first_setup_events_total",
			Help: "Total number of first-time setup events",
		},
		[]string{"status", "reason"},
	)

	// 系统指标
	pm.uptime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sslcat_uptime_seconds",
			Help: "SSLcat uptime in seconds",
		},
	)

	pm.configReloads = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sslcat_config_reloads_total",
			Help: "Total number of configuration reloads",
		},
		[]string{"status"},
	)
}

// registerMetrics 注册指标到Prometheus
func (pm *PrometheusMetrics) registerMetrics() {
	prometheus.MustRegister(
		// HTTP指标
		pm.requestsTotal,
		pm.requestDuration,
		pm.responseSize,

		// 负载均衡指标
		pm.backendRequests,
		pm.backendDuration,
		pm.backendStatus,

		// 压缩指标
		pm.compressionRatio,
		pm.compressionTotal,

		// 缓存指标
		pm.cacheHits,
		pm.cacheMisses,
		pm.cacheSize,

		// SSL指标
		pm.certificateExpiry,
		pm.certificateStatus,

		// 安全指标
		pm.blockedRequests,
		pm.securityEvents,

		// 首次设置指标
		pm.firstSetupEvents,

		// 系统指标
		pm.uptime,
		pm.configReloads,
	)

	pm.log.Info("Prometheus metrics registered")
}

// RecordHTTPRequest 记录HTTP请求指标
func (pm *PrometheusMetrics) RecordHTTPRequest(domain, method, statusCode string, duration time.Duration, responseSize int64) {
	pm.requestsTotal.WithLabelValues(domain, method, statusCode).Inc()
	pm.requestDuration.WithLabelValues(domain, method).Observe(duration.Seconds())

	if responseSize > 0 {
		pm.responseSize.WithLabelValues(domain, "").Observe(float64(responseSize))
	}
}

// RecordBackendRequest 记录后端请求指标
func (pm *PrometheusMetrics) RecordBackendRequest(domain, backendID, backendAddress, status string, duration time.Duration) {
	pm.backendRequests.WithLabelValues(domain, backendID, backendAddress, status).Inc()
	pm.backendDuration.WithLabelValues(domain, backendID).Observe(duration.Seconds())
}

// SetBackendHealth 设置后端健康状态
func (pm *PrometheusMetrics) SetBackendHealth(domain, backendID, backendAddress string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	pm.backendStatus.WithLabelValues(domain, backendID, backendAddress).Set(value)
}

// RecordCompression 记录压缩指标
func (pm *PrometheusMetrics) RecordCompression(algorithm, contentType string, originalSize, compressedSize int64) {
	if originalSize > 0 && compressedSize > 0 {
		ratio := float64(originalSize) / float64(compressedSize)
		pm.compressionRatio.WithLabelValues(algorithm, contentType).Observe(ratio)
	}

	result := "success"
	if compressedSize >= originalSize {
		result = "no_benefit"
	}
	pm.compressionTotal.WithLabelValues(algorithm, result).Inc()
}

// RecordCacheHit 记录缓存命中
func (pm *PrometheusMetrics) RecordCacheHit(cacheType, domain string) {
	pm.cacheHits.WithLabelValues(cacheType, domain).Inc()
}

// RecordCacheMiss 记录缓存未命中
func (pm *PrometheusMetrics) RecordCacheMiss(cacheType, domain string) {
	pm.cacheMisses.WithLabelValues(cacheType, domain).Inc()
}

// SetCacheSize 设置缓存大小
func (pm *PrometheusMetrics) SetCacheSize(cacheType string, sizeBytes int64) {
	pm.cacheSize.WithLabelValues(cacheType).Set(float64(sizeBytes))
}

// SetCertificateExpiry 设置证书过期时间
func (pm *PrometheusMetrics) SetCertificateExpiry(domain, issuer string, expiryTime time.Time) {
	pm.certificateExpiry.WithLabelValues(domain, issuer).Set(float64(expiryTime.Unix()))
}

// SetCertificateStatus 设置证书状态
func (pm *PrometheusMetrics) SetCertificateStatus(domain, issuer string, valid bool) {
	value := 0.0
	if valid {
		value = 1.0
	}
	pm.certificateStatus.WithLabelValues(domain, issuer).Set(value)
}

// RecordBlockedRequest 记录被阻止的请求
func (pm *PrometheusMetrics) RecordBlockedRequest(reason, sourceIP string) {
	pm.blockedRequests.WithLabelValues(reason, sourceIP).Inc()
}

// RecordSecurityEvent 记录安全事件
func (pm *PrometheusMetrics) RecordSecurityEvent(eventType, severity string) {
	pm.securityEvents.WithLabelValues(eventType, severity).Inc()
}

// RecordFirstSetup 记录首次设置事件
func (pm *PrometheusMetrics) RecordFirstSetup(status, reason string) {
	pm.firstSetupEvents.WithLabelValues(status, reason).Inc()
}

// SetUptime 设置运行时间
func (pm *PrometheusMetrics) SetUptime(startTime time.Time) {
	pm.uptime.Set(time.Since(startTime).Seconds())
}

// RecordConfigReload 记录配置重载
func (pm *PrometheusMetrics) RecordConfigReload(status string) {
	pm.configReloads.WithLabelValues(status).Inc()
}

// Handler 返回Prometheus指标处理器
func (pm *PrometheusMetrics) Handler() http.Handler {
	return promhttp.Handler()
}

// HTTPMiddleware 创建HTTP指标中间件
func (pm *PrometheusMetrics) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 包装ResponseWriter以捕获状态码和响应大小
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}

		// 处理请求
		next.ServeHTTP(wrapped, r)

		// 记录指标
		duration := time.Since(start)
		domain := r.Host
		method := r.Method
		statusCode := strconv.Itoa(wrapped.statusCode)

		pm.RecordHTTPRequest(domain, method, statusCode, duration, wrapped.size)
	})
}

// responseWriter 包装ResponseWriter以捕获状态码和大小
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(data)
	rw.size += int64(size)
	return size, err
}

// GetStats 获取指标统计信息
func (pm *PrometheusMetrics) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"metrics_registered": true,
		"endpoint":           "/metrics",
		"format":             "prometheus",
		"collectors": map[string]interface{}{
			"http_requests":      "Counter",
			"request_duration":   "Histogram",
			"response_size":      "Histogram",
			"backend_requests":   "Counter",
			"backend_duration":   "Histogram",
			"backend_status":     "Gauge",
			"compression_ratio":  "Histogram",
			"cache_hits":         "Counter",
			"cache_misses":       "Counter",
			"certificate_expiry": "Gauge",
			"security_events":    "Counter",
			"first_setup_events": "Counter",
			"uptime":             "Gauge",
			"config_reloads":     "Counter",
		},
	}
}
