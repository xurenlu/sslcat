package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

const (
	defaultConnectTimeoutSec        = 10
	defaultKeepAliveTimeoutSec      = 30
	defaultIdleTimeoutSec           = 90
	defaultTLSHandshakeTimeoutSec   = 10
	defaultExpectContinueTimeoutSec = 1
	defaultResponseHeaderTimeoutSec = 10
	defaultMaxIdleConns             = 1024
	defaultMaxIdleConnsPerHost      = 256
	defaultMaxConnsPerHost          = 256
)

type loggingTransport struct {
	base   http.RoundTripper
	log    *logrus.Entry
	config *config.Config
}

func newUpstreamTransport(rule *config.ProxyRule, proxyConfig *config.ProxyConfig) *http.Transport {
	connectTimeout := positiveOrDefault(rule.ConnectTimeoutSec, defaultConnectTimeoutSec)
	keepAliveTimeout := positiveOrDefault(rule.KeepAliveTimeoutSec, defaultKeepAliveTimeoutSec)
	idleTimeout := positiveOrDefault(rule.IdleTimeoutSec, defaultIdleTimeoutSec)
	tlsHandshakeTimeout := positiveOrDefault(rule.TLSHandshakeTimeoutSec, defaultTLSHandshakeTimeoutSec)
	expectContinueTimeout := positiveOrDefault(rule.ExpectContinueTimeoutSec, defaultExpectContinueTimeoutSec)
	responseHeaderTimeout := rule.ResponseHeaderTimeoutSec
	if responseHeaderTimeout <= 0 && proxyConfig != nil {
		responseHeaderTimeout = proxyConfig.DefaultResponseHeaderTimeoutSec
	}
	responseHeaderTimeout = positiveOrDefault(responseHeaderTimeout, defaultResponseHeaderTimeoutSec)

	maxIdleConns := defaultMaxIdleConns
	maxIdleConnsPerHost := defaultMaxIdleConnsPerHost
	maxConnsPerHost := defaultMaxConnsPerHost
	if proxyConfig != nil {
		maxIdleConns = positiveOrDefault(proxyConfig.MaxIdleConns, defaultMaxIdleConns)
		maxIdleConnsPerHost = positiveOrDefault(proxyConfig.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHost)
		maxConnsPerHost = positiveOrDefault(proxyConfig.MaxConnsPerHost, defaultMaxConnsPerHost)
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(connectTimeout) * time.Second,
			KeepAlive: time.Duration(keepAliveTimeout) * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      rule.UpstreamHTTP2Enabled,
		MaxIdleConns:           maxIdleConns,
		MaxIdleConnsPerHost:    maxIdleConnsPerHost,
		MaxConnsPerHost:        maxConnsPerHost,
		IdleConnTimeout:        time.Duration(idleTimeout) * time.Second,
		TLSHandshakeTimeout:    time.Duration(tlsHandshakeTimeout) * time.Second,
		ExpectContinueTimeout:  time.Duration(expectContinueTimeout) * time.Second,
		ResponseHeaderTimeout:  time.Duration(responseHeaderTimeout) * time.Second,
		MaxResponseHeaderBytes: 1 << 20,
		ReadBufferSize:         32 * 1024,
		WriteBufferSize:        32 * 1024,
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: true},
	}
}

func positiveOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func closeProxyIdleConnections(proxy *httputil.ReverseProxy) {
	if proxy == nil || proxy.Transport == nil {
		return
	}
	if closer, ok := proxy.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (lt *loggingTransport) CloseIdleConnections() {
	if closer, ok := lt.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if lt.config.Server.Debug {
		curlCmd := lt.buildCurlCommand(req)
		lt.log.WithFields(logrus.Fields{
			"type":           "ACTUAL_OUTGOING_REQUEST",
			"method":         req.Method,
			"url":            req.URL.String(),
			"host":           req.Header.Get("Host"),
			"user_agent":     req.Header.Get("User-Agent"),
			"content_type":   req.Header.Get("Content-Type"),
			"content_length": req.ContentLength,
			"curl_command":   curlCmd,
		}).Debug("实际发送给上游的HTTP请求")
		lt.log.Debugf("等效的curl命令: %s", curlCmd)

		importantHeaders := []string{
			"Authorization", "Cookie", "X-Forwarded-For", "X-Real-IP",
			"X-Forwarded-Proto", "X-Forwarded-Host", "Accept", "Accept-Encoding",
			"Accept-Language", "Cache-Control", "Referer", "traceparent", "tracestate",
			"X-Trace-ID", "X-Span-ID", "X-Request-ID", "X-B3-TraceId", "X-B3-SpanId",
			"X-B3-ParentSpanId", "X-Cloud-Trace-Context", "X-Amzn-Trace-Id", "baggage",
		}
		headers := make(map[string]string)
		for _, header := range importantHeaders {
			if value := req.Header.Get(header); value != "" {
				headers[header] = redactHeaderValue(header, value)
			}
		}
		if len(headers) > 0 {
			lt.log.WithFields(logrus.Fields{
				"type":    "ACTUAL_OUTGOING_REQUEST",
				"headers": headers,
			}).Debug("实际发送的请求头部信息")
		}
	}

	resp, err := lt.base.RoundTrip(req)
	if resp != nil && lt.config.Server.Debug {
		lt.log.WithFields(logrus.Fields{
			"type":           "ACTUAL_RESPONSE",
			"status_code":    resp.StatusCode,
			"status":         resp.Status,
			"content_type":   resp.Header.Get("Content-Type"),
			"content_length": resp.ContentLength,
			"server":         resp.Header.Get("Server"),
		}).Debug("上游服务器实际返回的HTTP响应")
	}
	return resp, err
}

func (lt *loggingTransport) buildCurlCommand(req *http.Request) string {
	parts := []string{"curl"}
	if req.Method != http.MethodGet {
		parts = append(parts, "-X", req.Method)
	}
	for name, values := range req.Header {
		for _, value := range values {
			value = redactHeaderValue(name, value)
			escapedValue := strings.ReplaceAll(value, "'", "'\\''")
			parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", name, escapedValue))
		}
	}
	if req.Body != nil && req.ContentLength > 0 {
		parts = append(parts, "-d", "'[REQUEST_BODY]'")
	}
	parts = append(parts, fmt.Sprintf("'%s'", req.URL.String()), "-v", "--insecure")
	return strings.Join(parts, " ")
}
