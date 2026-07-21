package httputil

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// 全局共享的 HTTP Transport，避免创建过多连接
var (
	defaultTransport     *http.Transport
	defaultTransportOnce sync.Once
)

// GetDefaultTransport 返回全局共享的 HTTP Transport
// 所有 HTTP 客户端都应该使用这个 Transport，避免连接泄漏
func GetDefaultTransport() *http.Transport {
	defaultTransportOnce.Do(func() {
		defaultTransport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          1024,             // 最大空闲连接数
			MaxIdleConnsPerHost:   128,              // 每个主机的最大空闲连接数
			MaxConnsPerHost:       256,              // 限制慢上游触发的拨号并发
			IdleConnTimeout:       90 * time.Second, // 空闲连接超时
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second, // 响应头超时，防止连接泄漏
			// 读写缓冲区大小
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
			// 不验证证书（用于内部通信）
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			// 连接池生命周期管理
			// 设置为 0 表示不限制连接的生命周期
		}
	})
	return defaultTransport
}

// GetDefaultClient 返回一个默认配置的 HTTP Client
// 适用于大多数场景的外部 HTTP 请求
func GetDefaultClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: GetDefaultTransport(),
	}
}

// NewClient 创建一个新的 HTTP Client，但使用共享的 Transport
// 这样可以避免每个 Client 都创建自己的连接池
func NewClient(timeout time.Duration) *http.Client {
	return GetDefaultClient(timeout)
}

// GetShortLivedClient 返回一个短生命周期的 HTTP Client
// 用于一次性请求，会自动关闭连接
func GetShortLivedClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 5 * time.Second, // 短暂的 KeepAlive
			}).DialContext,
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		},
	}
}
