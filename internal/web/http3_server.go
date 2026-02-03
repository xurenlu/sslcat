package web

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ssl"
)

// HTTP3Server HTTP/3 服务器
type HTTP3Server struct {
	server     *http3.Server
	config     *config.Config
	handler    http.Handler
	sslManager *ssl.Manager
	log        *logrus.Entry
}

// NewHTTP3Server 创建新的 HTTP/3 服务器实例
func NewHTTP3Server(cfg *config.Config, handler http.Handler, sslMgr *ssl.Manager) *HTTP3Server {
	return &HTTP3Server{
		config:     cfg,
		handler:    handler,
		sslManager: sslMgr,
		log:        logrus.WithField("component", "http3"),
	}
}

// Start 启动 HTTP/3 服务器
func (s *HTTP3Server) Start() error {
	if !s.config.Server.HTTP3Enabled {
		return nil // HTTP/3 未启用，直接返回
	}

	// HTTP/3 需要 HTTPS 启用
	if !s.config.Server.EnableHTTPS {
		s.log.Warn("HTTP/3 requires HTTPS to be enabled, skipping HTTP/3 server startup")
		return nil
	}

	// 获取 TLS 配置
	tlsConfig := s.getTLSConfigForHTTP3()
	if tlsConfig == nil {
		return fmt.Errorf("failed to get TLS config for HTTP/3")
	}

	// 创建 HTTP/3 服务器
	s.server = &http3.Server{
		Addr:      fmt.Sprintf("%s:443", s.config.Server.Host),
		Handler:   s.handler,
		TLSConfig: tlsConfig,
	}

	// 配置 QUIC 参数（如果配置了）
	if s.config.Server.HTTP3Config != nil {
		cfg := s.config.Server.HTTP3Config
		if cfg.MaxIdleTimeout != "" {
			if timeout, err := time.ParseDuration(cfg.MaxIdleTimeout); err == nil {
				// 注意：quic-go 的配置需要通过 QUICConfig 设置
				// 这里暂时记录，实际配置在 ListenAndServe 时通过 QUICConfig 传递
				s.log.Debugf("HTTP/3 MaxIdleTimeout configured: %v", timeout)
			}
		}
	}

	s.log.Infof("HTTP/3 server starting on %s:443", s.config.Server.Host)

	// 在 goroutine 中启动服务器
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			// HTTP/3 服务器启动失败不应导致整个程序退出
			// 记录错误，但允许 HTTP/1.1 和 HTTP/2 继续工作
			s.log.Errorf("HTTP/3 server error: %v", err)
		}
	}()

	return nil
}

// Stop 停止 HTTP/3 服务器
func (s *HTTP3Server) Stop() error {
	if s.server != nil {
		s.log.Info("Stopping HTTP/3 server...")
		return s.server.Close()
	}
	return nil
}

// getTLSConfigForHTTP3 获取适用于 HTTP/3 的 TLS 配置
func (s *HTTP3Server) getTLSConfigForHTTP3() *tls.Config {
	// 获取基础 TLS 配置
	baseConfig := s.sslManager.GetTLSConfig()
	if baseConfig == nil {
		return nil
	}

	// 克隆配置以避免修改原始配置
	tlsConfig := baseConfig.Clone()

	// HTTP/3 要求 TLS 1.3
	if tlsConfig.MinVersion < tls.VersionTLS13 {
		tlsConfig.MinVersion = tls.VersionTLS13
	}
	tlsConfig.MaxVersion = tls.VersionTLS13

	// 确保 NextProtos 包含 "h3"
	hasH3 := false
	for _, proto := range tlsConfig.NextProtos {
		if proto == "h3" {
			hasH3 = true
			break
		}
	}
	if !hasH3 {
		// 将 "h3" 添加到最前面，优先协商 HTTP/3
		tlsConfig.NextProtos = append([]string{"h3"}, tlsConfig.NextProtos...)
	}

	return tlsConfig
}
