package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
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

	// 稳定性改进：添加重试机制
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	restartMu  sync.Mutex
	retryCount int
	maxRetries int
}

// NewHTTP3Server 创建新的 HTTP/3 服务器实例
func NewHTTP3Server(cfg *config.Config, handler http.Handler, sslMgr *ssl.Manager) *HTTP3Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &HTTP3Server{
		config:     cfg,
		handler:    handler,
		sslManager: sslMgr,
		log:        logrus.WithField("component", "http3"),
		ctx:        ctx,
		cancel:     cancel,
		maxRetries: 5, // 最多重试5次
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

	// 启动服务器（带重试机制）
	s.wg.Add(1)
	go s.runWithRetry()

	return nil
}

// runWithRetry 带重试机制的服务器运行函数
func (s *HTTP3Server) runWithRetry() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// 检查重试次数
		if s.retryCount >= s.maxRetries {
			s.log.Errorf("HTTP/3 server failed after %d retries, giving up", s.maxRetries)
			return
		}

		// 获取 TLS 配置
		tlsConfig := s.getTLSConfigForHTTP3()
		if tlsConfig == nil {
			s.log.Error("Failed to get TLS config for HTTP/3")
			s.retryCount++
			// 使用 select 来响应 context 取消
			select {
			case <-s.ctx.Done():
				s.log.Info("HTTP/3 server shutdown requested during TLS config retry")
				return
			case <-time.After(5 * time.Second):
				// 继续重试
			}
			continue
		}

		// 创建 HTTP/3 服务器
		s.restartMu.Lock()
		s.server = &http3.Server{
			Addr:       fmt.Sprintf("%s:443", s.config.Server.Host),
			Handler:    s.handler,
			TLSConfig:  tlsConfig,
			QUICConfig: s.getQUICConfigForHTTP3(),
		}
		s.restartMu.Unlock()

		if s.retryCount == 0 {
			s.log.Infof("HTTP/3 server starting on %s:443", s.config.Server.Host)
		} else {
			s.log.Warnf("HTTP/3 server restarting (attempt %d/%d) on %s:443", s.retryCount+1, s.maxRetries, s.config.Server.Host)
		}

		// 启动服务器
		err := s.server.ListenAndServe()

		// 检查是否是正常关闭
		if err == nil || err == http.ErrServerClosed {
			s.log.Info("HTTP/3 server stopped normally")
			return
		}

		// 记录错误
		s.log.Errorf("HTTP/3 server error: %v (retry %d/%d)", err, s.retryCount+1, s.maxRetries)

		// 增加重试计数
		s.retryCount++

		// 等待后重试（指数退避：5s, 10s, 20s, 40s, 80s）
		// 使用 select 来响应 context 取消，避免在关闭时还要等待 sleep 完成
		backoff := time.Duration(5*(1<<uint(s.retryCount-1))) * time.Second
		if backoff > 80*time.Second {
			backoff = 80 * time.Second
		}
		s.log.Debugf("Waiting %v before retry...", backoff)

		select {
		case <-s.ctx.Done():
			s.log.Info("HTTP/3 server shutdown requested during retry backoff")
			return
		case <-time.After(backoff):
			// 继续重试
		}
	}
}

// Stop 停止 HTTP/3 服务器
func (s *HTTP3Server) Stop() error {
	// 取消上下文，停止重试循环
	s.cancel()

	// 停止服务器
	s.restartMu.Lock()
	if s.server != nil {
		s.log.Info("Stopping HTTP/3 server...")
		err := s.server.Close()
		s.restartMu.Unlock()

		// 等待 goroutine 结束
		s.wg.Wait()

		return err
	}
	s.restartMu.Unlock()

	// 等待 goroutine 结束
	s.wg.Wait()

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

func (s *HTTP3Server) getQUICConfigForHTTP3() *quic.Config {
	maxIdleTimeout := 120 * time.Second
	maxIncomingStreams := int64(1000)
	maxIncomingUniStreams := int64(1000)

	if cfg := s.config.Server.HTTP3Config; cfg != nil {
		if cfg.MaxIdleTimeout != "" {
			if timeout, err := time.ParseDuration(cfg.MaxIdleTimeout); err == nil && timeout > 0 {
				maxIdleTimeout = timeout
			} else if err != nil {
				s.log.Warnf("Invalid HTTP/3 max_idle_timeout %q, using %s: %v", cfg.MaxIdleTimeout, maxIdleTimeout, err)
			}
		}
		if cfg.MaxIncomingStreams > 0 {
			maxIncomingStreams = cfg.MaxIncomingStreams
		}
		if cfg.MaxIncomingUniStreams > 0 {
			maxIncomingUniStreams = cfg.MaxIncomingUniStreams
		}
	}

	return &quic.Config{
		HandshakeIdleTimeout:       10 * time.Second,
		MaxIdleTimeout:             maxIdleTimeout,
		MaxIncomingStreams:         maxIncomingStreams,
		MaxIncomingUniStreams:      maxIncomingUniStreams,
		KeepAlivePeriod:            maxIdleTimeout / 2,
		MaxStreamReceiveWindow:     8 << 20,
		MaxConnectionReceiveWindow: 32 << 20,
	}
}
