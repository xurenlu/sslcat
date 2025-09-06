package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/logger"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"
	"github.com/xurenlu/sslcat/internal/web"

	"github.com/sirupsen/logrus"
)

var (
	version = "1.0.13"
	build   = "dev"
)

// isIPHost 检查Host是否为IP地址
func isIPHost(host string) bool {
	// 移除端口号（如果有的话）
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	// 检查是否为有效的IP地址
	return net.ParseIP(host) != nil
}

func main() {
	var (
		configFile  = flag.String("config", "/etc/sslcat/sslcat.conf", "配置文件路径")
		adminPrefix = flag.String("admin-prefix", "/sslcat-panel", "管理面板路径前缀")
		email       = flag.String("email", "", "SSL证书邮箱")
		staging     = flag.Bool("staging", false, "使用Let's Encrypt测试环境")
		port        = flag.Int("port", 443, "监听端口")
		host        = flag.String("host", "0.0.0.0", "监听地址")
		logLevel    = flag.String("log-level", "info", "日志级别")
		showVersion = flag.Bool("version", false, "显示版本信息")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("SSLcat v%s (build: %s)\n", version, build)
		return
	}

	// 初始化日志
	logger.Init(*logLevel)
	log := logrus.WithFields(logrus.Fields{
		"component": "main",
	})

	log.Infof("Starting SSLcat v%s (build: %s)", version, build)

	// 加载配置
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// 覆盖配置
	if *adminPrefix != "/sslcat-panel" {
		cfg.AdminPrefix = *adminPrefix
	}
	if *email != "" {
		cfg.SSL.Email = *email
	}
	if *staging {
		cfg.SSL.Staging = true
	}
	if *port != 443 {
		cfg.Server.Port = *port
	}
	if *host != "0.0.0.0" {
		cfg.Server.Host = *host
	}

	// 创建必要目录
	if err := os.MkdirAll("/etc/sslcat", 0755); err != nil {
		log.Warnf("failed to create system config dir, falling back to CWD: %v", err)
	}
	if err := os.MkdirAll("/var/lib/sslcat", 0755); err != nil {
		log.Warnf("failed to create system data dir, falling back to CWD: %v", err)
	}

	// 初始化模块
	sslManager, err := ssl.NewManager(cfg)
	if err != nil {
		log.Fatalf("failed to init SSL manager: %v", err)
	}
	securityManager := security.NewManager(cfg)
	proxyManager := proxy.NewManager(cfg, sslManager, securityManager)
	webServer := web.NewServer(cfg, proxyManager, securityManager, sslManager)

	// 日志级别
	if cfg.Server.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// 启动子模块
	if err := sslManager.Start(); err != nil {
		log.Fatalf("启动SSL管理器失败: %v", err)
	}
	if err := proxyManager.Start(); err != nil {
		log.Fatalf("启动代理管理器失败: %v", err)
	}
	securityManager.Start()

	// 注册 TLS ClientHello 指纹回调
	sslManager.SetOnClientHello(func(hello *tls.ClientHelloInfo) {
		// 生成一个简单指纹：SNI + 曲线/签名算法数量 + ALPN数量
		sni := strings.ToLower(strings.TrimSpace(hello.ServerName))
		cipherCount := len(hello.SupportedCurves) + len(hello.SignatureSchemes)
		alpnCount := len(hello.SupportedProtos)
		raw := fmt.Sprintf("sni=%s;c=%d;a=%d", sni, cipherCount, alpnCount)
		fp := security.HashTLSRaw(raw)
		securityManager.LogTLSFingerprint(fp, "")
	})

	// 启动HTTP(S)
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      webServer,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    sslManager.GetTLSConfig(),
	}
	go func() {
		log.Infof("HTTPS server listening on %s (multi-domain SSL supported)", server.Addr)
		if cfg.Server.Port == 443 || cfg.Server.Port == 8443 {
			if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("failed to start HTTPS server: %v", err)
			}
		} else {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("failed to start HTTP server: %v", err)
			}
		}
	}()

	// 如果是443端口，同时启动80端口的HTTP重定向服务器，并处理 ACME HTTP-01 挑战
	if cfg.Server.Port == 443 {
		go func() {
			redirectServer := &http.Server{
				Addr: fmt.Sprintf("%s:80", cfg.Server.Host),
				Handler: sslManager.HTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// 检查Host是否为IP地址，如果是IP则不重定向到HTTPS
					if isIPHost(r.Host) {
						// IP访问时，检查是否有代理配置
						if rule := proxyManager.GetProxyConfig(r.Host); rule != nil {
							proxyManager.ProxyRequest(w, r, rule)
							return
						}
						// IP访问且无代理配置时，返回默认页面
						webServer.ServeHTTP(w, r)
						return
					}

					// 域名访问的处理逻辑
					// 检查是否是管理面板路径或API路径
					if strings.HasPrefix(r.URL.Path, cfg.AdminPrefix) {
						// 管理面板路径重定向到HTTPS
						httpsURL := fmt.Sprintf("https://%s%s", r.Host, r.RequestURI)
						http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
						return
					}

					// 其他路径通过代理处理（如果有配置）
					if rule := proxyManager.GetProxyConfig(r.Host); rule != nil {
						proxyManager.ProxyRequest(w, r, rule)
						return
					}

					// 没有配置的域名重定向到HTTPS
					httpsURL := fmt.Sprintf("https://%s%s", r.Host, r.RequestURI)
					http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
				})),
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			}

			log.Infof("HTTP redirect server listening on %s:80", cfg.Server.Host)
			if err := redirectServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Errorf("HTTP redirect server error: %v", err)
			}
		}()
	}

	// 等待信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	sig := <-quit
	log.Infof("Received signal %v, starting graceful shutdown...", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	securityManager.Stop()
	proxyManager.Stop()
	sslManager.Stop()
	_ = server.Shutdown(ctx)
	log.Info("SSLcat server stopped")
}
