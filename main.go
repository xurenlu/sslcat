package main

import (
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

	"github.com/xurenlu/sslcat/internal/cache"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/i18n"
	"github.com/xurenlu/sslcat/internal/logger"
	"github.com/xurenlu/sslcat/internal/notification"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/runner"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"
	"github.com/xurenlu/sslcat/internal/web"

	"github.com/sirupsen/logrus"
	_ "github.com/xurenlu/sslcat/internal/database"
)

var (
	version = "1.3.13-rc5"
	build   = "dev"
)

// isIPHost 检查Host是否为IP地址或localhost
func isIPHost(host string) bool {
	// 移除端口号（如果有的话）
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	// 检查是否为localhost
	if host == "localhost" {
		return true
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
		testConfig  = flag.Bool("test", false, "测试配置文件语法和完整性")
		checkConfig = flag.Bool("check", false, "检查配置文件并显示详细信息")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("SSLcat v%s (build: %s)\n", version, build)
		return
	}

	// 配置文件测试模式
	if *testConfig {
		fmt.Printf("🧪 测试配置文件: %s\n", *configFile)
		result, err := config.ValidateConfigFile(*configFile)
		if err != nil {
			fmt.Printf("❌ 验证过程出错: %v\n", err)
			os.Exit(1)
		}

		if result.Valid {
			fmt.Println("✅ 配置文件语法正确，所有必要设置已配置")
			os.Exit(0)
		} else {
			fmt.Printf("❌ 配置文件有 %d 个错误\n", len(result.Errors))
			for _, err := range result.Errors {
				fmt.Printf("   %s: %s\n", err.Field, err.Message)
			}
			os.Exit(1)
		}
	}

	// 配置文件检查模式
	if *checkConfig {
		result, err := config.ValidateConfigFile(*configFile)
		if err != nil {
			fmt.Printf("❌ 验证过程出错: %v\n", err)
			os.Exit(1)
		}

		config.PrintValidationResult(result, *configFile)

		if result.Valid {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
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

	// 创建配置监听器
	configWatcher, err := config.NewConfigWatcher(*configFile, cfg)
	if err != nil {
		log.Fatalf("failed to create config watcher: %v", err)
	}

	// 创建重载管理器
	reloadManager := config.NewReloadManager()

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
		// 使用 --port 参数时，自动切换到自定义模式
		cfg.Server.Port = *port
		cfg.Server.PortMode = "custom"
		cfg.Server.CustomPort = *port
		cfg.Server.EnableHTTPS = false
	}
	if *host != "0.0.0.0" {
		cfg.Server.Host = *host
	}

	// 启动时输出关键配置（不打印密码）
	log.WithFields(logrus.Fields{
		"config_file":             cfg.ConfigFile,
		"admin_prefix":            cfg.AdminPrefix,
		"server.host":             cfg.Server.Host,
		"server.port":             cfg.Server.Port,
		"server.debug":            cfg.Server.Debug,
		"access_log.enabled":      cfg.Server.AccessLogEnabled,
		"access_log.format":       cfg.Server.AccessLogFormat,
		"access_log.path":         cfg.Server.AccessLogPath,
		"access_log.max_size":     cfg.Server.AccessLogMaxSize,
		"access_log.max_files":    cfg.Server.AccessLogMaxFiles,
		"ssl.email":               cfg.SSL.Email,
		"ssl.staging":             cfg.SSL.Staging,
		"ssl.auto_renew":          cfg.SSL.AutoRenew,
		"ssl.disable_self_signed": cfg.SSL.DisableSelfSigned,
		"ssl.cert_dir":            cfg.SSL.CertDir,
		"ssl.key_dir":             cfg.SSL.KeyDir,
		"admin.username":          cfg.Admin.Username,
		"admin.password_file":     cfg.Admin.PasswordFile,
		"proxy.rules_count":       len(cfg.Proxy.Rules),
		"static_sites.count":      len(cfg.StaticSites),
		"php_sites.count":         len(cfg.PHPSites),
		"cluster.mode":            cfg.Cluster.Mode,
		"security.enable_waf":     cfg.Security.EnableWAF,
		"security.enable_ddos":    cfg.Security.EnableDDOS,
		"security.ua_filter":      cfg.Security.EnableUAFilter,
		"server.read_timeout":     cfg.Server.ReadTimeoutSec,
		"server.write_timeout":    cfg.Server.WriteTimeoutSec,
		"server.idle_timeout":     cfg.Server.IdleTimeoutSec,
		"server.max_upload_bytes": cfg.Server.MaxUploadBytes,
	}).Info("Effective configuration loaded")

	// 创建必要目录
	if err := os.MkdirAll("/etc/sslcat", 0755); err != nil {
		log.Warnf("failed to create system config dir, falling back to CWD: %v", err)
	}
	if err := os.MkdirAll("/var/lib/sslcat", 0755); err != nil {
		log.Warnf("failed to create system data dir, falling back to CWD: %v", err)
	}

	// 初始化通知集成器
	notificationIntegrator := notification.NewNotificationIntegratorFromConfig(cfg.Notification)

	// 初始化模块
	sslManager, err := ssl.NewManager(cfg)
	if err != nil {
		log.Fatalf("failed to init SSL manager: %v", err)
	}
	// 设置SSL管理器的通知集成器
	sslManager.SetNotificationIntegrator(notificationIntegrator)
	securityManager := security.NewManager(cfg)
	cdnCache := cache.NewCDNCache(cfg)
	cdnCache.StartCleaner()
	proxyManager := proxy.NewManager(cfg, sslManager, securityManager, cdnCache, version)

	// 初始化翻译器
	translator := i18n.NewTranslator(i18n.LangZhCN, "i18n")

	// 初始化 Runner 模块
	gitServer := runner.NewGitServer(cfg, translator)

	// 注入 SSL Manager 到 Git Server（用于自动申请证书）
	gitServer.SetSSLManager(sslManager)

	webServer := web.NewServer(cfg, proxyManager, securityManager, sslManager, gitServer, notificationIntegrator, version)

	// 注册可重载组件
	reloadManager.RegisterComponent(proxyManager)
	// 注意：其他组件（如sslManager, securityManager）也需要实现ReloadableComponent接口才能注册

	// 用于记录配置重载开始时间
	var reloadStartTime time.Time

	// 设置配置变化回调
	configWatcher.OnConfigChange(func(oldConfig, newConfig *config.Config) error {
		log.Info("Configuration changed, starting hot reload...")
		return reloadManager.ReloadAll(oldConfig, newConfig)
	})

	configWatcher.OnReloadStart(func() {
		log.Info("Configuration reload started")
		reloadStartTime = time.Now()
	})

	configWatcher.OnReloadSuccess(func(newConfig *config.Config) {
		duration := time.Since(reloadStartTime)
		log.Infof("Configuration reload completed successfully in %v", duration)

		// 更新全局配置引用
		cfg = newConfig
		// 更新Web服务器的配置引用
		webServer.UpdateConfig(newConfig)

		// 重新初始化日志系统（如果日志级别发生变化）
		if newConfig.Server.LogLevel != "" {
			logger.Init(newConfig.Server.LogLevel)
			log.Infof("日志级别已更新为: %s", newConfig.Server.LogLevel)
		}

		// 发送配置重载成功通知
		changes := []string{"配置文件已更新"}
		if err := notificationIntegrator.SendConfigReloaded(cfg.ConfigFile, duration, changes); err != nil {
			log.Warnf("Failed to send config reload notification: %v", err)
		}
	})

	configWatcher.OnReloadError(func(err error) {
		log.Errorf("Configuration reload failed: %v", err)

		// 发送配置重载失败通知
		if err := notificationIntegrator.SendConfigReloadFailed(
			cfg.ConfigFile,
			"配置验证或应用失败",
			err.Error(),
		); err != nil {
			log.Warnf("Failed to send config reload failure notification: %v", err)
		}
	})

	// 设置Web服务器的配置重载功能
	webServer.SetupConfigReload(configWatcher, reloadManager)

	// 启动配置监听
	if err := configWatcher.Start(); err != nil {
		log.Fatalf("failed to start config watcher: %v", err)
	}
	defer configWatcher.Stop()

	// 日志级别
	if cfg.Server.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// 发送系统启动通知
	notificationIntegrator.SendSystemStartupNotification()

	// 启动子模块
	if err := sslManager.Start(); err != nil {
		log.Fatalf("启动SSL管理器失败: %v", err)
	}
	if err := proxyManager.Start(); err != nil {
		log.Fatalf("启动代理管理器失败: %v", err)
	}
	securityManager.Start()

	// 启动 Runner 模块
	if err := gitServer.Start(); err != nil {
		log.Warnf("启动 Git 服务器失败: %v", err)
	}

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

	// 组装服务端超时
	readTimeout := time.Duration(cfg.Server.ReadTimeoutSec) * time.Second
	writeTimeout := time.Duration(cfg.Server.WriteTimeoutSec) * time.Second
	idleTimeout := time.Duration(cfg.Server.IdleTimeoutSec) * time.Second
	if cfg.Server.ReadTimeoutSec <= 0 {
		readTimeout = 30 * time.Second
	}
	if cfg.Server.WriteTimeoutSec <= 0 {
		writeTimeout = 30 * time.Second
	}
	if cfg.Server.IdleTimeoutSec <= 0 {
		idleTimeout = 120 * time.Second
	}

	// 根据端口模式启动服务器
	switch cfg.Server.PortMode {
	case "standard":
		startStandardMode(cfg, webServer, sslManager, proxyManager, readTimeout, writeTimeout, idleTimeout)
	case "custom":
		startCustomMode(cfg, webServer, readTimeout, writeTimeout, idleTimeout)
	default:
		// 默认使用标准模式
		startStandardMode(cfg, webServer, sslManager, proxyManager, readTimeout, writeTimeout, idleTimeout)
	}

	// 等待信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	sig := <-quit
	logrus.Infof("Received signal %v, starting graceful shutdown...", sig)

	// 发送系统关闭通知
	notificationIntegrator.SendSystemShutdownNotification()

	securityManager.Stop()
	proxyManager.Stop()
	sslManager.Stop()

	// 停止 Runner 模块
	gitServer.Stop()

	logrus.Info("SSLcat server stopped")
}

// startStandardMode 启动标准模式（监听 80 和 443 端口）
func startStandardMode(cfg *config.Config, webServer http.Handler, sslManager *ssl.Manager, proxyManager *proxy.Manager, readTimeout, writeTimeout, idleTimeout time.Duration) {
	// 启动 HTTPS 服务器 (443)
	if cfg.Server.EnableHTTPS {
		httpsServer := &http.Server{
			Addr:         fmt.Sprintf("%s:443", cfg.Server.Host),
			Handler:      webServer,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
			TLSConfig:    sslManager.GetTLSConfig(),
		}
		go func() {
			logrus.Infof("HTTPS server listening on %s:443 (multi-domain SSL supported)", cfg.Server.Host)
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logrus.Fatalf("failed to start HTTPS server: %v", err)
			}
		}()
	}

	// 启动 HTTP 重定向服务器 (80)
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
				// 检查是否是来自 localhost 的 API 请求（不重定向，直接处理）
				clientIP := r.RemoteAddr
				if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
					clientIP = clientIP[:idx]
				}
				isLocalhost := clientIP == "127.0.0.1" || clientIP == "::1" || strings.HasPrefix(clientIP, "127.")
				isAPIPath := strings.Contains(r.URL.Path, "/api/")

				if isLocalhost && isAPIPath {
					// localhost 的 API 请求直接处理，不重定向
					webServer.ServeHTTP(w, r)
					return
				}

				// 其他管理面板路径：只有在有有效证书时才重定向到HTTPS
				host := r.Host
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				if sslManager.HasValidCertificate(host) {
					httpsURL := fmt.Sprintf("https://%s%s", r.Host, r.RequestURI)
					http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
					return
				}
				// 没有证书时，直接用 HTTP 处理
				webServer.ServeHTTP(w, r)
				return
			}

			// 其他路径通过代理处理（如果有配置）
			if rule := proxyManager.GetProxyConfig(r.Host); rule != nil {
				// 如果配置了SSLOnly且有有效证书，才重定向
				host := r.Host
				if idx := strings.Index(host, ":"); idx != -1 {
					host = host[:idx]
				}
				if rule.SSLOnly && sslManager.HasValidCertificate(host) {
					httpsURL := fmt.Sprintf("https://%s%s", r.Host, r.RequestURI)
					http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
					return
				}
				proxyManager.ProxyRequest(w, r, rule)
				return
			}

			// 没有配置的域名：默认用 HTTP 处理，不强制重定向
			webServer.ServeHTTP(w, r)
		})),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	go func() {
		logrus.Infof("HTTP redirect server listening on %s:80", cfg.Server.Host)
		if err := redirectServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Errorf("HTTP redirect server error: %v", err)
		}
	}()
}

// startCustomMode 启动自定义模式（监听单个端口）
func startCustomMode(cfg *config.Config, webServer http.Handler, readTimeout, writeTimeout, idleTimeout time.Duration) {
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.CustomPort),
		Handler:      webServer,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	go func() {
		logrus.Infof("HTTP server listening on %s (custom port mode)", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("failed to start HTTP server: %v", err)
		}
	}()
}
