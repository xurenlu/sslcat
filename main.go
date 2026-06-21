package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xurenlu/sslcat/internal/cache"
	"github.com/xurenlu/sslcat/internal/cli"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/i18n"
	"github.com/xurenlu/sslcat/internal/logger"
	"github.com/xurenlu/sslcat/internal/monitor"
	"github.com/xurenlu/sslcat/internal/notification"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/report"
	"github.com/xurenlu/sslcat/internal/runner"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"
	"github.com/xurenlu/sslcat/internal/threatintel"
	"github.com/xurenlu/sslcat/internal/web"

	"github.com/sirupsen/logrus"
	_ "github.com/xurenlu/sslcat/internal/database"
	"golang.org/x/net/http2"
)

var (
	version = "2.3.0-rc1"
	build   = "dev"
)

// init 函数在包导入时执行，在所有其他初始化之前
// 强制使用纯 Go DNS 解析器，避免 CGO DNS 解析导致的 SIGFPE 异常
func init() {
	// 检查是否已经设置了 GODEBUG，如果没有则设置
	if os.Getenv("GODEBUG") == "" {
		os.Setenv("GODEBUG", "netdns=go")
	} else {
		// 如果已经设置，确保包含 netdns=go
		debug := os.Getenv("GODEBUG")
		if !strings.Contains(debug, "netdns=") {
			os.Setenv("GODEBUG", debug+",netdns=go")
		}
	}
}

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
	// 检查是否是帮助请求（-h 或 --help）
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		showHelp()
		return
	}

	cliManager := newCLIManager()
	cliCommandIndex := findCLICommandIndex(cliManager, os.Args[1:])
	// 检查是否是 CLI 命令（在定义 flag 之前检查）
	if cliCommandIndex >= 0 {
		// 处理子命令

		// 解析配置文件路径：未指定 -config 时，若存在系统安装配置则优先使用（与 systemd 服务一致）
		configFile := "sslcat.conf"
		configExplicit := false
		for i, arg := range os.Args {
			if arg == "-config" && i+1 < len(os.Args) {
				configFile = os.Args[i+1]
				configExplicit = true
				break
			}
		}
		if !configExplicit {
			const systemConfig = "/etc/sslcat/sslcat.conf"
			if _, err := os.Stat(systemConfig); err == nil {
				configFile = systemConfig
			}
		}

		// 加载配置用于 CLI 命令
		// 注意：config.Load() 如果文件不存在会返回默认配置，不会报错
		cfg, err := config.Load(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ 加载配置文件失败: %v\n", err)
			os.Exit(1)
		}
		cliManager.SetConfig(cfg)
		cliManager.SetConfigFile(configFile)

		// 执行命令
		if err := cliManager.Execute(os.Args[cliCommandIndex:]); err != nil {
			fmt.Fprintf(os.Stderr, "❌ 命令执行失败: %v\n", err)
			fmt.Fprintf(os.Stderr, "💡 提示: 使用 'sslcat help' 查看所有可用命令\n")
			os.Exit(1)
		}
		// CLI 命令执行成功，退出程序
		os.Exit(0)
	}

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

		// pprof 相关命令
		pprofEnable  = flag.Bool("pprof-enable", false, "启用 pprof 性能分析端点")
		pprofDisable = flag.Bool("pprof-disable", false, "禁用 pprof 性能分析端点")
		pprofExport  = flag.String("pprof-export", "", "导出 pprof 数据 (heap|cpu|goroutine|allocs|block|mutex)")
		pprofOutput  = flag.String("pprof-output", "", "导出文件路径 (默认: ./sslcat-{type}-{timestamp}.pprof)")
		pprofServer  = flag.String("pprof-server", "http://localhost:8080", "pprof 服务器地址")
	)

	flag.Parse()

	if *showVersion {
		ver := strings.TrimPrefix(version, "v")
		fmt.Printf("SSLcat v%s (build: %s)\n", ver, build)
		return
	}

	// pprof 命令处理
	if *pprofEnable || *pprofDisable || *pprofExport != "" {
		handlePprofCommands(configFile, pprofEnable, pprofDisable, pprofExport, pprofOutput, pprofServer)
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

	log.Infof("Starting SSLcat v%s (build: %s)", strings.TrimPrefix(version, "v"), build)

	// 配置 Go 运行时内存管理：优化 GC 以减少 CPU 占用
	// 1. 设置 GC 触发阈值
	//    GOGC 可以是任意正数值：
	//    - 默认 200：每增长 200% 内存触发 GC（平衡值，适合大多数场景）
	//    - 100：每增长 100% 内存触发 GC（Go 默认值，适合内存受限环境）
	//    - 300：每增长 300% 内存触发 GC（适合低流量场景，减少 GC 频率）
	//    - 50：每增长 50% 内存就触发 GC（更频繁，内存峰值更低，CPU 占用高）
	//    可以通过环境变量 GOGC 设置，也可以在代码中设置默认值
	//    注意：Go 运行时会自动读取 GOGC 环境变量，如果设置了环境变量，会优先使用
	//    推荐值：200（平衡）、300（低流量）、100（内存受限）
	goGCEnv := os.Getenv("GOGC")
	if goGCEnv != "" {
		// 解析环境变量值
		var goGCPercent int
		if _, err := fmt.Sscanf(goGCEnv, "%d", &goGCPercent); err == nil && goGCPercent > 0 {
			debug.SetGCPercent(goGCPercent) // 显式设置以确保生效
			log.Infof("GOGC set to %d via environment variable", goGCPercent)
		} else {
			log.Warnf("Invalid GOGC value '%s', using default", goGCEnv)
			debug.SetGCPercent(100) // 无效值时使用默认值 100
			log.Info("Set GC percent to 100 (default)")
		}
	} else {
		// 如果未设置 GOGC 环境变量，使用代码设置的默认值 200
		// GOGC=200 是一个平衡值：既能减少 GC 频率降低 CPU 占用，又不会导致内存占用过高
		// 适合大多数场景，包括中低流量的生产环境
		debug.SetGCPercent(200)
		log.Info("Set GC percent to 200 for balanced GC pressure (can be adjusted via GOGC env var)")
	}

	// 2. 设置内存限制（如果未通过环境变量设置）
	if os.Getenv("GOMEMLIMIT") == "" {
		// 默认设置 1GB 内存限制
		debug.SetMemoryLimit(1024 * 1024 * 1024) // 1GB
		log.Info("Set memory limit to 1GB")
	}

	// 3. 启动定期内存释放 goroutine（每 5 分钟释放一次空闲内存）
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			// 强制 GC
			runtime.GC()
			// 请求将空闲内存归还给操作系统
			debug.FreeOSMemory()
			log.Debug("Memory released to OS")
		}
	}()

	// 如果提供了 --email 参数，需要先设置到环境变量或临时配置中
	// 因为 config.Load 会验证 SSL email
	if *email != "" {
		// 设置环境变量供 config.Load 使用
		os.Setenv("SSLCAT_SSL_EMAIL", *email)
	}

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
		"ssl.auto_renew":          cfg.SSL.IsAutoRenewEnabled(),
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
	if err := os.MkdirAll("/opt/sslcat", 0755); err != nil {
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

	// 初始化威胁情报管理器
	threatIntelManager := threatintel.NewThreatIntelManager(cfg)
	// 将威胁情报管理器链接到安全管理器
	securityManager.SetThreatIntelManager(threatIntelManager)

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

	// 将威胁情报管理器链接到 Web 服务器
	webServer.SetThreatIntelManager(threatIntelManager)

	// 注册可重载组件
	reloadManager.RegisterComponent(proxyManager)
	reloadManager.RegisterComponent(sslManager)
	reloadManager.RegisterComponent(securityManager)
	// 注意：其他组件（如 gitServer 等）如果需要热重载，也需要实现 ReloadableComponent 接口并在此注册

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

	// 日志级别 - 优先使用配置文件中的 log_level
	if cfg.Server.LogLevel != "" {
		logger.Init(cfg.Server.LogLevel)
		log.Infof("日志级别已设置为: %s", cfg.Server.LogLevel)
	} else if cfg.Server.Debug {
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

	// 启动威胁情报管理器
	threatIntelManager.Start()

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
	var serverManager *ServerManager
	switch cfg.Server.PortMode {
	case "standard":
		serverManager = startStandardMode(cfg, webServer, sslManager, proxyManager, readTimeout, writeTimeout, idleTimeout)
	case "custom":
		startCustomMode(cfg, webServer, readTimeout, writeTimeout, idleTimeout)
		serverManager = nil // 自定义模式不返回服务器管理器
	default:
		// 默认使用标准模式
		serverManager = startStandardMode(cfg, webServer, sslManager, proxyManager, readTimeout, writeTimeout, idleTimeout)
	}

	// 启用 mutex 和 block profiling（在 pprof 启用时）
	// 这可以帮助诊断锁竞争和阻塞问题
	if cfg.Server.EnablePprof {
		runtime.SetMutexProfileFraction(10) // 采样 10% 的 mutex 争用
		runtime.SetBlockProfileRate(1)      // 记录所有阻塞操作
		logrus.Info("Mutex 和 Block profiling 已启用")
	}

	// 启动内存监控
	startMemoryMonitor(cdnCache, proxyManager)

	// 初始化报告生成系统
	var reportScheduler *report.ReportScheduler
	if cfg.Report.Enabled {
		// 获取必要的组件
		wafEngine := webServer.GetWAFEngine()
		ddosProtector := webServer.GetDDoSProtector()
		statsCollector := webServer.GetStatisticsCollector()
		monitorManager := webServer.GetMonitorManager()

		var metricsStorage *monitor.MetricsStorage
		if monitorManager != nil {
			metricsStorage = monitorManager.GetMetricsStorage()
		}

		// 创建数据收集器
		dataCollector := report.NewDataCollector(
			metricsStorage,
			wafEngine,
			ddosProtector,
			sslManager,
			statsCollector,
		)

		// 创建AI报告生成器
		aiReporter := report.NewAIReporter(&cfg.Report)
		// 如果AI配置中没有APIKey，尝试从AISecurity配置中获取
		if cfg.Report.AI.APIKey == "" && cfg.AISecurity.APIKey != "" {
			cfg.Report.AI.APIKey = cfg.AISecurity.APIKey
			cfg.Report.AI.APIEndpoint = cfg.AISecurity.APIEndpoint
			aiReporter = report.NewAIReporter(&cfg.Report)
		}

		// 创建报告生成器
		reportGenerator := report.NewReportGenerator(
			dataCollector,
			aiReporter,
			notificationIntegrator,
			cfg.Report.Enabled,
		)

		// 创建并启动调度器
		reportScheduler = report.NewReportScheduler(reportGenerator, &cfg.Report)
		reportScheduler.Start()

		// 将报告生成器注入到webServer（用于API调用）
		webServer.SetReportGenerator(reportGenerator)

		log.Info("报告生成系统已启动")
	}

	// 等待信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	sig := <-quit
	logrus.Infof("Received signal %v, starting graceful shutdown...", sig)

	// 发送系统关闭通知
	notificationIntegrator.SendSystemShutdownNotification()

	// 停止各个模块
	securityManager.Stop()
	proxyManager.Stop()
	sslManager.Stop()

	// 停止威胁情报管理器
	threatIntelManager.Stop()

	// 停止 Runner 模块
	gitServer.Stop()

	// 停止报告调度器
	if reportScheduler != nil {
		reportScheduler.Stop()
	}

	// 停止 Web 服务器（包括隧道管理器）
	webServer.Stop()

	// 停止所有 HTTP/HTTPS 服务器（包括 HTTP/2 和 HTTP/3）
	if serverManager != nil {
		serverManager.Stop()
	}

	// 停止通知管理器
	if notificationIntegrator != nil && notificationIntegrator.GetManager() != nil {
		notificationIntegrator.GetManager().Stop()
	}

	logrus.Info("SSLcat server stopped")
}

func newCLIManager() *cli.Manager {
	cliManager := cli.NewManager()
	cliManager.SetVersion(version, build)
	cliManager.RegisterOpsCommands()
	cliManager.RegisterConfigCommands()
	cliManager.RegisterProxyCommands()
	cliManager.RegisterSiteCommands()
	cliManager.RegisterSSLCommands()
	cliManager.RegisterBlockCommands()
	cliManager.RegisterHelpCommand()
	cliManager.RegisterConsoleCommand()
	cliManager.RegisterRenewDueCommand()
	cliManager.RegisterMCPCommands()
	return cliManager
}

func findCLICommandIndex(cliManager *cli.Manager, args []string) int {
	for i, arg := range args {
		if cliManager.HasCommand(arg) {
			return i + 1
		}
	}
	return -1
}

// filteredErrorLog 过滤频繁的 TLS handshake 错误日志
type filteredErrorLog struct {
	logger     *log.Logger
	lastErrors map[string]time.Time
	mutex      sync.RWMutex
}

func newFilteredErrorLog() *filteredErrorLog {
	return &filteredErrorLog{
		logger:     log.New(io.Discard, "", 0), // 默认丢弃所有日志
		lastErrors: make(map[string]time.Time),
	}
}

func (f *filteredErrorLog) Write(p []byte) (n int, err error) {
	msg := string(p)
	// 过滤 TLS handshake 错误，避免日志刷屏
	if strings.Contains(msg, "TLS handshake error") {
		// 提取域名（如果存在）
		domain := extractDomainFromTLSError(msg)
		if domain != "" {
			f.mutex.Lock()
			lastTime, exists := f.lastErrors[domain]
			now := time.Now()
			// 同一域名的错误每5分钟只记录一次
			if !exists || now.Sub(lastTime) > 5*time.Minute {
				f.lastErrors[domain] = now
				f.mutex.Unlock()
				// 使用 logrus 记录，但级别设为 Debug，避免刷屏
				logrus.Debugf("TLS handshake error (filtered): %s", strings.TrimSpace(msg))
			} else {
				f.mutex.Unlock()
			}
		} else {
			// 没有域名信息，每5分钟记录一次
			f.mutex.Lock()
			lastTime, exists := f.lastErrors["_general_"]
			now := time.Now()
			if !exists || now.Sub(lastTime) > 5*time.Minute {
				f.lastErrors["_general_"] = now
				f.mutex.Unlock()
				logrus.Debugf("TLS handshake error (filtered): %s", strings.TrimSpace(msg))
			} else {
				f.mutex.Unlock()
			}
		}
		return len(p), nil
	}
	// 其他错误正常记录
	logrus.Debugf("HTTP server error: %s", strings.TrimSpace(msg))
	return len(p), nil
}

// extractDomainFromTLSError 从 TLS 错误消息中提取域名
func extractDomainFromTLSError(msg string) string {
	// 查找 "no certificate available for" 后面的域名
	if idx := strings.Index(msg, "no certificate available for"); idx != -1 {
		start := idx + len("no certificate available for")
		parts := strings.Fields(msg[start:])
		if len(parts) > 0 {
			domain := strings.TrimSpace(parts[0])
			// 移除可能的标点符号
			domain = strings.Trim(domain, ".,;:!?")
			return domain
		}
	}
	return ""
}

// ServerManager 管理 HTTP/HTTPS 服务器实例，用于优雅关闭
type ServerManager struct {
	httpsServer    *http.Server
	redirectServer *http.Server
	http3Server    *web.HTTP3Server
}

// Stop 优雅关闭所有服务器
func (sm *ServerManager) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 停止 HTTPS 服务器（包含 HTTP/2）
	if sm.httpsServer != nil {
		logrus.Info("Stopping HTTPS server (HTTP/1.1 and HTTP/2)...")
		if err := sm.httpsServer.Shutdown(ctx); err != nil {
			logrus.Errorf("Failed to shutdown HTTPS server: %v", err)
		} else {
			logrus.Info("HTTPS server stopped gracefully")
		}
	}

	// 停止 HTTP 重定向服务器
	if sm.redirectServer != nil {
		logrus.Info("Stopping HTTP redirect server...")
		if err := sm.redirectServer.Shutdown(ctx); err != nil {
			logrus.Errorf("Failed to shutdown HTTP redirect server: %v", err)
		} else {
			logrus.Info("HTTP redirect server stopped gracefully")
		}
	}

	// 停止 HTTP/3 服务器
	if sm.http3Server != nil {
		if err := sm.http3Server.Stop(); err != nil {
			logrus.Errorf("Failed to stop HTTP/3 server: %v", err)
		}
	}
}

// startStandardMode 启动标准模式（监听 80 和 443 端口）
// 返回服务器管理器，用于在关闭时优雅停止所有服务器
func startStandardMode(cfg *config.Config, webServer http.Handler, sslManager *ssl.Manager, proxyManager *proxy.Manager, readTimeout, writeTimeout, idleTimeout time.Duration) *ServerManager {
	// 创建过滤的 ErrorLog
	filteredLog := newFilteredErrorLog()
	manager := &ServerManager{}

	// 启动 HTTPS 服务器 (443)
	if cfg.Server.EnableHTTPS {
		httpsServer := &http.Server{
			Addr:              fmt.Sprintf("%s:443", cfg.Server.Host),
			Handler:           webServer,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			ReadHeaderTimeout: 10 * time.Second, // 读取 header 超时，防止慢速攻击
			MaxHeaderBytes:    1 << 20,          // 限制请求头最大 1MB，防止内存攻击
			IdleTimeout:       idleTimeout,
			TLSConfig:         sslManager.GetTLSConfig(),
			ErrorLog:          log.New(filteredLog, "", 0), // 使用过滤的 ErrorLog
		}
		manager.httpsServer = httpsServer

		// 配置 HTTP/2 支持（根据全局配置）
		// 注意：即使全局关闭，站点级覆盖也可能启用 HTTP/2，所以总是配置 HTTP/2 服务器
		// TLS 配置中的 NextProtos 会控制实际是否协商 HTTP/2
		// 優化參數以避免 ERR_HTTP2_PROTOCOL_ERROR：
		// - MaxConcurrentStreams: 根据配置调整，默认 250
		// - MaxReadFrameSize: 根据配置调整，默认 1MB
		// - IdleTimeout: 根据配置调整，默认 120 秒
		// - MaxUploadBufferPerConnection: 設置上傳緩衝區大小
		// - MaxUploadBufferPerStream: 設置每個流的上傳緩衝區

		// 从配置读取 HTTP/2 参数，使用默认值
		http2Config := cfg.Server.HTTP2Config
		maxConcurrentStreams := int64(250)
		maxReadFrameSize := int64(1048576) // 1MB
		idleTimeoutSec := 120
		maxUploadBufferPerConn := int64(8 << 20)   // 8MB
		maxUploadBufferPerStream := int64(1 << 20) // 1MB

		if http2Config != nil {
			if http2Config.MaxConcurrentStreams > 0 {
				maxConcurrentStreams = http2Config.MaxConcurrentStreams
			}
			if http2Config.MaxReadFrameSize > 0 {
				maxReadFrameSize = http2Config.MaxReadFrameSize
			}
			if http2Config.IdleTimeout > 0 {
				idleTimeoutSec = http2Config.IdleTimeout
			}
			if http2Config.MaxUploadBufferPerConnection > 0 {
				maxUploadBufferPerConn = http2Config.MaxUploadBufferPerConnection
			}
			if http2Config.MaxUploadBufferPerStream > 0 {
				maxUploadBufferPerStream = http2Config.MaxUploadBufferPerStream
			}
		}

		http2.ConfigureServer(httpsServer, &http2.Server{
			MaxConcurrentStreams:         uint32(maxConcurrentStreams),
			MaxReadFrameSize:             uint32(maxReadFrameSize),
			IdleTimeout:                  time.Duration(idleTimeoutSec) * time.Second,
			MaxUploadBufferPerConnection: int32(maxUploadBufferPerConn),
			MaxUploadBufferPerStream:     int32(maxUploadBufferPerStream),
		})

		go func() {
			http2Status := "disabled"
			if cfg.Server.HTTP2Enabled {
				http2Status = "enabled"
			}
			logrus.Infof("HTTPS server listening on %s:443 (HTTP/2 %s, multi-domain SSL supported)", cfg.Server.Host, http2Status)
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				// HTTP/2 服务器启动失败不应导致整个程序退出，记录错误但继续运行
				logrus.Errorf("HTTPS server (HTTP/2) error: %v", err)
				logrus.Warn("HTTPS server failed, but continuing with other servers...")
			}
		}()
	}

	// 启动 HTTP/3 服务器 (UDP:443)
	if cfg.Server.EnableHTTPS && cfg.Server.HTTP3Enabled {
		http3Server := web.NewHTTP3Server(cfg, webServer, sslManager)
		if err := http3Server.Start(); err != nil {
			logrus.Errorf("Failed to start HTTP/3 server: %v", err)
			// HTTP/3 启动失败不应导致整个程序退出，继续运行 HTTP/1.1 和 HTTP/2
		} else {
			manager.http3Server = http3Server
		}
	}

	// 启动 HTTP 重定向服务器 (80)
	redirectServer := &http.Server{
		Addr:     fmt.Sprintf("%s:80", cfg.Server.Host),
		ErrorLog: log.New(filteredLog, "", 0), // 使用过滤的 ErrorLog
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

				// 管理面板路径：不强制重定向到HTTPS，允许HTTP访问
				// 这样可以支持内网环境或特殊场景下的HTTP访问
				// 如果用户需要HTTPS，可以通过浏览器直接访问HTTPS地址
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
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		ReadHeaderTimeout: 10 * time.Second, // 读取 header 超时，防止慢速攻击
		MaxHeaderBytes:    1 << 20,          // 限制请求头最大 1MB，防止内存攻击
		IdleTimeout:       90 * time.Second, // 空闲连接超时
	}

	manager.redirectServer = redirectServer
	go func() {
		logrus.Infof("HTTP redirect server listening on %s:80", cfg.Server.Host)
		if err := redirectServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// HTTP 重定向服务器启动失败不应导致整个程序退出
			logrus.Errorf("HTTP redirect server error: %v", err)
			logrus.Warn("HTTP redirect server failed, but continuing with other servers...")
		}
	}()

	return manager
}

// startCustomMode 启动自定义模式（监听单个端口）
func startCustomMode(cfg *config.Config, webServer http.Handler, readTimeout, writeTimeout, idleTimeout time.Duration) {
	// 创建过滤的 ErrorLog
	filteredLog := newFilteredErrorLog()

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.CustomPort),
		Handler:           webServer,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		ReadHeaderTimeout: 10 * time.Second, // 读取 header 超时，防止慢速攻击
		MaxHeaderBytes:    1 << 20,          // 限制请求头最大 1MB，防止内存攻击
		IdleTimeout:       idleTimeout,
		ErrorLog:          log.New(filteredLog, "", 0), // 使用过滤的 ErrorLog
	}

	go func() {
		logrus.Infof("HTTP server listening on %s (custom port mode)", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("failed to start HTTP server: %v", err)
		}
	}()
}

// handlePprofCommands 处理 pprof 相关命令
func handlePprofCommands(configFile *string, pprofEnable, pprofDisable *bool, pprofExport, pprofOutput, pprofServer *string) {
	// 加载配置
	cfg, err := config.Load(*configFile)
	if err != nil {
		fmt.Printf("❌ 加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	// 启用 pprof
	if *pprofEnable {
		cfg.Server.EnablePprof = true
		if err := saveConfig(cfg, *configFile); err != nil {
			fmt.Printf("❌ 保存配置失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ pprof 性能分析端点已启用")
		fmt.Println("   访问地址: http://localhost:8080/debug/pprof/")
		fmt.Println("   注意: 需要重启 sslcat 服务使配置生效")
		return
	}

	// 禁用 pprof
	if *pprofDisable {
		cfg.Server.EnablePprof = false
		if err := saveConfig(cfg, *configFile); err != nil {
			fmt.Printf("❌ 保存配置失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ pprof 性能分析端点已禁用")
		fmt.Println("   注意: 需要重启 sslcat 服务使配置生效")
		return
	}

	// 导出 pprof 数据
	if *pprofExport != "" {
		exportPprofData(*pprofExport, *pprofOutput, *pprofServer)
		return
	}
}

// saveConfig 保存配置到文件
func saveConfig(cfg *config.Config, configFile string) error {
	// 使用 Config.Save 方法，它会自动只保存与默认值不同的配置
	return cfg.Save(configFile)
}

// exportPprofData 导出 pprof 数据
func exportPprofData(profileType, outputPath, serverURL string) {
	// 验证 profile 类型
	validTypes := map[string]bool{
		"heap":      true,
		"cpu":       true,
		"goroutine": true,
		"allocs":    true,
		"block":     true,
		"mutex":     true,
	}
	if !validTypes[profileType] {
		fmt.Printf("❌ 无效的 profile 类型: %s\n", profileType)
		fmt.Println("   支持的类型: heap, cpu, goroutine, allocs, block, mutex")
		os.Exit(1)
	}

	// 生成输出文件名
	if outputPath == "" {
		timestamp := time.Now().Format("20060102-150405")
		outputPath = fmt.Sprintf("./sslcat-%s-%s.pprof", profileType, timestamp)
	}

	// 构建 URL
	url := fmt.Sprintf("%s/debug/pprof/%s", serverURL, profileType)

	fmt.Printf("📊 正在导出 %s profile 数据...\n", profileType)
	fmt.Printf("   服务器: %s\n", url)
	fmt.Printf("   输出文件: %s\n", outputPath)

	// 下载数据
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("❌ 连接服务器失败: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("❌ 服务器返回错误: %s\n", resp.Status)
		os.Exit(1)
	}

	// 保存文件
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("❌ 读取数据失败: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		fmt.Printf("❌ 保存文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ %s profile 数据已导出到: %s\n", profileType, outputPath)
	fmt.Printf("   文件大小: %d bytes\n", len(data))

	// 提供分析建议
	switch profileType {
	case "heap":
		fmt.Println("💡 使用 go tool pprof 分析内存使用:")
		fmt.Printf("   go tool pprof %s\n", outputPath)
	case "cpu":
		fmt.Println("💡 使用 go tool pprof 分析 CPU 使用:")
		fmt.Printf("   go tool pprof %s\n", outputPath)
	case "goroutine":
		fmt.Println("💡 使用 go tool pprof 分析 goroutine:")
		fmt.Printf("   go tool pprof %s\n", outputPath)
	}
}

// startMemoryMonitor 启动内存监控
func startMemoryMonitor(cdnCache *cache.CDNCache, proxyManager *proxy.Manager) {
	go func() {
		// 使用质数间隔避免与其他定时器同时触发（5分钟 = 301秒）
		ticker := time.NewTicker(301 * time.Second)
		defer ticker.Stop()

		logrus.Info("内存监控已启动，每5分钟输出一次统计信息")

		for range ticker.C {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			goroutines := runtime.NumGoroutine()

			// 基本内存统计
			allocMB := m.Alloc / 1024 / 1024
			sysMB := m.Sys / 1024 / 1024
			numGC := m.NumGC

			// 获取 CDN Cache processing map 大小
			processingMapSize := 0
			if cdnCache != nil {
				processingMapSize = cdnCache.GetProcessingMapSize()
			}

			// 正常日志
			logrus.Infof("📊 内存统计: Alloc=%dMB, Sys=%dMB, NumGC=%d, Goroutines=%d, CDN_Processing=%d",
				allocMB, sysMB, numGC, goroutines, processingMapSize)

			// 异常检测和告警
			warnings := []string{}

			// Goroutine 数量检查
			if goroutines > 10000 {
				warnings = append(warnings, fmt.Sprintf("Goroutine 数量异常高: %d (严重)", goroutines))
			} else if goroutines > 5000 {
				warnings = append(warnings, fmt.Sprintf("Goroutine 数量较高: %d (警告)", goroutines))
			}

			// 内存使用检查
			if allocMB > 2000 {
				warnings = append(warnings, fmt.Sprintf("内存使用异常高: %dMB (严重)", allocMB))
			} else if allocMB > 1000 {
				warnings = append(warnings, fmt.Sprintf("内存使用较高: %dMB (警告)", allocMB))
			}

			// CDN processing map 检查
			if processingMapSize > 1000 {
				warnings = append(warnings, fmt.Sprintf("CDN processing map 异常大: %d 个条目 (严重)", processingMapSize))
			} else if processingMapSize > 100 {
				warnings = append(warnings, fmt.Sprintf("CDN processing map 较大: %d 个条目 (警告)", processingMapSize))
			}

			// 输出告警
			if len(warnings) > 0 {
				for _, warning := range warnings {
					logrus.Errorf("⚠️ 内存告警: %s", warning)
				}

				// 输出详细的 Goroutine 信息（仅在异常时）
				if goroutines > 5000 {
					logrus.Warnf("建议检查 Goroutine 泄漏，可以使用: curl http://localhost:6060/debug/pprof/goroutine?debug=2")
				}
			}
		}
	}()
}

// showHelp 显示帮助信息，包括所有子命令和启动参数
func showHelp() {
	fmt.Printf("SSLcat v%s (build: %s)\n", strings.TrimPrefix(version, "v"), build)
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  sslcat [选项]                  # 启动服务器")
	fmt.Println("  sslcat <命令> [子命令] [选项]  # 执行 CLI 命令")
	fmt.Println()
	fmt.Println("CLI 子命令:")
	fmt.Println()

	// 创建 CLI 管理器并注册所有命令以显示帮助
	cliManager := newCLIManager()
	cliManager.ShowHelp()

	fmt.Println("启动参数:")
	fmt.Println()
	fmt.Println("  基本参数:")
	fmt.Println("    -config <path>              配置文件路径（默认：/etc/sslcat/sslcat.conf）")
	fmt.Println("    -admin-prefix <path>        管理面板路径前缀（默认：/sslcat-panel）")
	fmt.Println("    -host <address>             监听地址（默认：0.0.0.0）")
	fmt.Println("    -port <port>                监听端口（默认：443）")
	fmt.Println("    -email <email>              SSL证书邮箱")
	fmt.Println("    -staging                    使用Let's Encrypt测试环境")
	fmt.Println("    -log-level <level>         日志级别：debug, info, warn, error（默认：info）")
	fmt.Println()
	fmt.Println("  配置验证:")
	fmt.Println("    -test                       测试配置文件语法和完整性")
	fmt.Println("    -check                      检查配置文件并显示详细信息")
	fmt.Println("    -version                    显示版本信息")
	fmt.Println()
	fmt.Println("  性能分析 (pprof):")
	fmt.Println("    -pprof-enable               启用 pprof 性能分析端点")
	fmt.Println("    -pprof-disable               禁用 pprof 性能分析端点")
	fmt.Println("    -pprof-export <type>        导出 pprof 数据 (heap|cpu|goroutine|allocs|block|mutex)")
	fmt.Println("    -pprof-output <path>        导出文件路径")
	fmt.Println("    -pprof-server <url>         pprof 服务器地址（默认：http://localhost:8080）")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  sslcat -h                     显示此帮助信息")
	fmt.Println("  sslcat help                   显示 CLI 命令帮助")
	fmt.Println("  sslcat console                启动交互式 Terminal UI 控制台")
	fmt.Println("  sslcat config show            显示完整配置")
	fmt.Println("  sslcat status --json          输出当前配置摘要（JSON）")
	fmt.Println("  sslcat doctor                 执行本地诊断")
	fmt.Println("  sslcat site list              列出静态/PHP 站点")
	fmt.Println("  sslcat proxy list              列出所有代理规则")
	fmt.Println("  sslcat proxy health-check --domain example.com")
	fmt.Println("  sslcat ssl list               列出所有 SSL 证书")
	fmt.Println("  sslcat renew   同上；未写 -config 时若存在 /etc/sslcat/sslcat.conf 会自动使用")
	fmt.Println("  sslcat renew -config /etc/sslcat/sslcat.conf   批量续期已过期或 3 天内过期的证书")
	fmt.Println("  sslcat ssl renew --all -config /etc/sslcat/sslcat.conf  同上（ssl 子命令）")
	fmt.Println("  sslcat ssl renew -domain a.com -config /etc/sslcat/sslcat.conf  续期单个域名")
	fmt.Println("  sslcat -config ./sslcat.conf  使用自定义配置文件启动")
	fmt.Println()
}
