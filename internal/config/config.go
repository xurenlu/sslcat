package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Config 应用配置结构
type Config struct {
	Server       ServerConfig   `json:"server"`
	SSL          SSLConfig      `json:"ssl"`
	Admin        AdminConfig    `json:"admin"`
	Proxy        ProxyConfig    `json:"proxy"`
	Security     SecurityConfig `json:"security"`
	CDNCache     CDNCacheConfig `json:"cdn_cache"`
	AdminPrefix  string         `json:"admin_prefix"`
	BotAPIPrefix string         `json:"bot_api_prefix"` // 机器人检测 API 前缀（随机生成）
	ConfigFile   string         `json:"-"`              // 配置文件路径，不序列化

	// 压缩配置
	Compression CompressionConfig `json:"compression"`
	// 集群配置
	Cluster ClusterConfig `json:"cluster"`
	// 静态站点
	StaticSites []StaticSite `json:"static_sites"`
	// PHP 站点
	PHPSites []PHPSite `json:"php_sites"`
	// Runner 配置
	Runners RunnerConfig `json:"runners"`
	// 威胁情报配置
	ThreatIntel ThreatIntelConfig `json:"threat_intel"`
	// 通知配置
	Notification NotificationConfig `json:"notification"`
	// 上游缓存配置
	UpstreamCache UpstreamCacheConfig `json:"upstream_cache"`
	// AI 安全分析配置
	AISecurity AISecurityConfig `json:"ai_security"`
	// 图片优化配置
	ImageOptimization ImageOptimizationConfig `json:"image_optimization"`
	// 监控配置
	Monitoring MonitoringConfig `json:"monitoring"`
	// 缓存预热配置
	CacheWarmup CacheWarmupConfig `json:"cache_warmup"`
	// 报告生成配置
	Report ReportConfig `json:"report"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"` // 向后兼容，保留原字段
	Debug       bool   `json:"debug"`
	LogLevel    string `json:"log_level"`    // debug|info|warn|error
	EnablePprof bool   `json:"enable_pprof"` // 是否启用 pprof 性能分析端点

	// 新的端口配置
	PortMode    string `json:"port_mode"`    // "standard" | "custom" (默认 "standard")
	CustomPort  int    `json:"custom_port"`  // 自定义端口（仅在 custom 模式生效）
	EnableHTTPS bool   `json:"enable_https"` // 是否启用 HTTPS（默认 true）

	// HTTP/2 配置
	HTTP2Enabled bool `json:"http2_enabled"` // 是否启用 HTTP/2（默认 false）

	// HTTP/3 配置
	HTTP3Enabled bool         `json:"http3_enabled"` // 是否启用 HTTP/3（默认 false）
	HTTP3Config  *HTTP3Config `json:"http3_config,omitempty"`

	// 访问日志
	AccessLogEnabled  bool   `json:"access_log_enabled"`
	AccessLogFormat   string `json:"access_log_format"` // nginx|apache|json
	AccessLogPath     string `json:"access_log_path"`
	AccessLogMaxSize  int64  `json:"access_log_max_size"` // bytes
	AccessLogMaxFiles int    `json:"access_log_max_files"`

	// 共享内存缓存
	SharedCacheMaxSizeMB int    `json:"shared_cache_max_size_mb"` // 共享缓存最大容量（MB）
	CacheBackendType     string `json:"cache_backend_type"`       // 缓存后端类型：bigcache/simple/auto（默认simple）

	// 客户端连接超时（秒）
	ReadTimeoutSec  int `json:"read_timeout_sec"`
	WriteTimeoutSec int `json:"write_timeout_sec"`
	IdleTimeoutSec  int `json:"idle_timeout_sec"`
	// 最大上传大小（字节），用于限制 multipart 上传体积
	MaxUploadBytes int64 `json:"max_upload_bytes"`

	// Session 存储配置
	SessionStorage string `json:"session_storage"` // memory|file (默认 file)
	DataDir        string `json:"data_dir"`        // 数据目录（用于文件存储）

	// 安全密钥（用于 Token 签名等）
	SecretKey string `json:"secret_key"`
}

// SSLConfig SSL证书配置
type SSLConfig struct {
	Email             string   `json:"email"`
	Staging           bool     `json:"staging"`
	Domains           []string `json:"domains"`
	CertDir           string   `json:"cert_dir"`
	KeyDir            string   `json:"key_dir"`
	AutoRenew         bool     `json:"auto_renew"`
	DisableSelfSigned bool     `json:"disable_self_signed"`

	// DNS验证配置
	DNSProviders       []DNSProvider `json:"dns_providers"`
	DefaultDNSProvider string        `json:"default_dns_provider"`
	ChallengeMethods   []string      `json:"challenge_methods"` // ["http-01", "dns-01"]

	// TLS Session Resumption 配置
	SessionResumption *SessionResumptionConfig `json:"session_resumption,omitempty"`
}

// SessionResumptionConfig TLS Session Resumption 配置
// 默認開啟：未配置此塊或 enabled 未設為 false 時均啟用
type SessionResumptionConfig struct {
	Enabled                   bool   `json:"enabled"`                      // 是否啟用（默認 true，僅設為 false 時關閉）
	Mode                      string `json:"mode"`                         // "id" | "ticket" | "both" (默認 "both")
	CacheSize                 int    `json:"cache_size"`                   // Session ID 緩存大小（默認 1000）
	TicketLifetime            int    `json:"ticket_lifetime"`              // Session Ticket 有效期（秒，默認 3600）
	TicketKeyRotationInterval int    `json:"ticket_key_rotation_interval"` // Session Ticket 密鑰輪換間隔（秒，默認 86400）
}

// HTTP3Config HTTP/3 配置
type HTTP3Config struct {
	Enabled               bool   `json:"enabled"`
	MaxIdleTimeout        string `json:"max_idle_timeout"`         // 默认 "120s"
	MaxIncomingStreams    int64  `json:"max_incoming_streams"`     // 默认 1000
	MaxIncomingUniStreams int64  `json:"max_incoming_uni_streams"` // 默认 1000
}

// DNSProvider DNS服务商配置
type DNSProvider struct {
	Name      string `json:"name"`       // 服务商名称
	Type      string `json:"type"`       // cloudflare/aliyun/tencent/aws/godaddy/custom
	Enabled   bool   `json:"enabled"`    // 是否启用
	APIKey    string `json:"api_key"`    // API密钥
	APISecret string `json:"api_secret"` // API密钥(部分服务商需要)
	ZoneID    string `json:"zone_id"`    // 域名区域ID
	Endpoint  string `json:"endpoint"`   // 自定义API端点
	Priority  int    `json:"priority"`   // 优先级，数字越小优先级越高
}

// AdminConfig 管理面板配置
type AdminConfig struct {
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	FirstRun     bool   `json:"first_run"`
	PasswordFile string `json:"password_file"`
	// TOTP 二次验证
	EnableTOTP     bool   `json:"enable_totp"`
	TOTPSecret     string `json:"totp_secret,omitempty"`
	TOTPSecretFile string `json:"totp_secret_file"`
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Rules []ProxyRule `json:"rules"`
	// 未命中代理规则时的行为: "404" | "302" | "blank" | "502"
	UnmatchedBehavior string `json:"unmatched_behavior"`
	// 当 UnmatchedBehavior=="302" 时的跳转URL
	UnmatchedRedirectURL string `json:"unmatched_redirect_url"`
	// 全局默认：等待后端响应头超时（秒），单条规则未设置时使用，默认 3
	DefaultResponseHeaderTimeoutSec int `json:"default_response_header_timeout_sec"`
}

// ProxyRule 代理规则
type ProxyRule struct {
	Domain  string `json:"domain"`
	Target  string `json:"target,omitempty"` // 旧字段：单后端目标（兼容保留）
	Port    int    `json:"port,omitempty"`   // 旧字段：单后端端口（兼容保留）
	Enabled bool   `json:"enabled"`
	SSLOnly bool   `json:"ssl_only"`

	// 路径前缀匹配配置
	PathPrefixes []string `json:"path_prefixes,omitempty"` // 路径前缀列表，如 ["/api/v1/", "/api/v2/"]
	PathExact    bool     `json:"path_exact"`              // 是否精确匹配路径前缀

	// 路径前缀规则配置（支持多组配置）
	PathPrefixRules []PathPrefixRule `json:"path_prefix_rules,omitempty"` // 路径前缀规则列表

	// 新字段：统一后端配置
	Backends []ProxyBackend `json:"backends,omitempty"` // 统一后端服务器列表

	// 保留字段：负载均衡配置（向后兼容）
	LoadBalancerEnabled   bool           `json:"load_balancer_enabled,omitempty"`   // 是否启用负载均衡（兼容保留）
	LoadBalancerAlgorithm string         `json:"load_balancer_algorithm,omitempty"` // 负载均衡算法（兼容保留）
	LoadBalancerBackends  []ProxyBackend `json:"load_balancer_backends,omitempty"`  // 后端服务器列表（兼容保留）

	// 会话保持配置
	SessionAffinityEnabled bool   `json:"session_affinity_enabled"` // 是否启用会话保持
	SessionAffinityMethod  string `json:"session_affinity_method"`  // 会话保持方法: cookie, header, ip
	SessionAffinityCookie  string `json:"session_affinity_cookie"`  // Cookie名称
	SessionAffinityHeader  string `json:"session_affinity_header"`  // Header名称
	SessionAffinityTTL     int    `json:"session_affinity_ttl"`     // 会话保持时间（秒）

	// 上游调试（多后端时生效）：在响应头中输出当前服务的上游机器、会话保持状态等
	UpstreamDebugHeaders bool `json:"upstream_debug_headers"` // 是否输出上游调试 header，默认关闭

	// 性能监控配置
	EnableTracing bool `json:"enable_tracing,omitempty"` // 是否启用请求追踪（会影响性能）
	EnableMetrics bool `json:"enable_metrics,omitempty"` // 是否启用指标收集（会影响性能）

	// 健康检查配置
	HealthCheckEnabled  bool   `json:"health_check_enabled"`  // 是否启用健康检查
	HealthCheckPath     string `json:"health_check_path"`     // 健康检查路径
	HealthCheckInterval int    `json:"health_check_interval"` // 健康检查间隔（秒）
	HealthCheckTimeout  int    `json:"health_check_timeout"`  // 健康检查超时（秒）
	HealthCheckMethod   string `json:"health_check_method"`   // 健康检查HTTP方法
	ExpectedStatusCode  int    `json:"expected_status_code"`  // 期望的状态码

	// 故障转移配置
	FailoverEnabled   bool `json:"failover_enabled"`   // 是否启用故障转移
	MaxRetries        int  `json:"max_retries"`        // 最大重试次数
	RetryInterval     int  `json:"retry_interval"`     // 重试间隔（秒）
	FailureThreshold  int  `json:"failure_threshold"`  // 故障阈值
	RecoveryThreshold int  `json:"recovery_threshold"` // 恢复阈值
	// HTTP Host头部优化设置
	OptimizeHostHeader bool `json:"optimize_host_header"`
	// 每域名的类CDN设置
	CDNEnabled           bool   `json:"cdn_enabled"`
	CDNPreset            string `json:"cdn_preset"`      // none|static|images|cloud_storage
	CDNDefaultTTLSeconds int    `json:"cdn_ttl_seconds"` // 0 表示使用全局规则

	// 云存储后端配置
	CloudStorageType      string `json:"cloud_storage_type"`       // aliyun_oss|aws_s3|tencent_cos|auto
	CloudStorageRegion    string `json:"cloud_storage_region"`     // 云存储区域
	CloudStorageBucket    string `json:"cloud_storage_bucket"`     // 存储桶名称
	CloudStorageEndpoint  string `json:"cloud_storage_endpoint"`   // 自定义端点
	CloudStoragePath      string `json:"cloud_storage_path"`       // 存储路径前缀
	CloudStorageAccessKey string `json:"cloud_storage_access_key"` // 访问密钥
	CloudStorageSecretKey string `json:"cloud_storage_secret_key"` // 秘密密钥

	// 访问控制设置
	AuthEnabled        bool            `json:"auth_enabled"`         // 是否开启访问控制
	AuthUsers          []ProxyAuthUser `json:"auth_users,omitempty"` // 用户密码列表
	AuthSessionTimeout int             `json:"auth_session_timeout"` // 登录有效期（秒），默认3600
	AuthCookieDomain   string          `json:"auth_cookie_domain"`   // Cookie作用域，默认为代理域名

	// 代理超时配置
	ConnectTimeoutSec        int `json:"connect_timeout_sec"`         // 连接超时（秒），默认30
	KeepAliveTimeoutSec      int `json:"keep_alive_timeout_sec"`      // 连接保持超时（秒），默认30
	IdleTimeoutSec           int `json:"idle_timeout_sec"`            // 空闲连接超时（秒），默认90
	TLSHandshakeTimeoutSec   int `json:"tls_handshake_timeout_sec"`   // TLS握手超时（秒），默认10
	ExpectContinueTimeoutSec int `json:"expect_continue_timeout_sec"` // Expect-Continue超时（秒），默认1
	ResponseHeaderTimeoutSec int `json:"response_header_timeout_sec"` // 响应头超时（秒），默认3
	HealthCheckTimeoutSec    int `json:"health_check_timeout_sec"`    // 健康检查超时（秒），默认5

	// WebSocket代理优化配置
	WebSocketOptimized bool `json:"websocket_optimized"` // 是否启用WebSocket优化，默认true

	// WAF 配置（按域名）
	WAFEnabled            *bool `json:"waf_enabled,omitempty"`   // 是否启用WAF，nil表示使用全局配置
	WebSocketBufferSize   int   `json:"websocket_buffer_size"`   // WebSocket缓冲区大小，默认100
	WebSocketReadTimeout  int   `json:"websocket_read_timeout"`  // WebSocket读取超时（秒），默认30
	WebSocketWriteTimeout int   `json:"websocket_write_timeout"` // WebSocket写入超时（秒），默认10
	WebSocketPingInterval int   `json:"websocket_ping_interval"` // WebSocket心跳间隔（秒），默认30
	WebSocketTimeout      int   `json:"websocket_timeout"`       // WebSocket连接总超时（秒），默认1800

	// 自定义头部配置
	UpstreamRequestHeaders map[string]string `json:"upstream_request_headers,omitempty"`
	ResponseHeaders        map[string]string `json:"response_headers,omitempty"`

	// Git部署服务标记
	ManagedByGitDeploy bool   `json:"managed_by_git_deploy"` // 是否由Git部署服务管理
	GitDeployAppName   string `json:"git_deploy_app_name"`   // 关联的Git应用名称
	GitDeployAppID     string `json:"git_deploy_app_id"`     // 关联的Git应用ID

	// 机器人检测配置
	BotDetectionEnabled bool                `json:"bot_detection_enabled"`          // 是否启用机器人检测
	BotDetectionConfig  *BotDetectionConfig `json:"bot_detection_config,omitempty"` // 机器人检测配置

	// 访问日志覆盖（nil 表示使用全局设置）
	AccessLogEnabled *bool  `json:"access_log_enabled,omitempty"` // 是否记录访问日志，nil=继承全局
	AccessLogPath    string `json:"access_log_path,omitempty"`    // 覆盖日志路径，空=使用全局

	// HTTP/2 覆盖（nil 表示使用全局设置）
	HTTP2Enabled *bool `json:"http2_enabled,omitempty"` // 是否启用 HTTP/2，nil=继承全局
	// HTTP/3 覆盖（nil 表示使用全局设置）
	HTTP3Enabled *bool `json:"http3_enabled,omitempty"` // 是否启用 HTTP/3，nil=继承全局
}

// PathPrefixRule 路径前缀规则
type PathPrefixRule struct {
	// 路径前缀配置
	Prefixes []string `json:"prefixes"` // 路径前缀列表，如 ["/api/v1/", "/api/v2/"]
	Exact    bool     `json:"exact"`    // 是否精确匹配路径前缀

	// 后端服务器配置
	Backends []ProxyBackend `json:"backends"` // 该规则对应的后端服务器列表

	// 负载均衡配置
	LoadBalancerAlgorithm string `json:"load_balancer_algorithm,omitempty"` // 负载均衡算法

	// 会话保持配置
	SessionAffinityEnabled bool   `json:"session_affinity_enabled"` // 是否启用会话保持
	SessionAffinityMethod  string `json:"session_affinity_method"`  // 会话保持方法
	SessionAffinityCookie  string `json:"session_affinity_cookie"`  // Cookie名称
	SessionAffinityHeader  string `json:"session_affinity_header"`  // Header名称
	SessionAffinityTTL     int    `json:"session_affinity_ttl"`     // 会话保持时间（秒）

	// 健康检查配置
	HealthCheckEnabled  bool   `json:"health_check_enabled"`  // 是否启用健康检查
	HealthCheckPath     string `json:"health_check_path"`     // 健康检查路径
	HealthCheckInterval int    `json:"health_check_interval"` // 健康检查间隔（秒）
	HealthCheckTimeout  int    `json:"health_check_timeout"`  // 健康检查超时（秒）
	HealthCheckMethod   string `json:"health_check_method"`   // 健康检查HTTP方法
	ExpectedStatusCode  int    `json:"expected_status_code"`  // 期望的状态码

	// 故障转移配置
	FailoverEnabled   bool `json:"failover_enabled"`   // 是否启用故障转移
	MaxRetries        int  `json:"max_retries"`        // 最大重试次数
	RetryInterval     int  `json:"retry_interval"`     // 重试间隔（秒）
	FailureThreshold  int  `json:"failure_threshold"`  // 故障阈值
	RecoveryThreshold int  `json:"recovery_threshold"` // 恢复阈值

	// 规则名称和描述
	Name        string `json:"name,omitempty"`        // 规则名称
	Description string `json:"description,omitempty"` // 规则描述
	Enabled     bool   `json:"enabled"`               // 是否启用该规则

	// 性能监控配置
	EnableTracing bool `json:"enable_tracing,omitempty"` // 是否启用请求追踪（会影响性能）
	EnableMetrics bool `json:"enable_metrics,omitempty"` // 是否启用指标收集（会影响性能）
}

// ProxyBackend 代理后端服务器
type ProxyBackend struct {
	ID       string `json:"id"`       // 后端唯一标识
	Host     string `json:"host"`     // 主机地址
	Port     int    `json:"port"`     // 端口
	Weight   int    `json:"weight"`   // 权重，默认为1
	Priority int    `json:"priority"` // 优先级，数字越小优先级越高
	Enabled  bool   `json:"enabled"`  // 是否启用

	// 健康检查配置（可选，覆盖全局配置）
	HealthCheckEnabled  bool   `json:"health_check_enabled,omitempty"`  // 是否启用健康检查
	HealthCheckPath     string `json:"health_check_path,omitempty"`     // 健康检查路径
	HealthCheckInterval int    `json:"health_check_interval,omitempty"` // 检查间隔（秒）
	HealthCheckTimeout  int    `json:"health_check_timeout,omitempty"`  // 检查超时（秒）
	HealthCheckMethod   string `json:"health_check_method,omitempty"`   // 检查方法
	ExpectedStatusCode  int    `json:"expected_status_code,omitempty"`  // 期望的状态码

	// 连接配置
	MaxConnections   int `json:"max_connections,omitempty"`    // 最大连接数
	ConnectTimeout   int `json:"connect_timeout,omitempty"`    // 连接超时（秒）
	ReadTimeout      int `json:"read_timeout,omitempty"`       // 读取超时（秒）
	WriteTimeout     int `json:"write_timeout,omitempty"`      // 写入超时（秒）
	KeepAliveTimeout int `json:"keep_alive_timeout,omitempty"` // 长连接超时（秒）

	// SSL/TLS配置
	TLSEnabled    bool   `json:"tls_enabled,omitempty"`     // 是否启用TLS
	TLSInsecure   bool   `json:"tls_insecure,omitempty"`    // 是否跳过TLS验证
	TLSServerName string `json:"tls_server_name,omitempty"` // TLS服务器名称

	// 故障转移配置
	MaxRetries        int `json:"max_retries,omitempty"`        // 最大重试次数
	RetryInterval     int `json:"retry_interval,omitempty"`     // 重试间隔（秒）
	FailureThreshold  int `json:"failure_threshold,omitempty"`  // 故障阈值
	RecoveryThreshold int `json:"recovery_threshold,omitempty"` // 恢复阈值

	// 元数据
	Metadata map[string]string `json:"metadata,omitempty"` // 元数据，用于存储自定义信息
}

// ProxyAuthUser 代理访问控制用户
type ProxyAuthUser struct {
	Username string `json:"username"`
	Password string `json:"password"` // 明文存储（内部使用，不暴露给前端）
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	MaxAttempts       int      `json:"max_attempts"`
	BlockDurationStr  string   `json:"block_duration"`
	MaxAttempts5Min   int      `json:"max_attempts_5min"`
	BlockFile         string   `json:"block_file"`
	AllowedUserAgents []string `json:"allowed_user_agents"`

	// IP访问控制
	IPWhitelist []string `json:"ip_whitelist"`
	IPBlacklist []string `json:"ip_blacklist"`

	// 地理位置过滤
	GeoBlocking GeoBlockingConfig `json:"geo_blocking"`

	// CORS配置
	CORS CORSConfig `json:"cors"`
	// 可疑 UA 计数阈值（达到后封禁）
	UAInvalidMax1Min int `json:"ua_invalid_max_1min"`
	UAInvalidMax5Min int `json:"ua_invalid_max_5min"`
	// TLS 指纹统计配置
	TLSFingerprintWindowSec int `json:"tls_fp_window_sec"`
	TLSFingerprintMaxPerMin int `json:"tls_fp_max_per_min"`
	TLSFingerprintTopN      int `json:"tls_fp_top_n"`

	// 安全功能开关
	EnableUAFilter bool `json:"enable_ua_filter"`
	EnableWAF      bool `json:"enable_waf"`
	EnableDDOS     bool `json:"enable_ddos"`

	// WAF 频率限制配置
	WAFRateLimitEnabled  bool `json:"waf_rate_limit_enabled"`   // 是否启用 WAF 频率限制
	WAFRateLimitWindow   int  `json:"waf_rate_limit_window"`    // 时间窗口（秒），默认 60
	WAFRateLimitMaxHits  int  `json:"waf_rate_limit_max_hits"`  // 时间窗口内最大触发次数，默认 10
	WAFRateLimitBlockSec int  `json:"waf_rate_limit_block_sec"` // 封禁时长（秒），默认 3600

	// TLS 指纹封禁配置
	WAFTLSBlockEnabled     bool `json:"waf_tls_block_enabled"`      // 是否启用 TLS 指纹封禁
	WAFTLSBlockWindow      int  `json:"waf_tls_block_window"`       // 时间窗口（秒），默认 60
	WAFTLSBlockMaxHits     int  `json:"waf_tls_block_max_hits"`     // 时间窗口内最大触发次数，默认 10
	WAFTLSBlockDurationSec int  `json:"waf_tls_block_duration_sec"` // 封禁时长（秒），默认 3600

	// IP 段封禁配置
	WAFSubnetBlockEnabled     bool `json:"waf_subnet_block_enabled"`      // 是否启用 IP 段封禁
	WAFSubnetMask             int  `json:"waf_subnet_mask"`               // 网段掩码，默认 24 (/24)
	WAFSubnetThreshold        int  `json:"waf_subnet_threshold"`          // 同段被封IP数量阈值，默认 3
	WAFSubnetBlockDurationSec int  `json:"waf_subnet_block_duration_sec"` // 封禁时长（秒），默认 7200

	// 人机验证配置
	EnableCaptcha bool `json:"enable_captcha"`
	MinFormMs     int  `json:"min_form_ms"`

	// 解析后的时间字段
	BlockDuration time.Duration `json:"-"`

	// 安全管理器内存泄漏防护
	MaxAccessLogEntries    int `json:"max_access_log_entries"`    // 每个IP的访问日志最多保留多少条，默认3000
	MaxBlockedIPs          int `json:"max_blocked_ips"`           // 最多保留多少个被封禁的IP，默认1000
	MaxAttemptCounts       int `json:"max_attempt_counts"`        // 最多保留多少个IP的尝试计数，默认1000
	MaxLastAttempts        int `json:"max_last_attempts"`         // 最多保留多少个IP的最后尝试时间，默认100
	UAInvalidMaxTotal      int `json:"u-invalid_max_total"`       // 最多保留多少个IP的UA违规记录，默认500
	TLSFingerprintMaxTotal int `json:"tls_fingerprint_max_total"` // 最多保留多少个TLS指纹计数，默认500
	CleanupIntervalMin     int `json:"cleanup_interval_min"`      // 清理间隔（分钟），默认5
}

// GeoBlockingConfig 地理位置过滤配置
type GeoBlockingConfig struct {
	// 是否启用地理位置过滤
	Enabled bool `json:"enabled"`

	// 允许的国家代码列表
	AllowedCountries []string `json:"allowed_countries"`

	// 阻止的国家代码列表
	BlockedCountries []string `json:"blocked_countries"`

	// GeoIP数据库路径
	DatabasePath string `json:"database_path"`

	// 数据库更新间隔（小时）
	UpdateInterval int `json:"update_interval"`

	// 是否允许未知国家
	AllowUnknown bool `json:"allow_unknown"`
}

// CORSConfig CORS配置
type CORSConfig struct {
	// 是否启用CORS
	Enabled bool `json:"enabled"`

	// 允许的源
	AllowedOrigins []string `json:"allowed_origins"`

	// 允许的方法
	AllowedMethods []string `json:"allowed_methods"`

	// 允许的头部
	AllowedHeaders []string `json:"allowed_headers"`

	// 暴露的头部
	ExposedHeaders []string `json:"exposed_headers"`

	// 是否允许凭证
	AllowCredentials bool `json:"allow_credentials"`

	// 预检请求缓存时间
	MaxAge int `json:"max_age"`

	// 是否允许私有网络
	AllowPrivateNetwork bool `json:"allow_private_network"`
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	// IP限流
	IPRateLimit IPRateLimitConfig `json:"ip_rate_limit"`

	// 用户限流
	UserRateLimit UserRateLimitConfig `json:"user_rate_limit"`

	// 路径限流
	PathRateLimit []PathRateLimitRule `json:"path_rate_limit"`

	// 方法限流
	MethodRateLimit map[string]int `json:"method_rate_limit"`

	// 全局限流
	GlobalRateLimit GlobalRateLimitConfig `json:"global_rate_limit"`
}

// IPRateLimitConfig IP限流配置
type IPRateLimitConfig struct {
	RequestsPerSecond int `json:"requests_per_second"`
	RequestsPerMinute int `json:"requests_per_minute"`
	RequestsPerHour   int `json:"requests_per_hour"`
	BurstSize         int `json:"burst_size"`
}

// UserRateLimitConfig 用户限流配置
type UserRateLimitConfig struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	RequestsPerHour   int `json:"requests_per_hour"`
}

// PathRateLimitRule 路径限流规则
type PathRateLimitRule struct {
	Path              string `json:"path"`
	Pattern           string `json:"pattern"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	BurstSize         int    `json:"burst_size"`
}

// GlobalRateLimitConfig 全局限流配置
type GlobalRateLimitConfig struct {
	RequestsPerSecond int `json:"requests_per_second"`
	RequestsPerMinute int `json:"requests_per_minute"`
}

// CDNCacheRule CDN 类缓存规则
type CDNCacheRule struct {
	// 匹配类型: prefix | suffix | media
	MatchType string `json:"match_type"`
	// 当 MatchType==media 时按 Content-Type 前缀匹配，如 image/, text/css
	MediaTypes []string `json:"media_types,omitempty"`
	// 当 MatchType==prefix/suffix 时按路径匹配
	Pattern string `json:"pattern,omitempty"`
	// 该规则命中的 TTL（秒）
	TTLSeconds int `json:"ttl_seconds"`
}

// CDNCacheConfig CDN 类缓存配置
type CDNCacheConfig struct {
	Enabled           bool           `json:"enabled"`
	CacheDir          string         `json:"cache_dir"`
	MaxSizeBytes      int64          `json:"max_size_bytes"`
	DefaultTTLSeconds int            `json:"default_ttl_seconds"`
	CleanIntervalSec  int            `json:"clean_interval_seconds"`
	MaxObjectBytes    int64          `json:"max_object_bytes"`
	Rules             []CDNCacheRule `json:"rules"`
}

// CompressionConfig 压缩配置
type CompressionConfig struct {
	// 是否启用压缩
	Enabled bool `json:"enabled"`

	// 支持的压缩算法，按优先级排序
	Algorithms []string `json:"algorithms"`

	// 最小压缩文件大小（字节）
	MinSize int64 `json:"min_size"`

	// 压缩级别配置
	Level CompressionLevelConfig `json:"level"`

	// 可压缩的文件类型
	Types []string `json:"types"`

	// 不压缩的文件类型
	ExcludedTypes []string `json:"excluded_types"`

	// 可压缩的Content-Type
	ContentTypes []string `json:"content_types"`
}

// CompressionLevelConfig 压缩级别配置
type CompressionLevelConfig struct {
	// Gzip压缩级别 (1-9, -1=默认, -2=最快, -3=最佳)
	Gzip int `json:"gzip"`

	// Brotli压缩级别 (0-11)
	Brotli int `json:"brotli"`
}

// ClusterConfig 集群配置
type ClusterConfig struct {
	// 集群模式: "master", "slave", "standalone"
	Mode string `json:"mode"`

	// 节点ID（自动生成）
	NodeID string `json:"node_id"`

	// 节点名称
	NodeName string `json:"node_name"`

	// Master配置（当模式为slave时使用）
	Master MasterConfig `json:"master"`

	// 同步配置
	Sync SyncConfig `json:"sync"`

	// 集群通信端口
	Port int `json:"port"`

	// 集群通信密钥
	AuthKey string `json:"auth_key"`
}

// MasterConfig Master节点配置
type MasterConfig struct {
	// Master节点地址
	Host string `json:"host"`

	// Master节点端口
	Port int `json:"port"`

	// 认证密钥
	AuthKey string `json:"auth_key"`

	// 连接超时时间（秒）
	Timeout int `json:"timeout"`

	// 重连间隔（秒）
	RetryInterval int `json:"retry_interval"`
}

// SyncConfig 同步配置
type SyncConfig struct {
	// 是否启用配置同步
	ConfigEnabled bool `json:"config_enabled"`

	// 是否启用证书同步
	CertEnabled bool `json:"cert_enabled"`

	// 同步间隔（秒）
	Interval int `json:"interval"`

	// 同步超时时间（秒）
	Timeout int `json:"timeout"`

	// 排除的配置项
	ExcludeConfigs []string `json:"exclude_configs"`
}

// StaticSite 静态站点配置
type StaticSite struct {
	Domain  string `json:"domain"`
	Root    string `json:"root"`
	Index   string `json:"index"`
	Enabled bool   `json:"enabled"`

	// 路径前缀匹配配置
	PathPrefixes []string `json:"path_prefixes,omitempty"` // 路径前缀列表，如 ["/api/v1/", "/api/v2/"]
	PathExact    bool     `json:"path_exact"`              // 是否精确匹配路径前缀

	// 路径前缀规则配置（支持多组配置）
	PathPrefixRules []PathPrefixRule `json:"path_prefix_rules,omitempty"` // 路径前缀规则列表

	// 自定义响应头
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`

	// 访问日志覆盖（仅 AccessLogEnabled 有值时生效，空路径表示使用全局）
	AccessLogEnabled *bool  `json:"access_log_enabled,omitempty"`
	AccessLogPath    string `json:"access_log_path,omitempty"`

	// HTTP/2 覆盖（nil 表示使用全局设置）
	HTTP2Enabled *bool `json:"http2_enabled,omitempty"`
	// HTTP/3 覆盖（nil 表示使用全局设置）
	HTTP3Enabled *bool `json:"http3_enabled,omitempty"`
}

// BotDetectionConfig 机器人检测配置
type BotDetectionConfig struct {
	// 检测模式: "monitor"(仅记录) | "challenge"(验证)
	Mode string `json:"mode"`

	// 风险阈值
	LowRiskThreshold    int `json:"low_risk_threshold"`
	MediumRiskThreshold int `json:"medium_risk_threshold"`
	HighRiskThreshold   int `json:"high_risk_threshold"`

	// 频率限制
	MaxRequestsPerMinute int `json:"max_requests_per_minute"`
	MaxRequestsPerHour   int `json:"max_requests_per_hour"`

	// 白名单有效期(小时)
	WhitelistDuration int `json:"whitelist_duration"`

	// Token 有效期(小时)
	TokenDuration int `json:"token_duration"`

	// 跳过验证的路径
	SkipPaths []string `json:"skip_paths"`
}

// PHPSite PHP 站点配置
type PHPSite struct {
	Domain   string            `json:"domain"`
	Root     string            `json:"root"`
	Index    string            `json:"index"`
	Enabled  bool              `json:"enabled"`
	FCGIAddr string            `json:"fcgi_addr"` // unix:/path/php-fpm.sock 或 127.0.0.1:9000
	Vars     map[string]string `json:"vars"`

	// 路径前缀匹配配置
	PathPrefixes []string `json:"path_prefixes,omitempty"` // 路径前缀列表，如 ["/api/v1/", "/api/v2/"]
	PathExact    bool     `json:"path_exact"`              // 是否精确匹配路径前缀

	// 路径前缀规则配置（支持多组配置）
	PathPrefixRules []PathPrefixRule `json:"path_prefix_rules,omitempty"` // 路径前缀规则列表

	// 自定义响应头
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`

	// 新增优化配置
	OptimizationConfig *PHPOptimizationConfig `json:"optimization_config,omitempty"`

	// 安全配置
	SecurityConfig *PHPSecurityConfig `json:"security_config,omitempty"`

	// 监控配置
	MonitoringConfig *PHPMonitoringConfig `json:"monitoring_config,omitempty"`

	// 访问日志覆盖（仅 AccessLogEnabled 有值时生效，空路径表示使用全局）
	AccessLogEnabled *bool  `json:"access_log_enabled,omitempty"`
	AccessLogPath    string `json:"access_log_path,omitempty"`

	// HTTP/2 覆盖（nil 表示使用全局设置）
	HTTP2Enabled *bool `json:"http2_enabled,omitempty"`
	// HTTP/3 覆盖（nil 表示使用全局设置）
	HTTP3Enabled *bool `json:"http3_enabled,omitempty"`
}

// PHPOptimizationConfig PHP 优化配置
type PHPOptimizationConfig struct {
	// OPcache 配置
	OPcacheEnabled            bool `json:"opcache_enabled"`
	OPcacheMemorySize         int  `json:"opcache_memory_size"` // MB
	OPcacheMaxFiles           int  `json:"opcache_max_files"`
	OPcacheValidateTimestamps bool `json:"opcache_validate_timestamps"`

	// 性能优化
	EnableGzipCompression bool `json:"enable_gzip_compression"`
	EnableStaticCaching   bool `json:"enable_static_caching"`
	CacheTTL              int  `json:"cache_ttl"` // 秒

	// 安全优化
	HidePHPVersion            bool `json:"hide_php_version"`
	DisableDangerousFunctions bool `json:"disable_dangerous_functions"`

	// 框架特定优化
	LaravelOptimizations bool `json:"laravel_optimizations"`
	SymfonyOptimizations bool `json:"symfony_optimizations"`
}

// PHPSecurityConfig PHP 安全配置
type PHPSecurityConfig struct {
	// 文件上传安全
	MaxUploadSize     int64    `json:"max_upload_size"`    // 字节
	AllowedExtensions []string `json:"allowed_extensions"` // 允许的文件扩展名
	BlockedExtensions []string `json:"blocked_extensions"` // 禁止的文件扩展名

	// 路径安全
	DisablePathTraversal bool     `json:"disable_path_traversal"`
	AllowedPaths         []string `json:"allowed_paths"` // 允许访问的路径

	// 执行安全
	DisableEval      bool     `json:"disable_eval"`
	DisableShellExec bool     `json:"disable_shell_exec"`
	AllowedFunctions []string `json:"allowed_functions"` // 允许的函数

	// 会话安全
	SessionSecure   bool   `json:"session_secure"`
	SessionHttpOnly bool   `json:"session_http_only"`
	SessionSameSite string `json:"session_same_site"` // Strict|Lax|None
}

// PHPMonitoringConfig PHP 监控配置
type PHPMonitoringConfig struct {
	// 性能监控
	EnablePerformanceMonitoring bool `json:"enable_performance_monitoring"`
	PerformanceThreshold        int  `json:"performance_threshold"` // 毫秒

	// 错误监控
	EnableErrorMonitoring bool `json:"enable_error_monitoring"`
	ErrorReportingLevel   int  `json:"error_reporting_level"`
	LogSlowQueries        bool `json:"log_slow_queries"`
	SlowQueryThreshold    int  `json:"slow_query_threshold"` // 毫秒

	// 资源监控
	EnableResourceMonitoring bool `json:"enable_resource_monitoring"`
	MemoryLimit              int  `json:"memory_limit"`  // MB
	CPUThreshold             int  `json:"cpu_threshold"` // 百分比

	// 日志配置
	LogLevel    string `json:"log_level"` // debug|info|warn|error
	LogFile     string `json:"log_file"`
	LogMaxSize  int64  `json:"log_max_size"` // 字节
	LogMaxFiles int    `json:"log_max_files"`
}

// ThreatIntelConfig 威胁情报配置
type ThreatIntelConfig struct {
	// 是否启用威胁情报
	Enabled bool `json:"enabled"`

	// 威胁情报源配置
	Sources map[string]ThreatIntelSourceConfig `json:"sources"`

	// 检测配置
	Detection DetectionConfig `json:"detection"`

	// 更新配置
	Update UpdateConfig `json:"update"`

	// 日志配置
	Log LogConfig `json:"log"`
}

// ThreatIntelSourceConfig 威胁情报源配置
type ThreatIntelSourceConfig struct {
	Name       string        `json:"name"`
	URL        string        `json:"url"`
	APIKey     string        `json:"api_key"`
	Enabled    bool          `json:"enabled"`
	UpdateFreq time.Duration `json:"update_freq"`
	Timeout    time.Duration `json:"timeout"`
	MaxRetries int           `json:"max_retries"`
}

// DetectionConfig 检测配置
type DetectionConfig struct {
	// 是否启用实时检测
	RealTimeEnabled bool `json:"real_time_enabled"`

	// 检测阈值
	ThreatScoreThreshold float64 `json:"threat_score_threshold"`

	// 自动响应
	AutoResponse AutoResponseConfig `json:"auto_response"`

	// 白名单
	Whitelist []string `json:"whitelist"`
}

// AutoResponseConfig 自动响应配置
type AutoResponseConfig struct {
	// 是否启用自动响应
	Enabled bool `json:"enabled"`

	// 响应动作
	Actions []string `json:"actions"` // block|monitor|log|alert

	// 响应阈值
	ResponseThreshold float64 `json:"response_threshold"`
}

// UpdateConfig 更新配置
type UpdateConfig struct {
	// 更新频率
	UpdateFreq time.Duration `json:"update_freq"`

	// 并发更新数
	ConcurrentUpdates int `json:"concurrent_updates"`

	// 更新超时
	UpdateTimeout time.Duration `json:"update_timeout"`
}

// LogConfig 日志配置
type LogConfig struct {
	// 日志级别
	Level string `json:"level"`

	// 日志文件
	LogFile string `json:"log_file"`

	// 最大文件大小
	MaxSize int64 `json:"max_size"`

	// 最大文件数
	MaxFiles int `json:"max_files"`
}

// RunnerConfig Runner 配置
type RunnerConfig struct {
	// Git 服务器配置
	Git GitServerConfig `json:"git"`
}

// GitServerConfig Git 服务器配置
type GitServerConfig struct {
	Enabled bool `json:"enabled"`
	// Git 仓库目录
	ReposDir string `json:"repos_dir"`
	// 最大并发克隆数
	MaxConcurrent int `json:"max_concurrent"`
	// 克隆超时时间（秒）
	CloneTimeout int `json:"clone_timeout"`
	// 自动清理仓库
	AutoCleanup bool `json:"auto_cleanup"`
	// 清理间隔（秒）
	CleanupInterval int `json:"cleanup_interval"`
}

// Load 加载配置文件
func Load(configFile string) (*Config, error) {
	// 设置默认值
	config := &Config{
		Server: ServerConfig{
			Host:        "0.0.0.0",
			Port:        443, // 向后兼容，保留原字段
			Debug:       false,
			LogLevel:    "info", // 默认日志级别
			EnablePprof: false,  // 默认禁用 pprof
			// 新的端口配置默认值
			PortMode:             "standard", // 默认标准模式
			CustomPort:           8080,       // 默认自定义端口
			EnableHTTPS:          true,       // 默认启用 HTTPS
			HTTP2Enabled:         false,      // 默认禁用 HTTP/2
			HTTP3Enabled:         false,      // 默认禁用 HTTP/3
			AccessLogEnabled:     true,
			AccessLogFormat:      "nginx",
			AccessLogPath:        "./data/access.log",
			AccessLogMaxSize:     100 * 1024 * 1024,
			AccessLogMaxFiles:    10,
			SharedCacheMaxSizeMB: 10,       // 从64MB降低到10MB（资源受限模式）
			ReadTimeoutSec:       1800,     // 30分钟
			WriteTimeoutSec:      1800,     // 30分钟
			IdleTimeoutSec:       120,      // 2分钟（可调）
			MaxUploadBytes:       1 << 30,  // 1 GiB
			SessionStorage:       "file",   // 默认使用文件存储
			DataDir:              "./data", // 数据目录
		},
		SSL: SSLConfig{
			Staging:            false,
			CertDir:            "./data/certs",
			KeyDir:             "./data/keys",
			AutoRenew:          true,
			DisableSelfSigned:  true,
			DNSProviders:       []DNSProvider{},
			DefaultDNSProvider: "",
			ChallengeMethods:   []string{"http-01"},
		},
		Admin: AdminConfig{
			Username:       "admin",
			Password:       "admin*9527",
			FirstRun:       true,
			PasswordFile:   "./data/admin.pass",
			EnableTOTP:     false,
			TOTPSecretFile: "./data/admin.totp",
		},
		Proxy: ProxyConfig{
			Rules:                []ProxyRule{},
			UnmatchedBehavior:    "503", // 默认使用低成本 503，减少未匹配域名的资源消耗
			UnmatchedRedirectURL: "",
		},
		CDNCache: CDNCacheConfig{
			Enabled:           false,
			CacheDir:          "./data/cache/static",
			MaxSizeBytes:      5 * 1024 * 1024 * 1024, // 5GB
			DefaultTTLSeconds: 3600,                   // 1h
			CleanIntervalSec:  60,                     // 1min
			MaxObjectBytes:    20 * 1024 * 1024,       // 20MB
			Rules:             []CDNCacheRule{},
		},
		Security: SecurityConfig{
			MaxAttempts:      900,
			BlockDurationStr: "5s",
			MaxAttempts5Min:  3000,
			BlockFile:        "./data/sslcat.block",
			AllowedUserAgents: []string{
				"Mozilla/",
				"Chrome/",
				"Firefox/",
				"Safari/",
				"Edge/",
			},
			UAInvalidMax1Min:        30,
			UAInvalidMax5Min:        100,
			TLSFingerprintWindowSec: 60,
			TLSFingerprintMaxPerMin: 60000,
			TLSFingerprintTopN:      20,
			EnableUAFilter:          false,
			EnableWAF:               false,
			EnableDDOS:              true,
			EnableCaptcha:           false,
			MinFormMs:               800,
			// 安全管理器内存泄漏防护默认值
			MaxAccessLogEntries:    3000,
			MaxBlockedIPs:          1000,
			MaxAttemptCounts:       1000,
			MaxLastAttempts:        100,
			UAInvalidMaxTotal:      500,
			TLSFingerprintMaxTotal: 500,
			CleanupIntervalMin:     5,
		},
		AdminPrefix:  "/sslcat-panel",
		BotAPIPrefix: generateBotAPIPrefix(),
		Cluster: ClusterConfig{
			Mode:     "standalone",
			NodeID:   generateNodeID(),
			NodeName: "Node-1",
			Master: MasterConfig{
				Timeout:       30,
				RetryInterval: 10,
			},
			Sync: SyncConfig{
				ConfigEnabled: true,
				CertEnabled:   true,
				Interval:      30,
				Timeout:       10,
				ExcludeConfigs: []string{
					"admin.password",
					"admin.password_file",
					"admin_prefix",
					"cluster",
				},
			},
			Port:    8443,
			AuthKey: "",
		},
		StaticSites: []StaticSite{},
		PHPSites:    []PHPSite{},
		Runners: RunnerConfig{
			Git: GitServerConfig{
				Enabled:         false,
				ReposDir:        "./data/runners/git",
				MaxConcurrent:   3,
				CloneTimeout:    300, // 5分钟
				AutoCleanup:     true,
				CleanupInterval: 7200, // 2小时
			},
		},
		UpstreamCache: UpstreamCacheConfig{
			Enabled:         false, // 默认禁用，减少内存占用
			CacheDir:        "./data/upstream-cache",
			MaxSizeBytes:    50 * 1024 * 1024, // 从1GB降低到50MB（资源受限模式）
			DefaultTTL:      1 * time.Hour,    // 1小时
			RespectUpstream: true,
			MinFileSize:     1024,             // 1KB
			MaxFileSize:     10 * 1024 * 1024, // 从100MB降低到10MB
			CacheableTypes: []string{
				"image/jpeg", "image/png", "image/gif", "image/webp",
				"text/css", "text/javascript", "application/javascript",
				"font/woff", "font/woff2", "application/font-woff",
				"video/mp4", "audio/mpeg",
			},
		},
		Monitoring: MonitoringConfig{
			Enabled:                  true, // 默认启用监控
			MemoryMaxUsagePercent:    20.0, // 默认20%
			MemoryReleaseCooldownSec: 300,  // 默认5分钟
			// 看门狗默认配置
			WatchdogEnabled:                     true, // 默认启用看门狗
			WatchdogCheckIntervalSec:            30,   // 默认30秒
			WatchdogCPUThresholdPercent:         30.0, // 默认30%
			WatchdogCPUIncreaseThresholdPercent: 15.0, // 默认15%
			WatchdogCPUIncreaseWindowSec:        180,  // 默认3分钟
			WatchdogAlertCooldownSec:            3600, // 默认1小时
			// 指标存储默认配置
			MetricsStorage: MetricsStorageConfig{
				Enabled:             true,  // 默认启用
				SamplingInterval:    1,     // 默认1分钟（支持更细粒度的监控）
				RetentionDays:       90,    // 默认保留90天
				DetailRetentionDays: 7,     // 默认详细数据保留7天
				MaxRows:             10000, // 默认最大10000行
			},
		},
		CacheWarmup: CacheWarmupConfig{
			Enabled:  false, // 默认禁用缓存预热
			URLs:     []string{},
			Interval: 60, // 默认60分钟
			BaseURL:  "",
		},
		Report: ReportConfig{
			Enabled: false, // 默认禁用报告生成
			Daily: DailyReportConfig{
				Enabled: true,
				Time:    "02:00",
			},
			Weekly: WeeklyReportConfig{
				Enabled: true,
				Day:     "monday",
				Time:    "02:00",
			},
			Monthly: MonthlyReportConfig{
				Enabled: true,
				Day:     1,
				Time:    "02:00",
			},
			AI: ReportAIConfig{
				Enabled:     false, // 默认禁用AI报告
				Model:       "gpt-4o-mini",
				MaxTokens:   2000,
				Temperature: 0.3,
				Language:    "zh-CN",
			},
		},
		ImageOptimization: ImageOptimizationConfig{
			Enabled:       false,           // 默认禁用图片优化
			AutoWebP:      false,           // 默认禁用 WebP 转换
			WebPQuality:   80,              // WebP 质量
			WebPMinSizeKB: 200,             // WebP 转换最小文件大小 200KB
			JPEGQuality:   85,              // JPEG 质量
			PNGLevel:      6,               // PNG 压缩级别
			StripMetadata: false,           // 不移除元数据
			MinSizeBytes:  60 * 1024,       // 最小文件大小 60KB
			MaxSizeBytes:  5 * 1024 * 1024, // 最大文件大小 5MB
		},
	}

	// 如果配置文件存在，则加载
	if _, err := os.Stat(configFile); err == nil {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}

		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("解析配置文件失败: %w", err)
		}
	}

	// 配置迁移：处理旧的端口配置
	migratePortConfig(config)

	// 解析时间字符串
	if config.Security.BlockDurationStr != "" {
		duration, err := time.ParseDuration(config.Security.BlockDurationStr)
		if err != nil {
			return nil, fmt.Errorf("解析 block_duration 失败: %w", err)
		}
		config.Security.BlockDuration = duration
	} else {
		config.Security.BlockDuration = time.Minute // 默认1分钟
	}

	// 创建必要的目录
	if err := os.MkdirAll(config.SSL.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}
	if err := os.MkdirAll(config.SSL.KeyDir, 0755); err != nil {
		return nil, fmt.Errorf("创建密钥目录失败: %w", err)
	}
	// 创建 CDN 缓存目录（若配置启用或指定目录）
	if config.CDNCache.CacheDir != "" {
		if err := os.MkdirAll(config.CDNCache.CacheDir, 0755); err != nil {
			return nil, fmt.Errorf("创建CDN缓存目录失败: %w", err)
		}
	}
	// 确保密码文件目录存在，并且如存在则覆盖内存密码
	if config.Admin.PasswordFile != "" {
		if err := os.MkdirAll(filepath.Dir(config.Admin.PasswordFile), 0755); err != nil {
			return nil, fmt.Errorf("创建密码文件目录失败: %w", err)
		}
		if b, err := os.ReadFile(config.Admin.PasswordFile); err == nil {
			config.Admin.Password = strings.TrimSpace(string(b))
		}
	}

	// 确保TOTP密钥文件目录存在，并加载TOTP密钥
	if config.Admin.TOTPSecretFile != "" {
		if err := os.MkdirAll(filepath.Dir(config.Admin.TOTPSecretFile), 0755); err != nil {
			return nil, fmt.Errorf("创建TOTP密钥文件目录失败: %w", err)
		}
		if b, err := os.ReadFile(config.Admin.TOTPSecretFile); err == nil {
			secret := strings.TrimSpace(string(b))
			if secret != "" {
				config.Admin.TOTPSecret = secret
				config.Admin.EnableTOTP = true // 有密钥文件就自动启用
			}
		} else {
			// 文件不存在或读取失败，自动关闭TOTP
			if config.Admin.EnableTOTP {
				config.Admin.EnableTOTP = false
				config.Admin.TOTPSecret = ""
			}
		}
	}

	// 保存配置文件路径
	config.ConfigFile = configFile

	// 执行代理规则迁移
	config.migrateProxyRules()

	// 验证配置（包括循环检测）
	if err := ValidateConfigWithLoopDetection(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// generateNodeID 生成节点ID
func generateNodeID() string {
	// 使用时间戳和随机数生成节点ID
	data := make([]byte, 8)
	_, err := rand.Read(data)
	if err != nil {
		// 如果随机数生成失败，使用时间戳
		data = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	timestamp := time.Now().Unix()
	combined := fmt.Sprintf("%d-%x", timestamp, data)
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:8])
}

// generateBotAPIPrefix 生成随机的机器人检测 API 前缀
func generateBotAPIPrefix() string {
	// 生成 16 字节随机数据
	data := make([]byte, 16)
	_, err := rand.Read(data)
	if err != nil {
		// 如果随机数生成失败，使用时间戳
		data = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	hash := sha256.Sum256(data)
	// 使用前 12 个字符作为前缀，添加 /bot- 前缀使其更易识别（但不暴露管理面板）
	return "/bot-" + hex.EncodeToString(hash[:6])
}

// IsSlaveMode 检查是否为Slave模式
func (c *Config) IsSlaveMode() bool {
	return c.Cluster.Mode == "slave"
}

// IsMasterMode 检查是否为Master模式
func (c *Config) IsMasterMode() bool {
	return c.Cluster.Mode == "master"
}

// IsStandaloneMode 检查是否为独立模式
func (c *Config) IsStandaloneMode() bool {
	return c.Cluster.Mode == "standalone" || c.Cluster.Mode == ""
}

// 实现集群配置接口方法
func (c *Config) GetClusterMode() string {
	return c.Cluster.Mode
}

func (c *Config) GetNodeID() string {
	return c.Cluster.NodeID
}

func (c *Config) GetNodeName() string {
	return c.Cluster.NodeName
}

func (c *Config) GetMasterConfig() interface{} {
	return struct {
		Host          string
		Port          int
		AuthKey       string
		Timeout       int
		RetryInterval int
	}{
		Host:          c.Cluster.Master.Host,
		Port:          c.Cluster.Master.Port,
		AuthKey:       c.Cluster.Master.AuthKey,
		Timeout:       c.Cluster.Master.Timeout,
		RetryInterval: c.Cluster.Master.RetryInterval,
	}
}

func (c *Config) GetSyncConfig() interface{} {
	return struct {
		ConfigEnabled  bool
		CertEnabled    bool
		Interval       int
		Timeout        int
		ExcludeConfigs []string
	}{
		ConfigEnabled:  c.Cluster.Sync.ConfigEnabled,
		CertEnabled:    c.Cluster.Sync.CertEnabled,
		Interval:       c.Cluster.Sync.Interval,
		Timeout:        c.Cluster.Sync.Timeout,
		ExcludeConfigs: c.Cluster.Sync.ExcludeConfigs,
	}
}

func (c *Config) GetClusterPort() int {
	return c.Cluster.Port
}

func (c *Config) GetClusterAuthKey() string {
	return c.Cluster.AuthKey
}

func (c *Config) GetServicePort() int {
	return c.Server.Port
}

func (c *Config) GetCertDir() string {
	return c.SSL.CertDir
}

func (c *Config) GetProxyRules() []interface{} {
	rules := make([]interface{}, len(c.Proxy.Rules))
	for i, rule := range c.Proxy.Rules {
		rules[i] = rule
	}
	return rules
}

func (c *Config) GetSSLDomains() []string {
	return c.SSL.Domains
}

// ValidateConfigWithLoopDetection 验证配置（包括循环检测）
func ValidateConfigWithLoopDetection(config *Config) error {
	// 基本验证
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	// 验证服务器配置
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	// 验证SSL配置
	if config.SSL.Email == "" {
		return fmt.Errorf("SSL email is required")
	}

	// 验证管理员配置
	if config.Admin.Username == "" {
		return fmt.Errorf("admin username is required")
	}

	// 获取 sslcat 监听的端口列表
	listeningPorts := getListeningPorts(config)

	// 验证代理规则
	for i, rule := range config.Proxy.Rules {
		if rule.Domain == "" {
			return fmt.Errorf("proxy rule %d: domain is required", i)
		}

		if !rule.LoadBalancerEnabled {
			// 单后端模式
			if rule.Target == "" {
				return fmt.Errorf("proxy rule %d: target is required", i)
			}
			if rule.Port <= 0 {
				return fmt.Errorf("proxy rule %d: invalid port: %d", i, rule.Port)
			}

			// 检测循环代理：后端指向自己
			if err := detectProxyLoop(config, &rule, listeningPorts); err != nil {
				return fmt.Errorf("proxy rule %d (%s): %w", i, rule.Domain, err)
			}
		} else {
			// 负载均衡模式
			if len(rule.LoadBalancerBackends) == 0 {
				return fmt.Errorf("proxy rule %d: load balancer backends are required", i)
			}

			for j, backend := range rule.LoadBalancerBackends {
				if backend.Host == "" {
					return fmt.Errorf("proxy rule %d, backend %d: host is required", i, j)
				}
				if backend.Port <= 0 {
					return fmt.Errorf("proxy rule %d, backend %d: invalid port: %d", i, j, backend.Port)
				}

				// 检测负载均衡后端的循环代理
				if err := detectBackendLoop(config, &rule, &backend, listeningPorts); err != nil {
					return fmt.Errorf("proxy rule %d (%s), backend %d: %w", i, rule.Domain, j, err)
				}
			}
		}
	}

	return nil
}

// detectProxyLoop 检测单后端模式的循环代理
func detectProxyLoop(config *Config, rule *ProxyRule, listeningPorts []int) error {
	// 检查后端是否指向本地监听端口
	if isLocalhost(rule.Target) && containsPort(listeningPorts, rule.Port) {
		return fmt.Errorf("proxy loop detected: %s proxies to itself (%s:%d), this will cause infinite loop and resource exhaustion",
			rule.Domain, rule.Target, rule.Port)
	}

	return nil
}

// detectBackendLoop 检测负载均衡后端的循环代理
func detectBackendLoop(config *Config, rule *ProxyRule, backend *ProxyBackend, listeningPorts []int) error {
	// 检查后端是否指向本地监听端口
	if isLocalhost(backend.Host) && containsPort(listeningPorts, backend.Port) {
		return fmt.Errorf("proxy loop detected: %s backend (%s:%d) points to sslcat itself, this will cause infinite loop",
			rule.Domain, backend.Host, backend.Port)
	}

	return nil
}

// getListeningPorts 获取 sslcat 监听的所有端口
func getListeningPorts(config *Config) []int {
	ports := make([]int, 0, 3)

	// 添加主端口
	if config.Server.Port > 0 {
		ports = append(ports, config.Server.Port)
	}

	// 添加 HTTP 端口（通常是 80）
	if config.Server.PortMode == "standard" {
		ports = append(ports, 80)  // HTTP 端口
		ports = append(ports, 443) // HTTPS 端口
	} else if config.Server.PortMode == "custom" {
		if config.Server.CustomPort > 0 {
			ports = append(ports, config.Server.CustomPort)
		}
	}

	return ports
}

// isLocalhost 检查主机是否是本地地址
func isLocalhost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))

	// 检查常见的本地地址
	localAddresses := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"::",
	}

	for _, addr := range localAddresses {
		if host == addr {
			return true
		}
	}

	// 检查 127.x.x.x 网段
	if strings.HasPrefix(host, "127.") {
		return true
	}

	return false
}

// containsPort 检查端口列表是否包含指定端口
func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// getDefaultConfig 获取默认配置（提取自 Load 函数）
func getDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:              "0.0.0.0",
			Port:              443,
			Debug:             false,
			LogLevel:          "info",
			EnablePprof:       false,
			PortMode:          "standard",
			CustomPort:        8080,
			EnableHTTPS:       true,
			HTTP2Enabled:      false, // 默认禁用 HTTP/2
			HTTP3Enabled:      false, // 默认禁用 HTTP/3
			AccessLogEnabled:  true,
			AccessLogFormat:   "nginx",
			AccessLogPath:     "./data/access.log",
			AccessLogMaxSize:  100 * 1024 * 1024,
			AccessLogMaxFiles: 10,
			ReadTimeoutSec:    1800,
			WriteTimeoutSec:   1800,
			IdleTimeoutSec:    120,
			MaxUploadBytes:    1 << 30,
			SessionStorage:    "file",
			DataDir:           "./data",
		},
		SSL: SSLConfig{
			Staging:            false,
			CertDir:            "./data/certs",
			KeyDir:             "./data/keys",
			AutoRenew:          true,
			DisableSelfSigned:  true,
			DNSProviders:       []DNSProvider{},
			DefaultDNSProvider: "",
			ChallengeMethods:   []string{"http-01"},
		},
		Admin: AdminConfig{
			Username:       "admin",
			Password:       "admin*9527",
			FirstRun:       true,
			PasswordFile:   "./data/admin.pass",
			EnableTOTP:     false,
			TOTPSecretFile: "./data/admin.totp",
		},
		Proxy: ProxyConfig{
			Rules:                []ProxyRule{},
			UnmatchedBehavior:    "503", // 默认使用低成本 503，减少未匹配域名的资源消耗
			UnmatchedRedirectURL: "",
		},
		CDNCache: CDNCacheConfig{
			Enabled:           false,
			CacheDir:          "./data/cache/static",
			MaxSizeBytes:      5 * 1024 * 1024 * 1024,
			DefaultTTLSeconds: 3600,
			CleanIntervalSec:  60,
			MaxObjectBytes:    20 * 1024 * 1024,
			Rules:             []CDNCacheRule{},
		},
		Security: SecurityConfig{
			MaxAttempts:      900,
			BlockDurationStr: "5s",
			MaxAttempts5Min:  3000,
			BlockFile:        "./data/sslcat.block",
			AllowedUserAgents: []string{
				"Mozilla/",
				"Chrome/",
				"Firefox/",
				"Safari/",
				"Edge/",
			},
			UAInvalidMax1Min:        30,
			UAInvalidMax5Min:        100,
			TLSFingerprintWindowSec: 60,
			TLSFingerprintMaxPerMin: 60000,
			TLSFingerprintTopN:      20,
			EnableUAFilter:          false,
			EnableWAF:               false,
			EnableDDOS:              true,
			EnableCaptcha:           false,
			MinFormMs:               800,
			MaxAccessLogEntries:     3000,
			MaxBlockedIPs:           1000,
			MaxAttemptCounts:        1000,
			MaxLastAttempts:         100,
			UAInvalidMaxTotal:       500,
			TLSFingerprintMaxTotal:  500,
			CleanupIntervalMin:      5,
		},
		AdminPrefix:  "/sslcat-panel",
		BotAPIPrefix: generateBotAPIPrefix(),
		Cluster: ClusterConfig{
			Mode:     "standalone",
			NodeID:   generateNodeID(),
			NodeName: "Node-1",
			Master: MasterConfig{
				Timeout:       30,
				RetryInterval: 10,
			},
			Sync: SyncConfig{
				ConfigEnabled: true,
				CertEnabled:   true,
				Interval:      30,
				Timeout:       10,
				ExcludeConfigs: []string{
					"admin.password",
					"admin.password_file",
					"admin_prefix",
					"cluster",
				},
			},
			Port:    8443,
			AuthKey: "",
		},
		StaticSites: []StaticSite{},
		PHPSites:    []PHPSite{},
		Runners: RunnerConfig{
			Git: GitServerConfig{
				Enabled:         false,
				ReposDir:        "./data/runners/git",
				MaxConcurrent:   3,
				CloneTimeout:    300,
				AutoCleanup:     true,
				CleanupInterval: 7200,
			},
		},
		UpstreamCache: UpstreamCacheConfig{
			Enabled:         true,
			CacheDir:        "./data/upstream-cache",
			MaxSizeBytes:    1024 * 1024 * 1024,
			DefaultTTL:      1 * time.Hour,
			RespectUpstream: true,
			MinFileSize:     1024,
			MaxFileSize:     100 * 1024 * 1024,
			CacheableTypes: []string{
				"image/jpeg", "image/png", "image/gif", "image/webp",
				"text/css", "text/javascript", "application/javascript",
				"font/woff", "font/woff2", "application/font-woff",
				"video/mp4", "audio/mpeg",
			},
		},
		Monitoring: MonitoringConfig{
			Enabled: true,
			// 看门狗默认配置
			WatchdogEnabled:                     true, // 默认启用看门狗
			WatchdogCheckIntervalSec:            30,
			WatchdogCPUThresholdPercent:         30.0,
			WatchdogCPUIncreaseThresholdPercent: 15.0,
			WatchdogCPUIncreaseWindowSec:        180,
			WatchdogAlertCooldownSec:            3600,
			// 指标存储默认配置
			MetricsStorage: MetricsStorageConfig{
				Enabled:             true,
				SamplingInterval:    1, // 默认1分钟
				RetentionDays:       90,
				DetailRetentionDays: 7,
				MaxRows:             10000,
			},
		},
		CacheWarmup: CacheWarmupConfig{
			Enabled:  false,
			URLs:     []string{},
			Interval: 60,
			BaseURL:  "",
		},
		Report: ReportConfig{
			Enabled: false,
			Daily: DailyReportConfig{
				Enabled: true,
				Time:    "02:00",
			},
			Weekly: WeeklyReportConfig{
				Enabled: true,
				Day:     "monday",
				Time:    "02:00",
			},
			Monthly: MonthlyReportConfig{
				Enabled: true,
				Day:     1,
				Time:    "02:00",
			},
			AI: ReportAIConfig{
				Enabled:     false,
				Model:       "gpt-4o-mini",
				MaxTokens:   2000,
				Temperature: 0.3,
				Language:    "zh-CN",
			},
		},
		ImageOptimization: ImageOptimizationConfig{
			Enabled:       false,
			AutoWebP:      false,
			WebPQuality:   80,
			WebPMinSizeKB: 200,
			JPEGQuality:   85,
			PNGLevel:      6,
			StripMetadata: false,
			MinSizeBytes:  60 * 1024,
			MaxSizeBytes:  5 * 1024 * 1024,
		},
	}
}

// diffConfig 比较两个配置，返回只包含不同字段的配置
// 使用 JSON 序列化/反序列化的方式来实现深度比较
func diffConfig(current, defaultConfig *Config) (map[string]interface{}, error) {
	// 序列化为 JSON map
	currentJSON, err := json.Marshal(current)
	if err != nil {
		return nil, fmt.Errorf("序列化当前配置失败: %w", err)
	}

	defaultJSON, err := json.Marshal(defaultConfig)
	if err != nil {
		return nil, fmt.Errorf("序列化默认配置失败: %w", err)
	}

	var currentMap map[string]interface{}
	var defaultMap map[string]interface{}

	if err := json.Unmarshal(currentJSON, &currentMap); err != nil {
		return nil, fmt.Errorf("反序列化当前配置失败: %w", err)
	}

	if err := json.Unmarshal(defaultJSON, &defaultMap); err != nil {
		return nil, fmt.Errorf("反序列化默认配置失败: %w", err)
	}

	// 递归比较并保留不同的字段
	result := make(map[string]interface{})
	diffMap(currentMap, defaultMap, result)

	return result, nil
}

// diffMap 递归比较两个 map，将不同的字段添加到结果中
func diffMap(current, defaultVal map[string]interface{}, result map[string]interface{}) {
	for key, currentVal := range current {
		// 跳过 ConfigFile 字段（不序列化）
		if key == "config_file" {
			continue
		}

		defaultValForKey, exists := defaultVal[key]
		if !exists {
			// 默认配置中没有这个键，检查当前值是否是零值
			// 如果是零值，则不保留（因为默认值就是零值）
			if !isZeroValue(currentVal) {
				// 如果是嵌套结构（map 或 slice），需要递归清理零值字段
				if cleaned := cleanZeroValues(currentVal); cleaned != nil {
					result[key] = cleaned
				}
			}
			continue
		}

		// 如果是嵌套的 map，递归比较
		currentMap, currentIsMap := currentVal.(map[string]interface{})
		defaultMap, defaultIsMap := defaultValForKey.(map[string]interface{})

		if currentIsMap && defaultIsMap {
			// 都是 map，递归比较
			nestedResult := make(map[string]interface{})
			diffMap(currentMap, defaultMap, nestedResult)
			if len(nestedResult) > 0 {
				result[key] = nestedResult
			}
		} else if !deepEqual(currentVal, defaultValForKey) {
			// 不是嵌套 map，直接比较
			// 但需要清理零值字段（特别是对于 slice 中的 map 元素）
			if cleaned := cleanZeroValues(currentVal); cleaned != nil {
				result[key] = cleaned
			}
		}
	}
}

// cleanZeroValues 清理嵌套结构中的零值字段
func cleanZeroValues(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	// 处理 map
	if m, ok := v.(map[string]interface{}); ok {
		cleaned := make(map[string]interface{})
		for key, val := range m {
			// 跳过零值字段
			if isZeroValue(val) {
				continue
			}
			// 递归清理嵌套结构
			if cleanedVal := cleanZeroValues(val); cleanedVal != nil {
				cleaned[key] = cleanedVal
			}
		}
		if len(cleaned) == 0 {
			return nil
		}
		return cleaned
	}

	// 处理 slice
	if s, ok := v.([]interface{}); ok {
		cleaned := make([]interface{}, 0, len(s))
		for _, item := range s {
			if cleanedItem := cleanZeroValues(item); cleanedItem != nil {
				cleaned = append(cleaned, cleanedItem)
			}
		}
		if len(cleaned) == 0 {
			return nil
		}
		return cleaned
	}

	// 其他类型直接返回
	return v
}

// isZeroValue 检查值是否是零值（应该被忽略的默认值）
func isZeroValue(v interface{}) bool {
	if v == nil {
		return true
	}

	// 使用反射来处理所有类型，因为 JSON 反序列化后的类型可能不同
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return true
	}

	switch rv.Kind() {
	case reflect.Bool:
		return !rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return rv.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return rv.Float() == 0
	case reflect.String:
		return rv.String() == ""
	case reflect.Slice, reflect.Array:
		return rv.Len() == 0
	case reflect.Map:
		return rv.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return rv.IsNil()
	default:
		// 对于其他类型，尝试类型断言
		switch val := v.(type) {
		case bool:
			return !val
		case int, int8, int16, int32, int64:
			return val == 0
		case uint, uint8, uint16, uint32, uint64:
			return val == 0
		case float32, float64:
			return val == 0
		case string:
			return val == ""
		case []interface{}:
			return len(val) == 0
		case map[string]interface{}:
			return len(val) == 0
		default:
			return false
		}
	}
}

// deepEqual 深度比较两个值是否相等
func deepEqual(a, b interface{}) bool {
	// 处理 nil
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// 类型断言
	aMap, aIsMap := a.(map[string]interface{})
	bMap, bIsMap := b.(map[string]interface{})

	if aIsMap && bIsMap {
		// 都是 map，递归比较
		if len(aMap) != len(bMap) {
			return false
		}
		for key, aVal := range aMap {
			bVal, exists := bMap[key]
			if !exists || !deepEqual(aVal, bVal) {
				return false
			}
		}
		return true
	}

	aSlice, aIsSlice := a.([]interface{})
	bSlice, bIsSlice := b.([]interface{})

	if aIsSlice && bIsSlice {
		// 都是 slice，比较长度和元素
		if len(aSlice) != len(bSlice) {
			return false
		}
		for i := range aSlice {
			if !deepEqual(aSlice[i], bSlice[i]) {
				return false
			}
		}
		return true
	}

	// 其他类型直接比较
	return a == b
}

// Save 保存配置文件
func (c *Config) Save(configFile string) error {
	// 智能选择配置文件路径
	actualConfigFile := c.getWritableConfigPath(configFile)

	// 执行代理规则静默升级
	c.prepareProxyRulesForSave()

	// 验证配置完整性
	if err := c.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}

	// 创建用于比较的配置副本，清理敏感信息
	shadow := *c
	shadow.Security.BlockDurationStr = c.Security.BlockDuration.String()
	shadow.Admin.Password = ""
	shadow.Admin.TOTPSecret = "" // 不保存TOTP密钥到配置文件

	// 获取默认配置
	defaultConfig := getDefaultConfig()
	defaultConfig.Security.BlockDurationStr = defaultConfig.Security.BlockDuration.String()
	defaultConfig.Admin.Password = ""
	defaultConfig.Admin.TOTPSecret = ""

	// 比较配置，只保留不同的字段
	diffMap, err := diffConfig(&shadow, defaultConfig)
	if err != nil {
		return fmt.Errorf("比较配置失败: %w", err)
	}

	// 如果没有任何差异，保存空对象 {}
	if len(diffMap) == 0 {
		diffMap = make(map[string]interface{})
	}

	// 序列化差异配置
	data, err := json.MarshalIndent(diffMap, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 在保存前创建备份
	if err := c.createBackup(actualConfigFile); err != nil {
		// 备份失败不影响主流程，只记录警告
		// 使用 fmt.Printf 因为这里可能没有 logger
		fmt.Printf("警告: 创建配置文件备份失败: %v\n", err)
	}

	// 尝试保存到主要路径
	if err := c.saveToPath(actualConfigFile, data); err != nil {
		// 如果主要路径失败，尝试备用路径
		fallbackPaths := c.getFallbackPaths(configFile)
		for _, fallbackPath := range fallbackPaths {
			if fallbackPath == actualConfigFile {
				continue // 跳过已经尝试过的路径
			}

			if err := c.saveToPath(fallbackPath, data); err == nil {
				// 成功保存到备用路径，更新配置文件的路径记录
				c.ConfigFile = fallbackPath
				return nil
			}
		}

		// 所有路径都失败了，返回详细错误信息
		return fmt.Errorf("配置文件保存失败: 尝试了多个路径均失败。主要路径: %s, 错误: %w", actualConfigFile, err)
	}

	return nil
}

// saveToPath 保存配置到指定路径
func (c *Config) saveToPath(configPath string, data []byte) error {
	// 确保配置目录存在
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败 (%s): %w", configDir, err)
	}

	// 创建临时文件，然后原子性重命名
	tempFile := configPath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("写入临时配置文件失败 (%s): %w", tempFile, err)
	}

	// 原子性重命名
	if err := os.Rename(tempFile, configPath); err != nil {
		os.Remove(tempFile) // 清理临时文件

		// 提供更详细的错误信息和建议
		if os.IsNotExist(err) {
			return fmt.Errorf("重命名配置文件失败: 目标目录不存在 (%s -> %s)。请检查目录权限或使用备用路径", tempFile, configPath)
		} else if os.IsPermission(err) {
			return fmt.Errorf("重命名配置文件失败: 权限不足 (%s -> %s)。请检查文件权限或使用 sudo 运行", tempFile, configPath)
		} else {
			return fmt.Errorf("重命名配置文件失败 (%s -> %s): %w。建议检查文件系统权限或使用备用配置路径", tempFile, configPath, err)
		}
	}

	return nil
}

// getFallbackPaths 获取备用配置文件路径列表
func (c *Config) getFallbackPaths(originalPath string) []string {
	paths := []string{}

	// 运行时目录
	runtimeDir := "./data"
	if err := os.MkdirAll(runtimeDir, 0755); err == nil {
		paths = append(paths, filepath.Join(runtimeDir, "sslcat.conf"))
	}

	// 用户主目录
	if homeDir, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(homeDir, ".sslcat", "sslcat.conf"))
	}

	// 临时目录
	if tempDir := os.TempDir(); tempDir != "" {
		paths = append(paths, filepath.Join(tempDir, "sslcat.conf"))
	}

	// 当前目录
	paths = append(paths, "./sslcat.conf")

	return paths
}

// getWritableConfigPath 智能选择可写的配置文件路径
func (c *Config) getWritableConfigPath(originalPath string) string {
	// 首先尝试原始路径
	if c.canWriteToPath(originalPath) {
		return originalPath
	}

	// 如果原始路径不可写，尝试运行时目录
	runtimeDir := "./data"
	if err := os.MkdirAll(runtimeDir, 0755); err == nil {
		runtimePath := filepath.Join(runtimeDir, "sslcat.conf")
		if c.canWriteToPath(runtimePath) {
			return runtimePath
		}
	}

	// 尝试用户主目录
	if homeDir, err := os.UserHomeDir(); err == nil {
		homeConfigPath := filepath.Join(homeDir, ".sslcat", "sslcat.conf")
		if c.canWriteToPath(homeConfigPath) {
			return homeConfigPath
		}
	}

	// 尝试临时目录
	if tempDir := os.TempDir(); tempDir != "" {
		tempConfigPath := filepath.Join(tempDir, "sslcat.conf")
		if c.canWriteToPath(tempConfigPath) {
			return tempConfigPath
		}
	}

	// 最后尝试当前目录
	currentDirPath := "./sslcat.conf"
	if c.canWriteToPath(currentDirPath) {
		return currentDirPath
	}

	// 如果都不可写，返回原始路径（让调用者处理错误）
	return originalPath
}

// canWriteToPath 检查是否可以写入指定路径
func (c *Config) canWriteToPath(path string) bool {
	// 检查目录是否存在，如果不存在则尝试创建
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false
	}

	// 尝试创建一个临时文件来测试写入权限
	tempFile := path + ".test"
	if err := os.WriteFile(tempFile, []byte("test"), 0644); err != nil {
		return false
	}

	// 清理测试文件
	os.Remove(tempFile)
	return true
}

// createBackup 创建配置文件备份
// 备份策略：
// 1. 版本备份：保留最近10个版本备份（每次保存都创建新备份）
// 2. 按天备份：保留最近10个按天备份（每天只保留一个）
func (c *Config) createBackup(configFile string) error {
	// 如果配置文件不存在，不需要备份
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil
	}

	// 读取当前配置文件内容
	currentData, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 如果文件为空，不需要备份
	if len(currentData) == 0 {
		return nil
	}

	configDir := filepath.Dir(configFile)
	configBaseName := filepath.Base(configFile)

	// 创建版本备份（保留最近10个）
	if err := c.createVersionBackup(configDir, configBaseName, currentData); err != nil {
		return fmt.Errorf("创建版本备份失败: %w", err)
	}

	// 创建按天备份（保留最近10个不同的日期）
	if err := c.createDailyBackup(configDir, configBaseName, currentData); err != nil {
		return fmt.Errorf("创建按天备份失败: %w", err)
	}

	return nil
}

// createVersionBackup 创建版本备份（保留最近10个）
func (c *Config) createVersionBackup(configDir, configBaseName string, data []byte) error {
	backupPattern := filepath.Join(configDir, configBaseName+".backup.v*")
	backupFiles, err := filepath.Glob(backupPattern)
	if err != nil {
		return fmt.Errorf("查找备份文件失败: %w", err)
	}

	// 找到当前最大的版本号
	maxVersion := 0
	for _, backupFile := range backupFiles {
		// 提取版本号
		base := filepath.Base(backupFile)
		var version int
		if _, err := fmt.Sscanf(base, configBaseName+".backup.v%d", &version); err == nil {
			if version > maxVersion {
				maxVersion = version
			}
		}
	}

	// 如果已有10个备份，删除最旧的（v1）
	if len(backupFiles) >= 10 {
		oldestBackup := filepath.Join(configDir, configBaseName+".backup.v1")
		if err := os.Remove(oldestBackup); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("删除旧备份失败: %w", err)
		}
		// 重命名其他备份文件，使版本号连续
		for i := 2; i <= maxVersion; i++ {
			oldFile := filepath.Join(configDir, fmt.Sprintf("%s.backup.v%d", configBaseName, i))
			newFile := filepath.Join(configDir, fmt.Sprintf("%s.backup.v%d", configBaseName, i-1))
			if _, err := os.Stat(oldFile); err == nil {
				if err := os.Rename(oldFile, newFile); err != nil {
					return fmt.Errorf("重命名备份文件失败: %w", err)
				}
			}
		}
		maxVersion = maxVersion - 1
	}

	// 创建新的备份文件（版本号加1）
	newVersion := maxVersion + 1
	newBackupFile := filepath.Join(configDir, fmt.Sprintf("%s.backup.v%d", configBaseName, newVersion))
	if err := os.WriteFile(newBackupFile, data, 0644); err != nil {
		return fmt.Errorf("写入备份文件失败: %w", err)
	}

	return nil
}

// createDailyBackup 创建按天备份（保留最近10个不同的日期）
func (c *Config) createDailyBackup(configDir, configBaseName string, data []byte) error {
	// 获取今天的日期
	today := time.Now().Format("2006-01-02")
	todayBackupFile := filepath.Join(configDir, fmt.Sprintf("%s.backup.%s", configBaseName, today))

	// 检查今天是否已经有备份
	if _, err := os.Stat(todayBackupFile); err == nil {
		// 今天已有备份，比较内容是否相同
		existingData, err := os.ReadFile(todayBackupFile)
		if err == nil && len(existingData) == len(data) {
			// 如果内容相同，不需要更新
			same := true
			for i := range data {
				if existingData[i] != data[i] {
					same = false
					break
				}
			}
			if same {
				return nil // 内容相同，不需要更新
			}
		}
	}

	// 创建或更新今天的备份
	if err := os.WriteFile(todayBackupFile, data, 0644); err != nil {
		return fmt.Errorf("写入按天备份文件失败: %w", err)
	}

	// 清理旧的按天备份（保留最近10个不同的日期）
	if err := c.cleanupDailyBackups(configDir, configBaseName); err != nil {
		return fmt.Errorf("清理旧备份失败: %w", err)
	}

	return nil
}

// cleanupDailyBackups 清理旧的按天备份，只保留最近10个不同的日期
func (c *Config) cleanupDailyBackups(configDir, configBaseName string) error {
	backupPattern := filepath.Join(configDir, configBaseName+".backup.????-??-??")
	backupFiles, err := filepath.Glob(backupPattern)
	if err != nil {
		return fmt.Errorf("查找按天备份文件失败: %w", err)
	}

	// 如果备份文件数量不超过10个，不需要清理
	if len(backupFiles) <= 10 {
		return nil
	}

	// 提取日期并排序
	type backupInfo struct {
		file    string
		date    time.Time
		modTime time.Time
	}

	backups := make([]backupInfo, 0, len(backupFiles))
	for _, backupFile := range backupFiles {
		base := filepath.Base(backupFile)
		var dateStr string
		if _, err := fmt.Sscanf(base, configBaseName+".backup.%s", &dateStr); err != nil {
			continue
		}

		date, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}

		// 获取文件修改时间
		info, err := os.Stat(backupFile)
		if err != nil {
			continue
		}

		backups = append(backups, backupInfo{
			file:    backupFile,
			date:    date,
			modTime: info.ModTime(),
		})
	}

	// 按日期排序（最新的在前）
	for i := 0; i < len(backups)-1; i++ {
		for j := i + 1; j < len(backups); j++ {
			if backups[i].date.Before(backups[j].date) {
				backups[i], backups[j] = backups[j], backups[i]
			}
		}
	}

	// 删除超过10个的旧备份
	for i := 10; i < len(backups); i++ {
		if err := os.Remove(backups[i].file); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("删除旧备份失败: %w", err)
		}
	}

	return nil
}

// GetProxyRule 获取指定域名的代理规则
func (c *Config) GetProxyRule(domain string) *ProxyRule {
	for i := range c.Proxy.Rules {
		if c.Proxy.Rules[i].Domain == domain && c.Proxy.Rules[i].Enabled {
			return &c.Proxy.Rules[i]
		}
	}
	return nil
}

// AddProxyRule 添加代理规则
func (c *Config) AddProxyRule(rule ProxyRule) {
	// 检查是否已存在
	for i := range c.Proxy.Rules {
		if c.Proxy.Rules[i].Domain == rule.Domain {
			c.Proxy.Rules[i] = rule
			return
		}
	}
	// 添加新规则
	c.Proxy.Rules = append(c.Proxy.Rules, rule)
}

// Validate 验证配置完整性
func (c *Config) Validate() error {
	// 验证代理规则
	for i, rule := range c.Proxy.Rules {
		if rule.Domain == "" {
			return fmt.Errorf("代理规则 %d: 域名不能为空", i)
		}
		if rule.Target == "" {
			return fmt.Errorf("代理规则 %d: 目标地址不能为空", i)
		}
		if rule.Port < 0 || rule.Port > 65535 {
			return fmt.Errorf("代理规则 %d: 端口号必须在0-65535范围内", i)
		}
	}

	// 验证SSL配置
	if c.SSL.Email == "" && !c.SSL.DisableSelfSigned {
		return fmt.Errorf("SSL配置: 当禁用自签名证书时，必须提供邮箱地址")
	}

	// 验证服务器配置
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("服务器配置: 端口号必须在1-65535范围内")
	}

	return nil
}

// RemoveProxyRule 删除代理规则
func (c *Config) RemoveProxyRule(domain string) {
	for i := range c.Proxy.Rules {
		if c.Proxy.Rules[i].Domain == domain {
			c.Proxy.Rules = append(c.Proxy.Rules[:i], c.Proxy.Rules[i+1:]...)
			return
		}
	}
}

// NotificationConfig 通知配置
type NotificationConfig struct {
	MinNotificationLevel string         `json:"min_notification_level"` // 最小通知级别 (info|warning|error|critical)
	Channels             ChannelsConfig `json:"channels"`               // 通知渠道配置
}

// ChannelsConfig 通知渠道配置
type ChannelsConfig struct {
	Email   EmailChannelConfig   `json:"email"`   // 邮件通知配置
	Webhook WebhookChannelConfig `json:"webhook"` // Webhook通知配置（包括Slack、企业微信、飞书等）
	Syslog  SyslogChannelConfig  `json:"syslog"`  // 系统日志通知配置
	Console ConsoleChannelConfig `json:"console"` // 控制台通知配置
}

// EmailChannelConfig 邮件通知渠道配置
type EmailChannelConfig struct {
	Enabled bool   `json:"enabled"` // 是否启用
	Method  string `json:"method"`  // 邮件发送方式: smtp, sendmail, resend, mailgun, sendgrid

	// SMTP 配置
	SMTPHost string   `json:"smtp_host"` // SMTP服务器地址
	SMTPPort int      `json:"smtp_port"` // SMTP端口
	Username string   `json:"username"`  // 用户名
	Password string   `json:"password"`  // 密码
	From     string   `json:"from"`      // 发件人地址
	To       []string `json:"to"`        // 收件人地址列表
	UseTLS   bool     `json:"use_tls"`   // 是否使用TLS

	// Sendmail 配置
	SendmailCommand string `json:"sendmail_command"` // Sendmail 命令路径
	SendmailArgs    string `json:"sendmail_args"`    // Sendmail 参数

	// Resend 配置
	ResendAPIKey string `json:"resend_api_key"` // Resend API Key
	ResendFrom   string `json:"resend_from"`    // Resend 发件人
	ResendTo     string `json:"resend_to"`      // Resend 收件人

	// Mailgun 配置
	MailgunAPIKey string `json:"mailgun_api_key"` // Mailgun API Key
	MailgunDomain string `json:"mailgun_domain"`  // Mailgun 域名
	MailgunFrom   string `json:"mailgun_from"`    // Mailgun 发件人
	MailgunTo     string `json:"mailgun_to"`      // Mailgun 收件人

	// SendGrid 配置
	SendGridAPIKey string `json:"sendgrid_api_key"` // SendGrid API Key
	SendGridFrom   string `json:"sendgrid_from"`    // SendGrid 发件人
	SendGridTo     string `json:"sendgrid_to"`      // SendGrid 收件人
}

// WebhookChannelConfig Webhook通知渠道配置
type WebhookChannelConfig struct {
	Enabled bool              `json:"enabled"` // 是否启用
	URLs    []string          `json:"urls"`    // Webhook URL列表
	URL     string            `json:"url"`     // 单个Webhook URL（向后兼容）
	Headers map[string]string `json:"headers"` // 自定义HTTP头部
	Timeout int               `json:"timeout"` // 超时时间（秒）
}

// SyslogChannelConfig 系统日志通知渠道配置
type SyslogChannelConfig struct {
	Enabled bool   `json:"enabled"` // 是否启用
	Address string `json:"address"` // syslog服务器地址
	Network string `json:"network"` // 网络协议 (udp/tcp)
}

// ConsoleChannelConfig 控制台通知渠道配置
type ConsoleChannelConfig struct {
	Enabled bool `json:"enabled"` // 是否启用
}

// UpstreamCacheConfig 上游缓存配置
type UpstreamCacheConfig struct {
	Enabled         bool          `json:"enabled"`          // 是否启用上游缓存
	CacheDir        string        `json:"cache_dir"`        // 缓存目录
	MaxSizeBytes    int64         `json:"max_size_bytes"`   // 最大缓存总大小（字节）
	DefaultTTL      time.Duration `json:"default_ttl"`      // 默认TTL
	RespectUpstream bool          `json:"respect_upstream"` // 是否遵循上游的Cache-Control
	MinFileSize     int64         `json:"min_file_size"`    // 最小缓存文件大小（字节）
	MaxFileSize     int64         `json:"max_file_size"`    // 最大缓存文件大小（字节）
	CacheableTypes  []string      `json:"cacheable_types"`  // 可缓存的Content-Type列表
}

// AISecurityConfig AI 安全分析配置
type AISecurityConfig struct {
	Enabled       bool          `json:"enabled"`        // 是否启用 AI 安全分析
	APIKey        string        `json:"api_key"`        // OpenAI API Key
	APIEndpoint   string        `json:"api_endpoint"`   // API 端点（可选，默认 OpenAI）
	Model         string        `json:"model"`          // 使用的模型（默认 gpt-4o-mini）
	CheckInterval time.Duration `json:"check_interval"` // 检查间隔（默认 1 小时）
	MaxTokens     int           `json:"max_tokens"`     // 最大 token 数（默认 3000）
	Temperature   float64       `json:"temperature"`    // 温度参数（默认 0.3）
	Language      string        `json:"language"`       // 分析和通知使用的语言（zh-CN/en-US，默认 zh-CN）

	// 分析范围配置
	AnalysisWindow time.Duration `json:"analysis_window"` // 分析时间窗口（默认 1 小时）
	MinEvents      int           `json:"min_events"`      // 最少事件数才进行分析（默认 10）

	// 通知配置
	NotifyOnThreat bool   `json:"notify_on_threat"` // 检测到威胁时是否通知（默认 true）
	MinThreatLevel string `json:"min_threat_level"` // 最低通知威胁等级（low/medium/high/critical）
}

// ImageOptimizationConfig 图片优化配置
type ImageOptimizationConfig struct {
	Enabled bool `json:"enabled"` // 是否启用图片优化

	// 格式转换
	AutoWebP      bool `json:"auto_webp"`        // 自动转换为 WebP
	WebPQuality   int  `json:"webp_quality"`     // WebP 质量 (0-100，默认 80)
	WebPMinSizeKB int  `json:"webp_min_size_kb"` // WebP 转换最小文件大小 (KB，默认 200)
	JPEGQuality   int  `json:"jpeg_quality"`     // JPEG 质量 (0-100，默认 85)
	PNGLevel      int  `json:"png_level"`        // PNG 压缩级别 (0-9，默认 6)
	StripMetadata bool `json:"strip_metadata"`   // 移除 EXIF 元数据

	// 文件大小限制（优化 CPU 使用）
	MinSizeBytes int64 `json:"min_size_bytes"` // 最小文件大小（字节，默认 60KB）
	MaxSizeBytes int64 `json:"max_size_bytes"` // 最大文件大小（字节，默认 5MB）

	// 尺寸调整
	AllowResize  bool  `json:"allow_resize"`  // 允许尺寸调整
	MaxWidth     int   `json:"max_width"`     // 最大宽度（默认 2000）
	MaxHeight    int   `json:"max_height"`    // 最大高度（默认 2000）
	AllowedSizes []int `json:"allowed_sizes"` // 允许的尺寸列表

	// 缓存
	CacheEnabled bool  `json:"cache_enabled"`  // 启用缓存
	CacheTTL     int   `json:"cache_ttl"`      // 缓存TTL（秒，默认 86400）
	MaxCacheSize int64 `json:"max_cache_size"` // 最大缓存大小（字节，默认 1GB）

	// 过滤器
	IncludePatterns []string `json:"include_patterns"` // 包含的路径模式
	ExcludePatterns []string `json:"exclude_patterns"` // 排除的路径模式
}

// migratePortConfig 迁移旧的端口配置到新的配置结构
func migratePortConfig(config *Config) {
	// 如果 PortMode 为空，说明是旧配置，需要迁移
	if config.Server.PortMode == "" {
		if config.Server.Port == 443 {
			// 原来是 443 端口，迁移到标准模式
			config.Server.PortMode = "standard"
			config.Server.EnableHTTPS = true
		} else {
			// 其他端口，迁移到自定义模式
			config.Server.PortMode = "custom"
			config.Server.CustomPort = config.Server.Port
			config.Server.EnableHTTPS = false
		}
	}
}

// MigrateToUnifiedBackends 迁移到统一后端配置
// 从旧的单后端或负载均衡配置迁移到新的统一后端数组
func (rule *ProxyRule) MigrateToUnifiedBackends() {
	// 如果已经有新的 backends 字段，直接返回
	if len(rule.Backends) > 0 {
		return
	}

	// 迁移逻辑：从旧字段到新字段
	if rule.LoadBalancerEnabled && len(rule.LoadBalancerBackends) > 0 {
		// 从负载均衡配置迁移
		rule.Backends = rule.LoadBalancerBackends
	} else if rule.Target != "" {
		// 从单后端配置迁移
		rule.Backends = []ProxyBackend{
			{
				ID:      fmt.Sprintf("%s_backend_1", rule.Domain),
				Host:    rule.Target,
				Port:    rule.Port,
				Weight:  1,
				Enabled: true,
			},
		}
	}
}

// PrepareForSave 准备保存配置时的静默升级
// 确保使用新的统一后端格式，同时保持向后兼容
func (rule *ProxyRule) PrepareForSave() {
	// 确保 backends 字段有值
	if len(rule.Backends) == 0 {
		rule.MigrateToUnifiedBackends()
	}

	// 根据 backends 数量设置负载均衡状态（保持兼容性）
	if len(rule.Backends) > 1 {
		rule.LoadBalancerEnabled = true
		if rule.LoadBalancerAlgorithm == "" {
			rule.LoadBalancerAlgorithm = "round_robin"
		}
		// 同步到旧字段以保持兼容性
		rule.LoadBalancerBackends = rule.Backends
	} else {
		rule.LoadBalancerEnabled = false
		// 同步到旧字段以保持兼容性
		if len(rule.Backends) == 1 {
			rule.Target = rule.Backends[0].Host
			rule.Port = rule.Backends[0].Port
		}
	}
}

// GetEffectiveBackends 获取有效的后端列表
// 优先使用新的 backends 字段，如果没有则从旧字段迁移
func (rule *ProxyRule) GetEffectiveBackends() []ProxyBackend {
	if len(rule.Backends) > 0 {
		return rule.Backends
	}

	// 如果没有新字段，尝试迁移
	rule.MigrateToUnifiedBackends()
	return rule.Backends
}

// IsLoadBalanced 判断是否启用负载均衡
// 基于后端数量自动判断，但如果存在HTTPS URL后端则不启用负载均衡
func (rule *ProxyRule) IsLoadBalanced() bool {
	backends := rule.GetEffectiveBackends()
	if len(backends) <= 1 {
		return false
	}

	// 检查是否存在HTTPS URL后端（非IP地址）
	// 如果存在HTTPS URL后端，即使有多个后端也不启用负载均衡
	for _, backend := range backends {
		if isHTTPSURL(backend.Host) {
			return false
		}
	}

	return true
}

// isHTTPSURL 检查后端主机是否为HTTPS URL（非IP地址）
func isHTTPSURL(host string) bool {
	// 检查是否以 https:// 开头
	if !strings.HasPrefix(strings.ToLower(host), "https://") {
		return false
	}

	// 解析URL
	parsedURL, err := url.Parse(host)
	if err != nil {
		return false
	}

	// 提取主机名（去除端口）
	hostname := parsedURL.Hostname()
	if hostname == "" {
		return false
	}

	// 检查主机名是否为IP地址
	return net.ParseIP(hostname) == nil
}

// MatchesPath 检查请求路径是否匹配规则
// 支持路径前缀匹配，用于静态站点、PHP站点和代理转发
func (rule *ProxyRule) MatchesPath(requestPath string) bool {
	// 如果没有配置路径前缀，匹配所有路径
	if len(rule.PathPrefixes) == 0 {
		return true
	}

	// 检查请求路径是否匹配任何一个前缀
	for _, prefix := range rule.PathPrefixes {
		if rule.PathExact {
			// 精确匹配：路径必须完全等于前缀
			if requestPath == prefix {
				return true
			}
		} else {
			// 前缀匹配：路径必须以指定前缀开头
			if strings.HasPrefix(requestPath, prefix) {
				return true
			}
		}
	}

	return false
}

// GetMatchedPrefix 获取匹配的路径前缀
// 返回第一个匹配的前缀，如果没有匹配则返回空字符串
func (rule *ProxyRule) GetMatchedPrefix(requestPath string) string {
	if len(rule.PathPrefixes) == 0 {
		return ""
	}

	for _, prefix := range rule.PathPrefixes {
		if rule.PathExact {
			if requestPath == prefix {
				return prefix
			}
		} else {
			if strings.HasPrefix(requestPath, prefix) {
				return prefix
			}
		}
	}

	return ""
}

// MatchesPath 检查请求路径是否匹配静态站点规则
func (site *StaticSite) MatchesPath(requestPath string) bool {
	// 如果没有配置路径前缀，匹配所有路径
	if len(site.PathPrefixes) == 0 {
		return true
	}

	// 检查请求路径是否匹配任何一个前缀
	for _, prefix := range site.PathPrefixes {
		if site.PathExact {
			// 精确匹配：路径必须完全等于前缀
			if requestPath == prefix {
				return true
			}
		} else {
			// 前缀匹配：路径必须以指定前缀开头
			if strings.HasPrefix(requestPath, prefix) {
				return true
			}
		}
	}

	return false
}

// MatchesPath 检查请求路径是否匹配PHP站点规则
func (site *PHPSite) MatchesPath(requestPath string) bool {
	// 如果没有配置路径前缀，匹配所有路径
	if len(site.PathPrefixes) == 0 {
		return true
	}

	// 检查请求路径是否匹配任何一个前缀
	for _, prefix := range site.PathPrefixes {
		if site.PathExact {
			// 精确匹配：路径必须完全等于前缀
			if requestPath == prefix {
				return true
			}
		} else {
			// 前缀匹配：路径必须以指定前缀开头
			if strings.HasPrefix(requestPath, prefix) {
				return true
			}
		}
	}

	return false
}

// migrateProxyRules 迁移所有代理规则到统一后端格式
func (c *Config) migrateProxyRules() {
	for i := range c.Proxy.Rules {
		c.Proxy.Rules[i].MigrateToUnifiedBackends()
	}
}

// prepareProxyRulesForSave 准备保存配置时的静默升级
func (c *Config) prepareProxyRulesForSave() {
	for i := range c.Proxy.Rules {
		c.Proxy.Rules[i].PrepareForSave()
	}
}

// MatchesPath 检查请求路径是否匹配路径前缀规则
func (rule *PathPrefixRule) MatchesPath(requestPath string) bool {
	if !rule.Enabled {
		return false
	}

	// 检查请求路径是否匹配任何一个前缀
	for _, prefix := range rule.Prefixes {
		if rule.Exact {
			// 精确匹配：路径必须完全等于前缀
			if requestPath == prefix {
				return true
			}
		} else {
			// 前缀匹配：路径必须以指定前缀开头
			if strings.HasPrefix(requestPath, prefix) {
				return true
			}
		}
	}

	return false
}

// GetMatchedPrefix 获取匹配的路径前缀
func (rule *PathPrefixRule) GetMatchedPrefix(requestPath string) string {
	if !rule.Enabled {
		return ""
	}

	for _, prefix := range rule.Prefixes {
		if rule.Exact {
			if requestPath == prefix {
				return prefix
			}
		} else {
			if strings.HasPrefix(requestPath, prefix) {
				return prefix
			}
		}
	}

	return ""
}

// MonitoringConfig 监控配置
type MonitoringConfig struct {
	Enabled                  bool    `json:"enabled"`
	MemoryMaxUsagePercent    float64 `json:"memory_max_usage_percent"`    // 触发内存释放的系统占用百分比
	MemoryReleaseCooldownSec int     `json:"memory_release_cooldown_sec"` // 内存释放冷却时间（秒）

	// 看门狗监控配置
	WatchdogEnabled                     bool    `json:"watchdog_enabled"`                        // 是否启用看门狗
	WatchdogCheckIntervalSec            int     `json:"watchdog_check_interval_sec"`             // 检查间隔（秒，默认30）
	WatchdogCPUThresholdPercent         float64 `json:"watchdog_cpu_threshold_percent"`          // CPU绝对阈值（默认30%）
	WatchdogCPUIncreaseThresholdPercent float64 `json:"watchdog_cpu_increase_threshold_percent"` // CPU增长阈值（默认15%）
	WatchdogCPUIncreaseWindowSec        int     `json:"watchdog_cpu_increase_window_sec"`        // 增长检测时间窗口（默认180秒，即3分钟）
	WatchdogAlertCooldownSec            int     `json:"watchdog_alert_cooldown_sec"`             // 报警冷却时间（默认3600秒，即1小时）
	// 内存监控配置
	WatchdogMemoryThresholdMB         int64   `json:"watchdog_memory_threshold_mb"`          // 内存绝对阈值（MB，0表示禁用）
	WatchdogMemoryThresholdPercent    float64 `json:"watchdog_memory_threshold_percent"`     // 内存占用百分比阈值（0表示禁用）
	WatchdogMemoryIncreaseThresholdMB int64   `json:"watchdog_memory_increase_threshold_mb"` // 内存增长阈值（MB，0表示禁用）
	WatchdogMemoryIncreaseWindowSec   int     `json:"watchdog_memory_increase_window_sec"`   // 内存增长检测窗口（秒）
	// 自动退出配置
	WatchdogExitOnMemoryThreshold bool `json:"watchdog_exit_on_memory_threshold"` // 达到内存阈值时自动退出（由systemd重启）
	WatchdogExitOnCPUThreshold    bool `json:"watchdog_exit_on_cpu_threshold"`    // 达到CPU阈值时自动退出（由systemd重启）

	// 指标存储配置
	MetricsStorage MetricsStorageConfig `json:"metrics_storage"`
}

// MetricsStorageConfig 指标存储配置
type MetricsStorageConfig struct {
	Enabled             bool `json:"enabled"`               // 是否启用指标存储
	SamplingInterval    int  `json:"sampling_interval"`     // 采样间隔（分钟，默认15）
	RetentionDays       int  `json:"retention_days"`        // 数据保留天数（默认90）
	DetailRetentionDays int  `json:"detail_retention_days"` // 详细数据保留天数（默认7，超过此天数后聚合为天数据）
	MaxRows             int  `json:"max_rows"`              // 最大行数限制（默认10000）
}

// CacheWarmupConfig 缓存预热配置
type CacheWarmupConfig struct {
	Enabled  bool     `json:"enabled"`  // 是否启用缓存预热
	URLs     []string `json:"urls"`     // 需要预热的URL列表
	Interval int      `json:"interval"` // 预热间隔（分钟）
	BaseURL  string   `json:"base_url"` // 基础URL（可选，默认自动检测）
}

// ReportConfig 报告生成配置
type ReportConfig struct {
	Enabled bool                `json:"enabled"` // 是否启用报告生成
	Daily   DailyReportConfig   `json:"daily"`   // 日报配置
	Weekly  WeeklyReportConfig  `json:"weekly"`  // 周报配置
	Monthly MonthlyReportConfig `json:"monthly"` // 月报配置
	AI      ReportAIConfig      `json:"ai"`      // AI报告配置
}

// DailyReportConfig 日报配置
type DailyReportConfig struct {
	Enabled bool   `json:"enabled"` // 是否启用日报
	Time    string `json:"time"`    // 生成时间（格式: "HH:MM"，默认 "02:00"）
}

// WeeklyReportConfig 周报配置
type WeeklyReportConfig struct {
	Enabled bool   `json:"enabled"` // 是否启用周报
	Day     string `json:"day"`     // 生成日期（monday/tuesday/...，默认 "monday"）
	Time    string `json:"time"`    // 生成时间（格式: "HH:MM"，默认 "02:00"）
}

// MonthlyReportConfig 月报配置
type MonthlyReportConfig struct {
	Enabled bool   `json:"enabled"` // 是否启用月报
	Day     int    `json:"day"`     // 生成日期（每月几号，1-31，默认 1）
	Time    string `json:"time"`    // 生成时间（格式: "HH:MM"，默认 "02:00"）
}

// ReportAIConfig AI报告配置
type ReportAIConfig struct {
	Enabled     bool    `json:"enabled"`      // 是否启用AI报告生成
	APIKey      string  `json:"api_key"`      // OpenAI API Key（如果为空，使用ai_security的配置）
	APIEndpoint string  `json:"api_endpoint"` // API 端点（如果为空，使用ai_security的配置）
	Model       string  `json:"model"`        // 使用的模型（默认 gpt-4o-mini）
	MaxTokens   int     `json:"max_tokens"`   // 最大 token 数（默认 2000）
	Temperature float64 `json:"temperature"`  // 温度参数（默认 0.3）
	Language    string  `json:"language"`     // 报告语言（zh-CN/en-US，默认 zh-CN）
}
