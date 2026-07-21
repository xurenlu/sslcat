package config

// ServerConfig 服务器配置。
type ServerConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"` // 向后兼容，保留原字段
	Debug       bool   `json:"debug"`
	LogLevel    string `json:"log_level"`    // debug|info|warn|error
	EnablePprof bool   `json:"enable_pprof"` // 是否启用 pprof 性能分析端点
	PprofAddr   string `json:"pprof_addr"`   // pprof 独立监听地址，仅允许 loopback

	PortMode    string `json:"port_mode"`    // "standard" | "custom" (默认 "standard")
	CustomPort  int    `json:"custom_port"`  // 自定义端口（仅在 custom 模式生效）
	EnableHTTPS bool   `json:"enable_https"` // 是否启用 HTTPS（默认 true）

	// WebAuthn 依赖方配置。监听地址（如 0.0.0.0）不能作为公网 RP ID 使用。
	WebAuthnRPID     string `json:"webauthn_rp_id"`
	WebAuthnRPOrigin string `json:"webauthn_rp_origin"`

	HTTP2Enabled bool         `json:"http2_enabled"` // 是否启用 HTTP/2（默认 false）
	HTTP2Config  *HTTP2Config `json:"http2_config,omitempty"`
	HTTP3Enabled bool         `json:"http3_enabled"` // 是否启用 HTTP/3（默认 false）
	HTTP3Config  *HTTP3Config `json:"http3_config,omitempty"`

	AccessLogEnabled  bool   `json:"access_log_enabled"`
	AccessLogFormat   string `json:"access_log_format"` // nginx|apache|json
	AccessLogPath     string `json:"access_log_path"`
	AccessLogMaxSize  int64  `json:"access_log_max_size"` // bytes
	AccessLogMaxFiles int    `json:"access_log_max_files"`
	ErrorLogEnabled   bool   `json:"error_log_enabled"`
	ErrorLogPath      string `json:"error_log_path"`
	ErrorLogMaxSize   int64  `json:"error_log_max_size"` // bytes
	ErrorLogMaxFiles  int    `json:"error_log_max_files"`

	SharedCacheMaxSizeMB int    `json:"shared_cache_max_size_mb"`
	CacheBackendType     string `json:"cache_backend_type"` // bigcache/simple/auto（默认 simple）
	ReadTimeoutSec       int    `json:"read_timeout_sec"`
	WriteTimeoutSec      int    `json:"write_timeout_sec"`
	IdleTimeoutSec       int    `json:"idle_timeout_sec"`
	MaxUploadBytes       int64  `json:"max_upload_bytes"`

	SessionStorage string `json:"session_storage"` // memory|file（默认 file）
	DataDir        string `json:"data_dir"`
	SecretKey      string `json:"secret_key"`
}

// ProxyConfig 代理配置。
type ProxyConfig struct {
	Rules                           []ProxyRule `json:"rules"`
	UnmatchedBehavior               string      `json:"unmatched_behavior"`
	UnmatchedRedirectURL            string      `json:"unmatched_redirect_url"`
	DefaultResponseHeaderTimeoutSec int         `json:"default_response_header_timeout_sec"`
	MaxIdleConns                    int         `json:"max_idle_conns"`
	MaxIdleConnsPerHost             int         `json:"max_idle_conns_per_host"`
	MaxConnsPerHost                 int         `json:"max_conns_per_host"`
}
