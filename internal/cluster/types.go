package cluster

// MasterConfig Master节点配置结构
type MasterConfig struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	AuthKey       string `json:"auth_key"`
	Timeout       int    `json:"timeout"`
	RetryInterval int    `json:"retry_interval"`
}

// SyncConfig 同步配置结构
type SyncConfig struct {
	ConfigEnabled  bool     `json:"config_enabled"`
	CertEnabled    bool     `json:"cert_enabled"`
	Interval       int      `json:"interval"`
	Timeout        int      `json:"timeout"`
	ExcludeConfigs []string `json:"exclude_configs"`
}
