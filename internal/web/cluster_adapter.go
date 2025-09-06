package web

import (
	"github.com/xurenlu/sslcat/internal/cluster"
	"github.com/xurenlu/sslcat/internal/config"
)

// ConfigAdapter 配置适配器，将config.Config适配到cluster.Config接口
type ConfigAdapter struct {
	config *config.Config
}

// NewConfigAdapter 创建配置适配器
func NewConfigAdapter(cfg *config.Config) cluster.Config {
	return &ConfigAdapter{config: cfg}
}

func (a *ConfigAdapter) GetClusterMode() string {
	return a.config.Cluster.Mode
}

func (a *ConfigAdapter) GetNodeID() string {
	return a.config.Cluster.NodeID
}

func (a *ConfigAdapter) GetNodeName() string {
	return a.config.Cluster.NodeName
}

func (a *ConfigAdapter) GetMasterConfig() cluster.MasterConfig {
	return cluster.MasterConfig{
		Host:          a.config.Cluster.Master.Host,
		Port:          a.config.Cluster.Master.Port,
		AuthKey:       a.config.Cluster.Master.AuthKey,
		Timeout:       a.config.Cluster.Master.Timeout,
		RetryInterval: a.config.Cluster.Master.RetryInterval,
	}
}

func (a *ConfigAdapter) GetSyncConfig() cluster.SyncConfig {
	return cluster.SyncConfig{
		ConfigEnabled:  a.config.Cluster.Sync.ConfigEnabled,
		CertEnabled:    a.config.Cluster.Sync.CertEnabled,
		Interval:       a.config.Cluster.Sync.Interval,
		Timeout:        a.config.Cluster.Sync.Timeout,
		ExcludeConfigs: a.config.Cluster.Sync.ExcludeConfigs,
	}
}

func (a *ConfigAdapter) GetClusterPort() int {
	return a.config.Cluster.Port
}

func (a *ConfigAdapter) GetClusterAuthKey() string {
	return a.config.Cluster.AuthKey
}

func (a *ConfigAdapter) IsSlaveMode() bool {
	return a.config.Cluster.Mode == "slave"
}

func (a *ConfigAdapter) IsMasterMode() bool {
	return a.config.Cluster.Mode == "master"
}

func (a *ConfigAdapter) IsStandaloneMode() bool {
	return a.config.Cluster.Mode == "standalone" || a.config.Cluster.Mode == ""
}

func (a *ConfigAdapter) GetServicePort() int {
	return a.config.Server.Port
}

func (a *ConfigAdapter) GetCertDir() string {
	return a.config.SSL.CertDir
}

func (a *ConfigAdapter) GetProxyRules() []interface{} {
	rules := make([]interface{}, len(a.config.Proxy.Rules))
	for i, rule := range a.config.Proxy.Rules {
		rules[i] = rule
	}
	return rules
}

func (a *ConfigAdapter) GetSSLDomains() []string {
	return a.config.SSL.Domains
}
