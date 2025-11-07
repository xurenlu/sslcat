package tunnel

import "github.com/xurenlu/sslcat/internal/config"

// CommandSpec 描述启动外部 CLI 进程所需的命令信息
type CommandSpec struct {
	Executable string
	Args       []string
	Env        []string
	WorkDir    string
}

// ProviderAdapter 定义不同隧道提供商的 CLI 适配器接口
type ProviderAdapter interface {
	Prepare(provider config.TunnelProviderConfig, tunnel config.TunnelDefinition, runtimeDir string) (*CommandSpec, error)
}

