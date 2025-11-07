package tunnel

import "errors"

var (
	// ErrProviderNotFound 当指定的隧道提供商不存在时返回
	ErrProviderNotFound = errors.New("tunnel provider not found")
	// ErrProviderDisabled 当提供商被禁用时返回
	ErrProviderDisabled = errors.New("tunnel provider is disabled")
	// ErrTunnelNotFound 当指定的隧道不存在时返回
	ErrTunnelNotFound = errors.New("tunnel definition not found")
	// ErrInvalidConfig 当配置无效时返回
	ErrInvalidConfig = errors.New("invalid tunnel configuration")
	// ErrAlreadyRunning 当隧道已经在运行时返回
	ErrAlreadyRunning = errors.New("tunnel is already running")
	// ErrNotRunning 当隧道未运行时返回
	ErrNotRunning = errors.New("tunnel is not running")
	// ErrCLIUnavailable 当 CLI 工具缺失或不可执行时返回
	ErrCLIUnavailable = errors.New("tunnel CLI tool not found or not executable")
	// ErrProcessFailed 当隧道进程启动失败或运行异常时返回
	ErrProcessFailed = errors.New("tunnel process failed to start or encountered an error")
)
