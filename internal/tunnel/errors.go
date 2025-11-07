package tunnel

import "errors"

var (
	// ErrProviderNotFound 当指定的隧道提供商不存在时返回
	ErrProviderNotFound = errors.New("tunnel provider not found")
	// ErrTunnelNotFound 当指定的隧道不存在时返回
	ErrTunnelNotFound = errors.New("tunnel definition not found")
)
