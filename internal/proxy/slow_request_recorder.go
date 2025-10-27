package proxy

import (
	"net/http"
	"time"
)

// SlowRequestRecorder 慢请求记录器接口
type SlowRequestRecorder interface {
	RecordSlowRequest(r *http.Request, statusCode int, responseTime time.Duration, backendID, backendAddr, target, ruleName string, contentSize int64, err error)
	IsSlowRequest(responseTime time.Duration) bool
}

// NoOpSlowRequestRecorder 空操作的慢请求记录器
type NoOpSlowRequestRecorder struct{}

func (n *NoOpSlowRequestRecorder) RecordSlowRequest(r *http.Request, statusCode int, responseTime time.Duration, backendID, backendAddr, target, ruleName string, contentSize int64, err error) {
	// 空操作
}

func (n *NoOpSlowRequestRecorder) IsSlowRequest(responseTime time.Duration) bool {
	return false
}
