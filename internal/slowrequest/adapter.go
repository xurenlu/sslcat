package slowrequest

import (
	"net/http"
	"time"
)

// Adapter 慢请求管理器适配器，实现代理管理器的 SlowRequestRecorder 接口
type Adapter struct {
	manager *Manager
}

// NewAdapter 创建慢请求管理器适配器
func NewAdapter(manager *Manager) *Adapter {
	return &Adapter{
		manager: manager,
	}
}

// RecordSlowRequest 记录慢请求
func (a *Adapter) RecordSlowRequest(r *http.Request, statusCode int, responseTime time.Duration, backendID, backendAddr, target, ruleName string, contentSize int64, err error) {
	record := a.manager.CreateRecordFromHTTP(r, statusCode, responseTime, backendID, backendAddr, target, ruleName, contentSize, err)
	a.manager.RecordSlowRequest(record)
}

// IsSlowRequest 判断是否为慢请求
func (a *Adapter) IsSlowRequest(responseTime time.Duration) bool {
	return a.manager.IsSlowRequest(responseTime)
}
