package mcp

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// PromMetrics 实现 MetricsRecorder，使用全局 prometheus 默认 registry。
//
// 指标：
//   sslcat_mcp_requests_total{tool,status}
//   sslcat_mcp_request_duration_seconds{tool}     histogram
//   sslcat_mcp_destructive_pending_confirmations  gauge
type PromMetrics struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	pending  prometheus.Gauge
}

var (
	promMetricsOnce sync.Once
	promMetricsInst *PromMetrics
)

// NewPromMetrics 返回单例 PromMetrics。重复调用安全（同一进程只注册一次）。
//
// 如果在测试或集成场景下默认 registry 已被替换或不可用，会优雅降级为不注册（返回的 metrics 仍可调用，
// 只是不会出现在 /metrics 端点上）。
func NewPromMetrics() *PromMetrics {
	promMetricsOnce.Do(func() {
		m := &PromMetrics{
			requests: prometheus.NewCounterVec(prometheus.CounterOpts{
				Namespace: "sslcat",
				Subsystem: "mcp",
				Name:      "requests_total",
				Help:      "MCP tool 调用总次数（按 tool 名与状态分组）。status 取值：ok / tool_error / error / forbidden / pending_confirm",
			}, []string{"tool", "status"}),
			duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Namespace: "sslcat",
				Subsystem: "mcp",
				Name:      "request_duration_seconds",
				Help:      "MCP tool 调用耗时（秒）。",
				Buckets:   prometheus.DefBuckets,
			}, []string{"tool"}),
			pending: prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace: "sslcat",
				Subsystem: "mcp",
				Name:      "destructive_pending_confirmations",
				Help:      "当前等待二次确认的 destructive tool 调用数量。",
			}),
		}
		// 注册到默认 registry；重复注册时静默失败（其它包可能也已注册过同名）。
		if err := prometheus.Register(m.requests); err != nil {
			if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
				m.requests = are.ExistingCollector.(*prometheus.CounterVec)
			}
		}
		if err := prometheus.Register(m.duration); err != nil {
			if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
				m.duration = are.ExistingCollector.(*prometheus.HistogramVec)
			}
		}
		if err := prometheus.Register(m.pending); err != nil {
			if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
				m.pending = are.ExistingCollector.(prometheus.Gauge)
			}
		}
		promMetricsInst = m
	})
	return promMetricsInst
}

// ObserveToolCall 实现 MetricsRecorder。
func (m *PromMetrics) ObserveToolCall(tool, status string, latencySec float64) {
	if m == nil {
		return
	}
	m.requests.WithLabelValues(tool, status).Inc()
	m.duration.WithLabelValues(tool).Observe(latencySec)
}

// SetPendingConfirmations 实现 MetricsRecorder。
func (m *PromMetrics) SetPendingConfirmations(n int) {
	if m == nil {
		return
	}
	m.pending.Set(float64(n))
}
