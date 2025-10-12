package tracing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// TraceContext 追踪上下文
type TraceContext struct {
	TraceID   string            `json:"trace_id"`   // 全局追踪ID
	SpanID    string            `json:"span_id"`    // 当前Span ID
	ParentID  string            `json:"parent_id"`  // 父Span ID
	RequestID string            `json:"request_id"` // 请求ID（兼容性）
	StartTime time.Time         `json:"start_time"`
	Service   string            `json:"service"`
	Operation string            `json:"operation"`
	Tags      map[string]string `json:"tags"`
	Baggage   map[string]string `json:"baggage"` // 跨服务传递的键值对
}

// Span 追踪Span
type Span struct {
	Context      *TraceContext
	StartTime    time.Time
	EndTime      time.Time
	Duration     time.Duration
	Success      bool
	ErrorMessage string
	Events       []SpanEvent
	mu           sync.RWMutex
}

// SpanEvent Span事件
type SpanEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	Name      string            `json:"name"`
	Attrs     map[string]string `json:"attributes"`
}

// Tracer 追踪器
type Tracer struct {
	serviceName string
	sampler     Sampler
	reporter    Reporter
	log         *logrus.Entry
	mu          sync.RWMutex
}

// Sampler 采样器接口
type Sampler interface {
	ShouldSample(traceID string) bool
}

// Reporter 报告器接口
type Reporter interface {
	Report(span *Span)
}

// AlwaysSampler 总是采样
type AlwaysSampler struct{}

func (AlwaysSampler) ShouldSample(traceID string) bool {
	return true
}

// RateSampler 比率采样器
type RateSampler struct {
	rate float64
}

func NewRateSampler(rate float64) *RateSampler {
	return &RateSampler{rate: rate}
}

func (rs *RateSampler) ShouldSample(traceID string) bool {
	// 使用 traceID 的最后一个字节决定是否采样
	if len(traceID) < 2 {
		return false
	}
	
	b, err := hex.DecodeString(traceID[len(traceID)-2:])
	if err != nil {
		return false
	}
	
	threshold := uint8(rs.rate * 255)
	return b[0] < threshold
}

// LogReporter 日志报告器
type LogReporter struct {
	log *logrus.Entry
}

func NewLogReporter() *LogReporter {
	return &LogReporter{
		log: logrus.WithField("component", "tracing_reporter"),
	}
}

func (lr *LogReporter) Report(span *Span) {
	lr.log.WithFields(logrus.Fields{
		"trace_id":  span.Context.TraceID,
		"span_id":   span.Context.SpanID,
		"parent_id": span.Context.ParentID,
		"operation": span.Context.Operation,
		"duration":  span.Duration.Milliseconds(),
		"success":   span.Success,
	}).Info("Span completed")
}

// NewTracer 创建追踪器
func NewTracer(serviceName string, sampler Sampler, reporter Reporter) *Tracer {
	if sampler == nil {
		sampler = AlwaysSampler{}
	}
	if reporter == nil {
		reporter = NewLogReporter()
	}

	return &Tracer{
		serviceName: serviceName,
		sampler:     sampler,
		reporter:    reporter,
		log: logrus.WithFields(logrus.Fields{
			"component": "tracer",
		}),
	}
}

// generateID 生成唯一ID
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 降级方案：使用时间戳
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// StartSpan 开始新的Span
func (t *Tracer) StartSpan(ctx context.Context, operation string) (*Span, context.Context) {
	// 尝试从context中提取父Span
	parentSpan, _ := ctx.Value(spanContextKey).(*Span)

	traceID := generateID()
	parentID := ""
	
	// 如果有父Span，使用相同的TraceID
	if parentSpan != nil {
		traceID = parentSpan.Context.TraceID
		parentID = parentSpan.Context.SpanID
	}

	spanID := generateID()
	requestID := traceID[:16] // RequestID使用TraceID的前16个字符
	
	traceCtx := &TraceContext{
		TraceID:   traceID,
		SpanID:    spanID,
		ParentID:  parentID,
		RequestID: requestID,
		StartTime: time.Now(),
		Service:   t.serviceName,
		Operation: operation,
		Tags:      make(map[string]string),
		Baggage:   make(map[string]string),
	}

	// 从父Span继承Baggage
	if parentSpan != nil {
		for k, v := range parentSpan.Context.Baggage {
			traceCtx.Baggage[k] = v
		}
	}

	span := &Span{
		Context:   traceCtx,
		StartTime: time.Now(),
		Events:    make([]SpanEvent, 0),
	}

	// 将Span放入context
	newCtx := context.WithValue(ctx, spanContextKey, span)

	return span, newCtx
}

// StartSpanFromHTTPRequest 从HTTP请求开始Span
func (t *Tracer) StartSpanFromHTTPRequest(r *http.Request) (*Span, context.Context) {
	ctx := r.Context()

	// 尝试从HTTP头中提取追踪信息（支持多种标准）
	traceID := extractTraceID(r)
	spanID := extractSpanID(r)
	
	if traceID == "" {
		traceID = generateID()
	}
	if spanID == "" {
		spanID = generateID()
	}

	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = traceID[:16]
	}

	traceCtx := &TraceContext{
		TraceID:   traceID,
		SpanID:    spanID,
		ParentID:  extractParentID(r),
		RequestID: requestID,
		StartTime: time.Now(),
		Service:   t.serviceName,
		Operation: fmt.Sprintf("%s %s", r.Method, r.URL.Path),
		Tags: map[string]string{
			"http.method":      r.Method,
			"http.url":         r.URL.String(),
			"http.host":        r.Host,
			"http.user_agent":  r.UserAgent(),
			"http.remote_addr": r.RemoteAddr,
		},
		Baggage: extractBaggage(r),
	}

	span := &Span{
		Context:   traceCtx,
		StartTime: time.Now(),
		Events:    make([]SpanEvent, 0),
		Success:   true,
	}

	newCtx := context.WithValue(ctx, spanContextKey, span)
	return span, newCtx
}

// extractTraceID 从HTTP请求中提取TraceID
func extractTraceID(r *http.Request) string {
	// 按优先级尝试不同的标准
	headers := []string{
		"X-Trace-ID",                  // 自定义标准
		"X-B3-TraceId",                // Zipkin B3
		"traceparent",                 // W3C Trace Context
		"X-Cloud-Trace-Context",       // Google Cloud
		"X-Amzn-Trace-Id",             // AWS X-Ray
	}

	for _, header := range headers {
		if value := r.Header.Get(header); value != "" {
			// W3C Trace Context 格式: version-trace_id-span_id-flags
			if header == "traceparent" {
				parts := strings.Split(value, "-")
				if len(parts) >= 2 {
					return parts[1]
				}
			}
			// AWS X-Ray 格式: Root=1-5e645f3e-1234567890abcdef;...
			if header == "X-Amzn-Trace-Id" {
				parts := strings.Split(value, ";")
				for _, part := range parts {
					if strings.HasPrefix(part, "Root=") {
						return strings.TrimPrefix(part, "Root=")
					}
				}
			}
			return value
		}
	}

	return ""
}

// extractSpanID 从HTTP请求中提取SpanID
func extractSpanID(r *http.Request) string {
	headers := []string{
		"X-Span-ID",
		"X-B3-SpanId",
	}

	for _, header := range headers {
		if value := r.Header.Get(header); value != "" {
			return value
		}
	}

	// 从 W3C Trace Context 中提取
	if traceparent := r.Header.Get("traceparent"); traceparent != "" {
		parts := strings.Split(traceparent, "-")
		if len(parts) >= 3 {
			return parts[2]
		}
	}

	return ""
}

// extractParentID 从HTTP请求中提取ParentID
func extractParentID(r *http.Request) string {
	if value := r.Header.Get("X-Parent-ID"); value != "" {
		return value
	}
	if value := r.Header.Get("X-B3-ParentSpanId"); value != "" {
		return value
	}
	return ""
}

// extractBaggage 从HTTP请求中提取Baggage
func extractBaggage(r *http.Request) map[string]string {
	baggage := make(map[string]string)

	// W3C Baggage
	if value := r.Header.Get("baggage"); value != "" {
		pairs := strings.Split(value, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) == 2 {
				baggage[kv[0]] = kv[1]
			}
		}
	}

	// OpenTelemetry Baggage
	for key, values := range r.Header {
		if strings.HasPrefix(key, "Baggage-") {
			baggage[strings.TrimPrefix(key, "Baggage-")] = values[0]
		}
	}

	return baggage
}

// InjectHTTPHeaders 将追踪信息注入HTTP头
func (s *Span) InjectHTTPHeaders(header http.Header) {
	header.Set("X-Request-ID", s.Context.RequestID)
	header.Set("X-Trace-ID", s.Context.TraceID)
	header.Set("X-Span-ID", s.Context.SpanID)
	if s.Context.ParentID != "" {
		header.Set("X-Parent-ID", s.Context.ParentID)
	}

	// W3C Trace Context 格式
	header.Set("traceparent", fmt.Sprintf("00-%s-%s-01",
		s.Context.TraceID,
		s.Context.SpanID))

	// Zipkin B3 格式
	header.Set("X-B3-TraceId", s.Context.TraceID)
	header.Set("X-B3-SpanId", s.Context.SpanID)
	if s.Context.ParentID != "" {
		header.Set("X-B3-ParentSpanId", s.Context.ParentID)
	}

	// Baggage
	if len(s.Context.Baggage) > 0 {
		var pairs []string
		for k, v := range s.Context.Baggage {
			pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
		}
		header.Set("baggage", strings.Join(pairs, ","))
	}
}

// SetTag 设置标签
func (s *Span) SetTag(key, value string) *Span {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Context.Tags[key] = value
	return s
}

// SetBaggage 设置Baggage（会传播到下游服务）
func (s *Span) SetBaggage(key, value string) *Span {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Context.Baggage[key] = value
	return s
}

// AddEvent 添加事件
func (s *Span) AddEvent(name string, attrs map[string]string) *Span {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, SpanEvent{
		Timestamp: time.Now(),
		Name:      name,
		Attrs:     attrs,
	})
	return s
}

// SetError 设置错误
func (s *Span) SetError(err error) *Span {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Success = false
	if err != nil {
		s.ErrorMessage = err.Error()
		s.Context.Tags["error"] = "true"
		s.Context.Tags["error.message"] = err.Error()
	}
	return s
}

// Finish 完成Span
func (s *Span) Finish() {
	s.EndTime = time.Now()
	s.Duration = s.EndTime.Sub(s.StartTime)
}

// spanContextKey context中span的key
type contextKey string

const spanContextKey contextKey = "span"

// SpanFromContext 从context中获取Span
func SpanFromContext(ctx context.Context) *Span {
	if span, ok := ctx.Value(spanContextKey).(*Span); ok {
		return span
	}
	return nil
}

// TracingMiddleware HTTP追踪中间件
func TracingMiddleware(tracer *Tracer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			span, ctx := tracer.StartSpanFromHTTPRequest(r)
			defer func() {
				span.Finish()
				if tracer.sampler.ShouldSample(span.Context.TraceID) {
					tracer.reporter.Report(span)
				}
			}()

			// 将追踪信息注入响应头
			span.InjectHTTPHeaders(w.Header())

			// 包装ResponseWriter以捕获状态码
			wrappedWriter := &responseWriter{
				ResponseWriter: w,
				statusCode:     200,
			}

			// 使用新的context处理请求
			next.ServeHTTP(wrappedWriter, r.WithContext(ctx))

			// 记录响应状态
			span.SetTag("http.status_code", fmt.Sprintf("%d", wrappedWriter.statusCode))
			if wrappedWriter.statusCode >= 400 {
				span.Success = false
				span.ErrorMessage = fmt.Sprintf("HTTP %d", wrappedWriter.statusCode)
			}
		})
	}
}

// responseWriter 包装http.ResponseWriter以捕获状态码
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.statusCode = statusCode
		rw.written = true
		rw.ResponseWriter.WriteHeader(statusCode)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(200)
	}
	return rw.ResponseWriter.Write(b)
}

