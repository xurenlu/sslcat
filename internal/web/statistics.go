package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/statistics"
)

// StatisticsAPI 统计API处理器
type StatisticsAPI struct {
	collector *statistics.Collector
	server    *Server // 添加对 server 的引用，用于认证检查
	log       *logrus.Entry
}

// NewStatisticsAPI 创建统计API处理器
func NewStatisticsAPI(collector *statistics.Collector, server *Server) *StatisticsAPI {
	return &StatisticsAPI{
		collector: collector,
		server:    server,
		log: logrus.WithFields(logrus.Fields{
			"component": "statistics_api",
		}),
	}
}

// StatisticsRequest 统计请求参数
type StatisticsRequest struct {
	Dimension string `json:"dimension"` // hour, day, month
	TimeKey   string `json:"time_key"`  // 可选，格式根据dimension确定
	Domain    string `json:"domain"`    // 可选，指定域名，空则为所有域名
	TopN      int    `json:"top_n"`     // 可选，Top N数量，默认20
}

// StatisticsResponse 统计响应
type StatisticsResponse struct {
	Success bool                       `json:"success"`
	Message string                     `json:"message,omitempty"`
	Data    *statistics.StatisticsData `json:"data,omitempty"`
}

// ConfigRequest 配置请求参数
type ConfigRequest struct {
	Enabled      *bool `json:"enabled,omitempty"`
	TopN         *int  `json:"top_n,omitempty"`
	GeoIPEnabled *bool `json:"geoip_enabled,omitempty"`
}

// ConfigResponse 配置响应
type ConfigResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Config  map[string]interface{} `json:"config,omitempty"`
}

// handleStatistics 处理统计数据查询请求
func (s *StatisticsAPI) handleStatistics(w http.ResponseWriter, r *http.Request) {
	// 认证检查
	if s.server != nil && !s.server.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StatisticsRequest

	if r.Method == http.MethodPost {
		// POST 请求从 body 解析参数
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeErrorResponse(w, "解析请求参数失败", http.StatusBadRequest)
			return
		}
	} else {
		// GET 请求从查询参数解析
		req.Dimension = r.URL.Query().Get("dimension")
		req.TimeKey = r.URL.Query().Get("time_key")
		req.Domain = r.URL.Query().Get("domain")

		if topNStr := r.URL.Query().Get("top_n"); topNStr != "" {
			if topN, err := strconv.Atoi(topNStr); err == nil {
				req.TopN = topN
			}
		}
	}

	// 验证和设置默认值
	if err := s.validateAndSetDefaults(&req); err != nil {
		s.writeErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 转换维度类型
	var dimension statistics.TimeDimension
	switch req.Dimension {
	case "hour":
		dimension = statistics.DimensionHour
	case "day":
		dimension = statistics.DimensionDay
	case "month":
		dimension = statistics.DimensionMonth
	default:
		s.writeErrorResponse(w, "无效的时间维度", http.StatusBadRequest)
		return
	}

	// 设置TopN
	if req.TopN > 0 {
		s.collector.SetTopN(req.TopN)
	}

	// 获取统计数据
	data, err := s.collector.GetStatistics(dimension, req.TimeKey, req.Domain)
	if err != nil {
		s.log.WithError(err).Error("获取统计数据失败")
		s.writeErrorResponse(w, "获取统计数据失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 返回响应
	response := StatisticsResponse{
		Success: true,
		Data:    data,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("编码响应失败")
	}
}

// handleStatisticsConfig 处理统计配置请求
func (s *StatisticsAPI) handleStatisticsConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfig(w, r)
	case http.MethodPost:
		s.handleUpdateConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetConfig 处理获取配置请求
func (s *StatisticsAPI) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	// 认证检查（只读）
	if s.server != nil && !s.server.authorizeAPI(w, r, true) {
		return
	}

	config := s.collector.GetStats()

	response := ConfigResponse{
		Success: true,
		Config:  config,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("编码配置响应失败")
	}
}

// handleUpdateConfig 处理更新配置请求
func (s *StatisticsAPI) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	// 认证检查（写操作）
	if s.server != nil && !s.server.authorizeAPI(w, r, false) {
		return
	}

	var req ConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, "解析配置参数失败", http.StatusBadRequest)
		return
	}

	// 更新配置
	if req.Enabled != nil {
		s.collector.SetEnabled(*req.Enabled)
	}

	if req.TopN != nil && *req.TopN > 0 {
		s.collector.SetTopN(*req.TopN)
	}

	if req.GeoIPEnabled != nil {
		s.collector.SetGeoIPEnabled(*req.GeoIPEnabled)
	}

	// 返回更新后的配置
	config := s.collector.GetStats()

	response := ConfigResponse{
		Success: true,
		Message: "配置更新成功",
		Config:  config,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("编码配置响应失败")
	}
}

// handleTimeKeys 处理时间键列表请求
func (s *StatisticsAPI) handleTimeKeys(w http.ResponseWriter, r *http.Request) {
	// 认证检查（只读）
	if s.server != nil && !s.server.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dimension := r.URL.Query().Get("dimension")
	if dimension == "" {
		dimension = "hour"
	}

	timeKeys := s.generateTimeKeys(dimension)

	response := map[string]interface{}{
		"success":   true,
		"dimension": dimension,
		"time_keys": timeKeys,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("编码时间键响应失败")
	}
}

// generateTimeKeys 生成时间键列表
func (s *StatisticsAPI) generateTimeKeys(dimension string) []map[string]string {
	var timeKeys []map[string]string
	now := time.Now()

	switch dimension {
	case "hour":
		// 生成过去24小时的时间键
		for i := 0; i < 24; i++ {
			t := now.Add(-time.Duration(i) * time.Hour)
			key := t.Format("2006-01-02-15")
			label := t.Format("01-02 15:00")
			timeKeys = append(timeKeys, map[string]string{
				"key":   key,
				"label": label,
			})
		}

	case "day":
		// 生成过去30天的时间键
		for i := 0; i < 30; i++ {
			t := now.AddDate(0, 0, -i)
			key := t.Format("2006-01-02")
			label := t.Format("01-02")
			timeKeys = append(timeKeys, map[string]string{
				"key":   key,
				"label": label,
			})
		}

	case "month":
		// 生成过去12个月的时间键
		for i := 0; i < 12; i++ {
			t := now.AddDate(0, -i, 0)
			key := t.Format("2006-01")
			label := t.Format("2006-01")
			timeKeys = append(timeKeys, map[string]string{
				"key":   key,
				"label": label,
			})
		}
	}

	return timeKeys
}

// validateAndSetDefaults 验证并设置默认值
func (s *StatisticsAPI) validateAndSetDefaults(req *StatisticsRequest) error {
	// 设置默认维度
	if req.Dimension == "" {
		req.Dimension = "hour"
	}

	// 验证维度
	validDimensions := map[string]bool{
		"hour":  true,
		"day":   true,
		"month": true,
	}
	if !validDimensions[req.Dimension] {
		return fmt.Errorf("无效的时间维度: %s，支持的维度: hour, day, month", req.Dimension)
	}

	// 设置默认TopN
	if req.TopN <= 0 {
		req.TopN = 20
	}

	// 验证TopN范围
	if req.TopN > 100 {
		req.TopN = 100
	}

	return nil
}

// writeErrorResponse 写入错误响应
func (s *StatisticsAPI) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := StatisticsResponse{
		Success: false,
		Message: message,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("编码错误响应失败")
	}
}

// RegisterRoutes 注册统计API路由
func (s *StatisticsAPI) RegisterRoutes(mux *http.ServeMux, prefix string) {
	// 统计数据查询
	mux.HandleFunc(prefix+"/statistics", s.handleStatistics)

	// 统计配置管理
	mux.HandleFunc(prefix+"/statistics/config", s.handleStatisticsConfig)

	// 时间键列表
	mux.HandleFunc(prefix+"/statistics/time-keys", s.handleTimeKeys)

	s.log.Info("统计API路由已注册")
}

// RecordMiddleware 创建统计记录中间件
func (s *StatisticsAPI) RecordMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 包装ResponseWriter以捕获状态码和字节数
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
			written:        0,
		}

		// 处理请求
		next.ServeHTTP(wrapped, r)

		// 记录访问统计
		s.collector.RecordAccessFromHTTP(r, wrapped.statusCode)
	})
}

// responseWriter 包装ResponseWriter以捕获状态码和字节数
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int64
}

// Hijack 实现 http.Hijacker 接口，用于 WebSocket 升级
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("responseWriter does not implement http.Hijacker")
	}
	return hijacker.Hijack()
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.written += int64(n)
	return n, err
}
