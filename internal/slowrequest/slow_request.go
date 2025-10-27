package slowrequest

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// SlowRequestRecord 慢请求记录
type SlowRequestRecord struct {
	ID           string    `json:"id"`              // 唯一标识
	Timestamp    time.Time `json:"timestamp"`       // 请求时间
	Method       string    `json:"method"`          // HTTP方法
	URL          string    `json:"url"`             // 请求URL
	Host         string    `json:"host"`            // 请求Host
	Path         string    `json:"path"`            // 请求路径
	ClientIP     string    `json:"client_ip"`       // 客户端IP
	UserAgent    string    `json:"user_agent"`      // User-Agent
	StatusCode   int       `json:"status_code"`     // 响应状态码
	ResponseTime int64     `json:"response_time"`   // 响应时间(毫秒)
	BackendID    string    `json:"backend_id"`      // 后端ID
	BackendAddr  string    `json:"backend_addr"`    // 后端地址
	Target       string    `json:"target"`          // 代理目标
	RuleName     string    `json:"rule_name"`       // 规则名称
	ContentType  string    `json:"content_type"`    // 响应内容类型
	ContentSize  int64     `json:"content_size"`    // 响应内容大小
	Error        string    `json:"error,omitempty"` // 错误信息
}

// SlowRequestStats 慢请求统计
type SlowRequestStats struct {
	TotalSlowRequests   int64                `json:"total_slow_requests"`   // 总慢请求数
	AverageResponseTime float64              `json:"average_response_time"` // 平均响应时间
	SlowestResponseTime int64                `json:"slowest_response_time"` // 最慢响应时间
	SlowestRequest      *SlowRequestRecord   `json:"slowest_request"`       // 最慢请求记录
	ByStatusCode        map[int]int64        `json:"by_status_code"`        // 按状态码统计
	ByMethod            map[string]int64     `json:"by_method"`             // 按方法统计
	ByHost              map[string]int64     `json:"by_host"`               // 按Host统计
	ByBackend           map[string]int64     `json:"by_backend"`            // 按后端统计
	RecentSlowRequests  []*SlowRequestRecord `json:"recent_slow_requests"`  // 最近的慢请求
}

// Manager 慢请求管理器
type Manager struct {
	records    []*SlowRequestRecord
	maxRecords int
	threshold  time.Duration
	mutex      sync.RWMutex
	log        *logrus.Entry
	stats      *SlowRequestStats
}

// NewManager 创建慢请求管理器
func NewManager(maxRecords int, threshold time.Duration) *Manager {
	return &Manager{
		records:    make([]*SlowRequestRecord, 0, maxRecords),
		maxRecords: maxRecords,
		threshold:  threshold,
		log: logrus.WithFields(logrus.Fields{
			"component": "slow_request_manager",
		}),
		stats: &SlowRequestStats{
			ByStatusCode: make(map[int]int64),
			ByMethod:     make(map[string]int64),
			ByHost:       make(map[string]int64),
			ByBackend:    make(map[string]int64),
		},
	}
}

// RecordSlowRequest 记录慢请求
func (m *Manager) RecordSlowRequest(record *SlowRequestRecord) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 添加到记录列表
	m.records = append(m.records, record)

	// 如果超过最大记录数，移除最旧的记录
	if len(m.records) > m.maxRecords {
		m.records = m.records[1:]
	}

	// 更新统计信息
	m.updateStats(record)

	m.log.WithFields(logrus.Fields{
		"id":            record.ID,
		"method":        record.Method,
		"url":           record.URL,
		"response_time": record.ResponseTime,
		"status_code":   record.StatusCode,
	}).Debug("记录慢请求")
}

// updateStats 更新统计信息
func (m *Manager) updateStats(record *SlowRequestRecord) {
	m.stats.TotalSlowRequests++

	// 更新平均响应时间
	totalTime := m.stats.AverageResponseTime * float64(m.stats.TotalSlowRequests-1)
	m.stats.AverageResponseTime = (totalTime + float64(record.ResponseTime)) / float64(m.stats.TotalSlowRequests)

	// 更新最慢响应时间
	if record.ResponseTime > m.stats.SlowestResponseTime {
		m.stats.SlowestResponseTime = record.ResponseTime
		m.stats.SlowestRequest = record
	}

	// 按状态码统计
	m.stats.ByStatusCode[record.StatusCode]++

	// 按方法统计
	m.stats.ByMethod[record.Method]++

	// 按Host统计
	m.stats.ByHost[record.Host]++

	// 按后端统计
	if record.BackendID != "" {
		m.stats.ByBackend[record.BackendID]++
	}

	// 更新最近的慢请求列表（保留最近20个）
	if len(m.stats.RecentSlowRequests) >= 20 {
		m.stats.RecentSlowRequests = m.stats.RecentSlowRequests[1:]
	}
	m.stats.RecentSlowRequests = append(m.stats.RecentSlowRequests, record)
}

// GetStats 获取统计信息
func (m *Manager) GetStats() *SlowRequestStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 返回统计信息的副本
	stats := *m.stats
	return &stats
}

// GetRecords 获取慢请求记录
func (m *Manager) GetRecords(limit int) []*SlowRequestRecord {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if limit <= 0 || limit > len(m.records) {
		limit = len(m.records)
	}

	// 返回最近的记录
	start := len(m.records) - limit
	if start < 0 {
		start = 0
	}

	records := make([]*SlowRequestRecord, limit)
	copy(records, m.records[start:])
	return records
}

// ClearRecords 清空记录
func (m *Manager) ClearRecords() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.records = m.records[:0]
	m.stats = &SlowRequestStats{
		ByStatusCode: make(map[int]int64),
		ByMethod:     make(map[string]int64),
		ByHost:       make(map[string]int64),
		ByBackend:    make(map[string]int64),
	}

	m.log.Info("慢请求记录已清空")
}

// IsSlowRequest 判断是否为慢请求
func (m *Manager) IsSlowRequest(responseTime time.Duration) bool {
	return responseTime >= m.threshold
}

// CreateRecordFromHTTP 从HTTP请求和响应创建慢请求记录
func (m *Manager) CreateRecordFromHTTP(r *http.Request, statusCode int, responseTime time.Duration, backendID, backendAddr, target, ruleName string, contentSize int64, err error) *SlowRequestRecord {
	record := &SlowRequestRecord{
		ID:           fmt.Sprintf("%d_%s", time.Now().UnixNano(), r.RemoteAddr),
		Timestamp:    time.Now(),
		Method:       r.Method,
		URL:          r.URL.String(),
		Host:         r.Host,
		Path:         r.URL.Path,
		ClientIP:     getClientIP(r),
		UserAgent:    r.Header.Get("User-Agent"),
		StatusCode:   statusCode,
		ResponseTime: int64(responseTime.Milliseconds()),
		BackendID:    backendID,
		BackendAddr:  backendAddr,
		Target:       target,
		RuleName:     ruleName,
		ContentType:  r.Header.Get("Content-Type"),
		ContentSize:  contentSize,
	}

	if err != nil {
		record.Error = err.Error()
	}

	return record
}

// getClientIP 获取客户端真实IP
func getClientIP(r *http.Request) string {
	// 检查 X-Forwarded-For 头部
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For 可能包含多个IP，取第一个
		if idx := len(xff); idx > 0 {
			if commaIdx := 0; commaIdx < idx {
				for i, c := range xff {
					if c == ',' {
						commaIdx = i
						break
					}
				}
				if commaIdx > 0 {
					return xff[:commaIdx]
				}
			}
		}
		return xff
	}

	// 检查 X-Real-IP 头部
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// 使用 RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// ExportToJSON 导出记录为JSON
func (m *Manager) ExportToJSON() ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return json.MarshalIndent(m.records, "", "  ")
}

// ExportStatsToJSON 导出统计信息为JSON
func (m *Manager) ExportStatsToJSON() ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return json.MarshalIndent(m.stats, "", "  ")
}
