package ml

import (
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// TrainingSample 训练样本（特征向量 + 元数据，用于训练 & 调试展示）
type TrainingSample struct {
	Vector    []float64 `json:"vector"`
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path,omitempty"`
	Method    string    `json:"method,omitempty"`
	Status    int       `json:"status,omitempty"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
}

// RequestSampler 真实请求样本采集器（线程安全的环形缓冲区）
// 每个进入 sslcat 的请求都通过 Observe() 喂一份样本进来，训练时直接从这里取。
type RequestSampler struct {
	mu        sync.Mutex
	buffer    []TrainingSample
	maxSize   int
	cursor    int // 环形游标
	filled    bool
	extractor *FeatureExtractor
	totalSeen int64
	log       *logrus.Entry
}

// NewRequestSampler 创建样本采集器
func NewRequestSampler(extractor *FeatureExtractor, maxSize int) *RequestSampler {
	if maxSize <= 0 {
		maxSize = 5000
	}
	return &RequestSampler{
		buffer:    make([]TrainingSample, maxSize),
		maxSize:   maxSize,
		extractor: extractor,
		log: logrus.WithFields(logrus.Fields{
			"component": "ml_request_sampler",
		}),
	}
}

// Observe 把一次请求转化为训练样本写入环形缓冲区
func (s *RequestSampler) Observe(r *http.Request, statusCode int, responseTime time.Duration, remoteAddr string) {
	if s == nil || s.extractor == nil || r == nil {
		return
	}
	features := s.extractor.Extract(r, statusCode, responseTime, remoteAddr)
	vec := s.extractor.GetFeatureVector(features)

	sample := TrainingSample{
		Vector:    vec,
		Timestamp: time.Now(),
		Path:      r.URL.Path,
		Method:    r.Method,
		Status:    statusCode,
		RemoteIP:  remoteAddr,
	}

	s.mu.Lock()
	s.buffer[s.cursor] = sample
	s.cursor++
	if s.cursor >= s.maxSize {
		s.cursor = 0
		s.filled = true
	}
	s.totalSeen++
	s.mu.Unlock()
}

// Vectors 返回当前缓冲区中的全部特征向量，按入队顺序（最旧 → 最新）
func (s *RequestSampler) Vectors() [][]float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := s.size()
	if n == 0 {
		return nil
	}
	out := make([][]float64, 0, n)
	if s.filled {
		// 从 cursor 开始绕一圈
		for i := 0; i < s.maxSize; i++ {
			idx := (s.cursor + i) % s.maxSize
			if len(s.buffer[idx].Vector) == 0 {
				continue
			}
			out = append(out, s.buffer[idx].Vector)
		}
	} else {
		for i := 0; i < s.cursor; i++ {
			out = append(out, s.buffer[i].Vector)
		}
	}
	return out
}

// Size 当前样本数（不持锁版本由调用方加锁）
func (s *RequestSampler) size() int {
	if s.filled {
		return s.maxSize
	}
	return s.cursor
}

// Size 当前样本数
func (s *RequestSampler) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size()
}

// TotalObserved 全部观测到的请求次数
func (s *RequestSampler) TotalObserved() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalSeen
}

// PredictionBuffer 最近预测的环形缓冲区
type PredictionBuffer struct {
	mu      sync.RWMutex
	buf     []AnomalyPrediction
	maxSize int
	cursor  int
	filled  bool
}

// NewPredictionBuffer 创建预测缓冲区
func NewPredictionBuffer(maxSize int) *PredictionBuffer {
	if maxSize <= 0 {
		maxSize = 200
	}
	return &PredictionBuffer{
		buf:     make([]AnomalyPrediction, maxSize),
		maxSize: maxSize,
	}
}

// Push 写入一次预测结果
func (b *PredictionBuffer) Push(p AnomalyPrediction) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.buf[b.cursor] = p
	b.cursor++
	if b.cursor >= b.maxSize {
		b.cursor = 0
		b.filled = true
	}
	b.mu.Unlock()
}

// Recent 返回最近 N 条预测（按时间倒序，最新在前）
func (b *PredictionBuffer) Recent(limit int) []AnomalyPrediction {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	n := b.size()
	if n == 0 {
		return nil
	}
	if limit <= 0 || limit > n {
		limit = n
	}

	out := make([]AnomalyPrediction, 0, limit)
	// 从最新往旧反向遍历
	for i := 0; i < limit; i++ {
		idx := (b.cursor - 1 - i + b.maxSize) % b.maxSize
		out = append(out, b.buf[idx])
	}
	return out
}

func (b *PredictionBuffer) size() int {
	if b.filled {
		return b.maxSize
	}
	return b.cursor
}

// Size 返回当前缓冲区元素数
func (b *PredictionBuffer) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.size()
}
