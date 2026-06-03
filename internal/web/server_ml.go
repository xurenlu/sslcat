package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/ml"
)

// GetMLEngine 获取ML推理引擎
func (s *Server) GetMLEngine() *ml.InferenceEngine {
	return s.mlInferenceEngine
}

// GetMLFeatureExtractor 获取ML特征提取器
func (s *Server) GetMLFeatureExtractor() *ml.FeatureExtractor {
	return s.mlFeatureExtractor
}

// GetMLThreatScorer 获取ML威胁评分器
func (s *Server) GetMLThreatScorer() *ml.ThreatScorer {
	return s.mlThreatScorer
}

// ML API 处理函数 —— 都是 *MLAPIHandler 的薄包装，先做 nil 检查再转发

func (s *Server) handleMLTrain(w http.ResponseWriter, r *http.Request) {
	if s.mlAPIHandler == nil {
		http.Error(w, "ML system not initialized", http.StatusServiceUnavailable)
		return
	}
	s.mlAPIHandler.handleTrain(w, r)
}

func (s *Server) handleMLStats(w http.ResponseWriter, r *http.Request) {
	if s.mlAPIHandler == nil {
		http.Error(w, "ML system not initialized", http.StatusServiceUnavailable)
		return
	}
	s.mlAPIHandler.handleStats(w, r)
}

func (s *Server) handleMLPredict(w http.ResponseWriter, r *http.Request) {
	if s.mlAPIHandler == nil {
		http.Error(w, "ML system not initialized", http.StatusServiceUnavailable)
		return
	}
	s.mlAPIHandler.handlePredict(w, r)
}

func (s *Server) handleMLFeedback(w http.ResponseWriter, r *http.Request) {
	if s.mlAPIHandler == nil {
		http.Error(w, "ML system not initialized", http.StatusServiceUnavailable)
		return
	}
	s.mlAPIHandler.handleFeedback(w, r)
}

func (s *Server) handleMLThreatScore(w http.ResponseWriter, r *http.Request) {
	if s.mlAPIHandler == nil {
		http.Error(w, "ML system not initialized", http.StatusServiceUnavailable)
		return
	}
	s.mlAPIHandler.handleThreatScore(w, r)
}

func (s *Server) handleMLExtractFeatures(w http.ResponseWriter, r *http.Request) {
	if s.mlAPIHandler == nil {
		http.Error(w, "ML system not initialized", http.StatusServiceUnavailable)
		return
	}
	s.mlAPIHandler.handleExtractFeatures(w, r)
}

// shouldFeedML 判断当前请求是否应该喂给 ML 系统
// 排除管理面板自身、健康检查、ML/Prometheus API 等噪音路径
func (s *Server) shouldFeedML(r *http.Request) bool {
	if s.mlSampler == nil || s.mlInferenceEngine == nil {
		return false
	}
	if r == nil || r.URL == nil {
		return false
	}
	path := r.URL.Path

	if s.config.AdminPrefix != "" && strings.HasPrefix(path, s.config.AdminPrefix) {
		return false
	}
	if path == "/metrics" || path == "/healthz" || path == "/favicon.ico" || path == "/robots.txt" {
		return false
	}
	if strings.HasPrefix(path, "/.well-known/") {
		return false
	}
	return true
}

// feedMLAsync 异步把请求送入采样器 + 推理引擎
func (s *Server) feedMLAsync(r *http.Request, statusCode int, responseTime time.Duration, remoteAddr string) {
	clone := r.Clone(r.Context())
	clone.Body = nil
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.WithField("panic", rec).Warn("ML feed panic recovered")
			}
		}()
		s.mlSampler.Observe(clone, statusCode, responseTime, remoteAddr)
		if s.mlForest != nil {
			if pred, err := s.mlInferenceEngine.Predict(clone, statusCode, responseTime, remoteAddr); err == nil && pred != nil {
				_ = pred
			}
		}
	}()
}

// handleMLRecentPredictions 返回最近 N 条 ML 推理预测
func (s *Server) handleMLRecentPredictions(w http.ResponseWriter, r *http.Request) {
	if s.mlInferenceEngine == nil {
		http.Error(w, "ML system not initialized", http.StatusServiceUnavailable)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	preds := s.mlInferenceEngine.RecentPredictions(limit)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"predictions": preds,
		"count":       len(preds),
	})
}

// handleMLTrainingHistory 返回训练历史
func (s *Server) handleMLTrainingHistory(w http.ResponseWriter, r *http.Request) {
	if s.mlHistoryStore == nil {
		http.Error(w, "ML system not initialized", http.StatusServiceUnavailable)
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	entries := s.mlHistoryStore.List(limit)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entries": entries,
		"count":   len(entries),
	})
}
