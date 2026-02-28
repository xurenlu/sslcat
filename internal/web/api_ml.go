package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/ml"
)

// MLAPIHandler ML API 处理器
type MLAPIHandler struct {
	inferenceEngine *ml.InferenceEngine
	forest          *ml.IsolationForest
	featureExtractor *ml.FeatureExtractor
	threatScorer    *ml.ThreatScorer
	log             *logrus.Entry
}

// NewMLAPIHandler 创建 ML API 处理器
func NewMLAPIHandler() *MLAPIHandler {
	return &MLAPIHandler{
		log: logrus.WithFields(logrus.Fields{
			"component": "ml_api",
		}),
	}
}

// SetEngine 设置推理引擎
func (h *MLAPIHandler) SetEngine(ie *ml.InferenceEngine, forest *ml.IsolationForest, extractor *ml.FeatureExtractor, scorer *ml.ThreatScorer) {
	h.inferenceEngine = ie
	h.forest = forest
	h.featureExtractor = extractor
	h.threatScorer = scorer
}

// TrainRequest 训练请求
type TrainRequest struct {
	Samples       [][]float64 `json:"samples"`
	NTrees        int         `json:"n_trees"`
	MaxSamples    int         `json:"max_samples"`
	Contamination float64     `json:"contamination"`
}

// PredictRequest 预测请求
type PredictRequest struct {
	Features      *ml.CombinedFeatures `json:"features"`
	FeatureVector []float64            `json:"feature_vector"`
}

// FeedbackRequest 反馈请求
type FeedbackRequest struct {
	PredictionID string  `json:"prediction_id"`
	IsAnomaly    bool    `json:"is_anomaly"`
	ActualLabel  string  `json:"actual_label"`
	Confidence   float64 `json:"confidence"`
}

// StatsResponse 统计响应
type StatsResponse struct {
	ModelLoaded    bool                   `json:"model_loaded"`
	TotalSamples   int                    `json:"total_samples"`
	FeatureDim     int                    `json:"feature_dim"`
	NTrees         int                    `json:"n_trees"`
	Contamination  float64                `json:"contamination"`
	TotalPredictions int64                `json:"total_predictions"`
	AnomalyCount   int64                  `json:"anomaly_count"`
	Threshold      float64                `json:"threshold"`
	AvgTreeDepth   float64                `json:"avg_tree_depth"`
	LastTraining   string                 `json:"last_training"`
	RecentPredictions []ml.AnomalyPrediction `json:"recent_predictions,omitempty"`
}

// RegisterRoutes 注册路由
func (h *MLAPIHandler) RegisterRoutes(router *mux.Router, adminPrefix string) {
	mlRouter := router.PathPrefix("/api/ml").Subrouter()

	// 模型管理
	mlRouter.HandleFunc("/train", h.handleTrain).Methods("POST")
	mlRouter.HandleFunc("/stats", h.handleStats).Methods("GET")
	mlRouter.HandleFunc("/reload", h.handleReload).Methods("POST")

	// 预测
	mlRouter.HandleFunc("/predict", h.handlePredict).Methods("POST")
	mlRouter.HandleFunc("/predict/batch", h.handlePredictBatch).Methods("POST")

	// 反馈
	mlRouter.HandleFunc("/feedback", h.handleFeedback).Methods("POST")

	// 威胁评分
	mlRouter.HandleFunc("/threat/score", h.handleThreatScore).Methods("POST")

	// 特征提取
	mlRouter.HandleFunc("/features/extract", h.handleExtractFeatures).Methods("POST")

	h.log.Infof("ML API routes registered under %s/api/ml", adminPrefix)
}

// handleTrain 训练模型
func (h *MLAPIHandler) handleTrain(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	var req TrainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", err)
		return
	}

	// 验证请求
	if len(req.Samples) == 0 {
		h.sendError(w, "No samples provided", fmt.Errorf("empty samples"))
		return
	}

	// 计算特征维度
	featureDim := len(req.Samples[0])
	if featureDim == 0 {
		h.sendError(w, "Invalid feature dimension", fmt.Errorf("feature dimension is 0"))
		return
	}

	// 创建或更新森林配置
	config := &ml.ForestConfig{
		NTrees:        req.NTrees,
		MaxSamples:    req.MaxSamples,
		Contamination: req.Contamination,
	}

	if config.NTrees == 0 {
		config.NTrees = 100
	}
	if config.MaxSamples == 0 {
		config.MaxSamples = 256
	}
	if config.Contamination == 0 {
		config.Contamination = 0.1
	}

	// 创建新的森林
	newForest := ml.NewIsolationForest(featureDim, config)

	// 训练
	h.log.Infof("开始训练 ML 模型: %d 树, %d 特征, %d 样本", config.NTrees, featureDim, len(req.Samples))
	if err := newForest.Fit(req.Samples); err != nil {
		h.sendError(w, "Training failed", err)
		return
	}

	// 更新推理引擎
	h.forest = newForest
	if h.inferenceEngine != nil && h.featureExtractor != nil {
		h.inferenceEngine.SetModel(h.forest, h.featureExtractor)
	}

	duration := time.Since(startTime)

	h.sendJSON(w, map[string]interface{}{
		"success":       true,
		"message":       "Model trained successfully",
		"n_trees":       config.NTrees,
		"max_samples":   config.MaxSamples,
		"contamination": config.Contamination,
		"feature_dim":   featureDim,
		"total_samples": len(req.Samples),
		"duration_ms":   duration.Milliseconds(),
		"timestamp":     time.Now().Format(time.RFC3339),
	})
}

// handleStats 获取模型统计
func (h *MLAPIHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if h.forest == nil {
		h.sendJSON(w, StatsResponse{
			ModelLoaded: false,
		})
		return
	}

	// 获取森林统计
	forestStats := h.forest.GetStats()

	response := StatsResponse{
		ModelLoaded:      true,
		TotalSamples:     forestStats["total_samples"].(int),
		FeatureDim:       forestStats["feature_dim"].(int),
		NTrees:           forestStats["n_trees"].(int),
		Contamination:    forestStats["contamination"].(float64),
		Threshold:        forestStats["threshold"].(float64),
		AvgTreeDepth:     forestStats["avg_tree_depth"].(float64),
		LastTraining:     time.Now().Format(time.RFC3339),
	}

	// 获取推理引擎统计
	if h.inferenceEngine != nil {
		engineStats := h.inferenceEngine.GetStats()
		if totalPred, ok := engineStats["total_predictions"].(int64); ok {
			response.TotalPredictions = totalPred
		}
		if anomalyCount, ok := engineStats["anomaly_count"].(int64); ok {
			response.AnomalyCount = anomalyCount
		}
	}

	h.sendJSON(w, response)
}

// handleReload 重新加载模型
func (h *MLAPIHandler) handleReload(w http.ResponseWriter, r *http.Request) {
	// TODO: 实现从文件加载模型
	h.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Model reload not implemented yet",
	})
}

// handlePredict 单次预测
func (h *MLAPIHandler) handlePredict(w http.ResponseWriter, r *http.Request) {
	if h.forest == nil {
		h.sendError(w, "Model not loaded", fmt.Errorf("forest is nil"))
		return
	}

	var req PredictRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", err)
		return
	}

	var featureVector []float64
	if req.FeatureVector != nil && len(req.FeatureVector) > 0 {
		featureVector = req.FeatureVector
	} else if req.Features != nil && h.featureExtractor != nil {
		featureVector = h.featureExtractor.GetFeatureVector(req.Features)
	} else {
		h.sendError(w, "No features provided", fmt.Errorf("missing features"))
		return
	}

	score, level := h.forest.GetAnomalyScore(featureVector)

	prediction := ml.AnomalyPrediction{
		Score:         score,
		Level:         level,
		IsAnomaly:     score >= h.forest.Contamination,
		FeatureVector: featureVector,
		Timestamp:     time.Now(),
	}

	if req.Features != nil {
		prediction.Features = req.Features
	}

	h.sendJSON(w, prediction)
}

// handlePredictBatch 批量预测
func (h *MLAPIHandler) handlePredictBatch(w http.ResponseWriter, r *http.Request) {
	if h.forest == nil {
		h.sendError(w, "Model not loaded", fmt.Errorf("forest is nil"))
		return
	}

	var req struct {
		Requests []PredictRequest `json:"requests"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", err)
		return
	}

	predictions := make([]ml.AnomalyPrediction, 0, len(req.Requests))

	for _, reqItem := range req.Requests {
		var featureVector []float64
		if reqItem.FeatureVector != nil && len(reqItem.FeatureVector) > 0 {
			featureVector = reqItem.FeatureVector
		} else if reqItem.Features != nil && h.featureExtractor != nil {
			featureVector = h.featureExtractor.GetFeatureVector(reqItem.Features)
		} else {
			continue
		}

		score, level := h.forest.GetAnomalyScore(featureVector)

		prediction := ml.AnomalyPrediction{
			Score:         score,
			Level:         level,
			IsAnomaly:     score >= h.forest.Contamination,
			FeatureVector: featureVector,
			Timestamp:     time.Now(),
		}

		if reqItem.Features != nil {
			prediction.Features = reqItem.Features
		}

		predictions = append(predictions, prediction)
	}

	h.sendJSON(w, map[string]interface{}{
		"predictions": predictions,
		"count":       len(predictions),
	})
}

// handleFeedback 处理反馈
func (h *MLAPIHandler) handleFeedback(w http.ResponseWriter, r *http.Request) {
	var req FeedbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", err)
		return
	}

	// TODO: 实现反馈收集和在线学习
	// 1. 存储反馈数据
	// 2. 定期使用反馈数据重新训练模型
	// 3. 调整模型参数或阈值

	h.log.WithFields(logrus.Fields{
		"prediction_id": req.PredictionID,
		"is_anomaly":    req.IsAnomaly,
		"actual_label":  req.ActualLabel,
	}).Info("Received ML feedback")

	h.sendJSON(w, map[string]interface{}{
		"success": true,
		"message": "Feedback received",
	})
}

// handleThreatScore 计算威胁评分
func (h *MLAPIHandler) handleThreatScore(w http.ResponseWriter, r *http.Request) {
	if h.threatScorer == nil {
		h.sendError(w, "Threat scorer not initialized", fmt.Errorf("scorer is nil"))
		return
	}

	var req struct {
		Predictions []ml.AnomalyPrediction `json:"predictions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", err)
		return
	}

	score := h.threatScorer.Score(req.Predictions)

	h.sendJSON(w, score)
}

// handleExtractFeatures 提取特征
func (h *MLAPIHandler) handleExtractFeatures(w http.ResponseWriter, r *http.Request) {
	if h.featureExtractor == nil {
		h.sendError(w, "Feature extractor not initialized", fmt.Errorf("extractor is nil"))
		return
	}

	// 从请求中提取特征
	// 这里需要从 HTTP 请求中提取信息，或者从请求体中获取预处理的特征

	var req struct {
		Method       string        `json:"method"`
		URL          string        `json:"url"`
		Headers      map[string]string `json:"headers"`
		RemoteAddr   string        `json:"remote_addr"`
		StatusCode   int           `json:"status_code"`
		ResponseTime time.Duration `json:"response_time"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body", err)
		return
	}

	// 构造模拟请求（实际应用中应该从中间件传入真实的 http.Request）
	// 这里简化处理，直接返回默认特征
	features := &ml.CombinedFeatures{
		Request: ml.RequestFeatures{
			URLLength:         len(req.URL),
			PathLength:        len(req.URL),
			PathDepth:         strings.Count(req.URL, "/"),
			ParamCount:        0,
			HeaderCount:       len(req.Headers),
			CookieCount:       0,
			SpecialCharRatio:  0,
			HasSQLKeywords:    false,
			HasXSSKeywords:    false,
			HasPathTraversal:  false,
			ContentType:       "",
			UserAgentLength:   0,
			RefererLength:     0,
			BodySize:          0,
			IsHTTPS:           false,
		},
		IP: ml.IPFeatures{
			RequestCount:       1,
			FailedRequestCount: 0,
			SuccessRate:        1.0,
			AvgRequestInterval: 0,
			UniquePaths:        1,
			UniqueUserAgents:   1,
			UAChangeCount:      0,
			ReputationScore:    1.0,
		},
		Time: ml.TimeFeatures{
			HourOfDay:       time.Now().Hour(),
			DayOfWeek:       int(time.Now().Weekday()),
			IsWeekend:       time.Now().Weekday() == time.Saturday || time.Now().Weekday() == time.Sunday,
			IsBusinessHours: time.Now().Hour() >= 9 && time.Now().Hour() < 18,
			RequestTrend:    0,
			ErrorRateTrend:  0,
		},
		Behavioral: ml.BehavioralFeatures{
			PathTraversalPattern:   false,
			ParamBruteForce:        false,
			SequentialAccess:       false,
			RapidSequentialRequests: false,
			IsScanning:             false,
		},
		Timestamp: time.Now(),
	}

	h.sendJSON(w, features)
}

// sendJSON 发送 JSON 响应
func (h *MLAPIHandler) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// sendError 发送错误响应
func (h *MLAPIHandler) sendError(w http.ResponseWriter, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	response := map[string]interface{}{
		"success": false,
		"message": message,
	}

	if err != nil {
		response["error"] = err.Error()
	}

	json.NewEncoder(w).Encode(response)
}
