package ml

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/notification"
)

// AnomalyPrediction 异常预测结果
type AnomalyPrediction struct {
	Score        float64   `json:"score"`         // 异常分数 0-1
	Level        string    `json:"level"`         // 级别: normal, low, medium, high, critical
	IsAnomaly    bool      `json:"is_anomaly"`    // 是否为异常
	Confidence   float64   `json:"confidence"`    // 置信度
	Features     *CombinedFeatures `json:"features"`   // 原始特征
	FeatureVector []float64 `json:"feature_vector"` // 特征向量
	Timestamp    time.Time `json:"timestamp"`     // 预测时间
	Reason       string    `json:"reason"`        // 异常原因
}

// ThreatLevel 威胁等级
type ThreatLevel string

const (
	ThreatLevelNone     ThreatLevel = "none"
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// ThreatScore 威胁评分
type ThreatScore struct {
	OverallScore   float64    `json:"overall_score"`    // 总分 0-100
	OverallLevel   ThreatLevel `json:"overall_level"`   // 总等级
	Components     map[string]ThreatComponent `json:"components"` // 各组件分数
	Timestamp      time.Time   `json:"timestamp"`
	Predictions    []AnomalyPrediction `json:"predictions"` // 所有预测结果
}

// ThreatComponent 威胁组件
type ThreatComponent struct {
	Score    float64 `json:"score"`    // 分数 0-100
	Weight   float64 `json:"weight"`   // 权重
	Reason    string  `json:"reason"`   // 原因
}

// InferenceEngine 推理引擎
type InferenceEngine struct {
	forest          *IsolationForest
	featureExtractor *FeatureExtractor
	modelMutex      sync.RWMutex

	// 缓存
	predictionCache map[string]*AnomalyPrediction
	cacheMutex      sync.RWMutex
	cacheTTL        time.Duration

	// 批处理
	batchBuffer        []*InferenceRequest
	batchMutex         sync.Mutex
	batchSize          int
	batchTimeout       time.Duration
	batchTicker        *time.Ticker
	batchStopChan      chan bool

	// 统计
	totalPredictions int64
	anomalyCount     int64

	log *logrus.Entry
}

// InferenceRequest 推理请求
type InferenceRequest struct {
	RequestID   string
	Request     *http.Request
	StatusCode  int
	ResponseTime time.Duration
	RemoteAddr  string
	Callback    func(*AnomalyPrediction)
	Timestamp   time.Time
}

// NewInferenceEngine 创建推理引擎
func NewInferenceEngine() *InferenceEngine {
	return &InferenceEngine{
		batchBuffer:    make([]*InferenceRequest, 0, 1000),
		batchSize:      100,
		batchTimeout:   100 * time.Millisecond,
		cacheTTL:       5 * time.Minute,
		predictionCache: make(map[string]*AnomalyPrediction),
		batchStopChan:  make(chan bool),
		log: logrus.WithFields(logrus.Fields{
			"component": "inference_engine",
		}),
	}
}

// Start 启动推理引擎
func (ie *InferenceEngine) Start() {
	ie.log.Info("启动推理引擎")

	// 启动批处理协程
	go ie.processBatchLoop()

	// 启动批处理器定时器
	ie.batchTicker = time.NewTicker(ie.batchTimeout)
}

// Stop 停止推理引擎
func (ie *InferenceEngine) Stop() {
	ie.batchStopChan <- true
	if ie.batchTicker != nil {
		ie.batchTicker.Stop()
	}
	ie.log.Info("推理引擎已停止")
}

// SetModel 设置模型
func (ie *InferenceEngine) SetModel(forest *IsolationForest, extractor *FeatureExtractor) {
	ie.modelMutex.Lock()
	defer ie.modelMutex.Unlock()

	ie.forest = forest
	ie.featureExtractor = extractor
}

// Predict 预测（同步）
func (ie *InferenceEngine) Predict(r *http.Request, statusCode int, responseTime time.Duration, remoteAddr string) (*AnomalyPrediction, error) {
	// 提取特征
	features := ie.featureExtractor.Extract(r, statusCode, responseTime, remoteAddr)
	featureVector := ie.featureExtractor.GetFeatureVector(features)

	ie.modelMutex.RLock()
	forest := ie.forest
	ie.modelMutex.RUnlock()

	if forest == nil {
		return nil, nil
	}

	// 预测
	score, level := forest.GetAnomalyScore(featureVector)

	prediction := &AnomalyPrediction{
		Score:         score,
		Level:        level,
		IsAnomaly:    score >= forest.Contamination,
		Confidence:   math.Abs(score - 0.5) * 2, // 简单的置信度计算
		Features:     features,
		FeatureVector: featureVector,
		Timestamp:    time.Now(),
		Reason:       ie.generateReason(score, features),
	}

	// 更新统计
	ie.updateStats(prediction)

	return prediction, nil
}

// PredictAsync 异步预测
func (ie *InferenceEngine) PredictAsync(r *http.Request, statusCode int, responseTime time.Duration, remoteAddr string, callback func(*AnomalyPrediction)) {
	request := &InferenceRequest{
		Request:     r,
		StatusCode:  statusCode,
		ResponseTime: responseTime,
		RemoteAddr:  remoteAddr,
		Callback:    callback,
		Timestamp:   time.Now(),
		RequestID:   generateRequestID(r, remoteAddr),
	}

	// 加入批处理缓冲区
	ie.batchMutex.Lock()
	if len(ie.batchBuffer) < cap(ie.batchBuffer) {
		ie.batchBuffer = append(ie.batchBuffer, request)
	}
	ie.batchMutex.Unlock()
}

// processBatchLoop 批处理预测循环
func (ie *InferenceEngine) processBatchLoop() {
	ticker := time.NewTicker(ie.batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ie.batchStopChan:
			return
		case <-ticker.C:
			ie.processBatch()
		}
	}
}

// processBatch 处理批次
func (ie *InferenceEngine) processBatch() {
	ie.batchMutex.Lock()
	if len(ie.batchBuffer) == 0 {
		ie.batchMutex.Unlock()
		return
	}

	// 取出批次
	batchSize := ie.batchSize
	if len(ie.batchBuffer) < batchSize {
		batchSize = len(ie.batchBuffer)
	}
	batch := ie.batchBuffer[:batchSize]
	ie.batchBuffer = ie.batchBuffer[batchSize:]
	ie.batchMutex.Unlock()

	// 并行处理批次
	var wg sync.WaitGroup
	for _, req := range batch {
		wg.Add(1)
		go func(r *InferenceRequest) {
			defer wg.Done()
			prediction, err := ie.Predict(r.Request, r.StatusCode, r.ResponseTime, r.RemoteAddr)
			if err != nil {
				ie.log.Warnf("预测失败: %v", err)
				return
			}
			if r.Callback != nil {
				r.Callback(prediction)
			}
		}(req)
	}
	wg.Wait()
}

// updateStats 更新统计
func (ie *InferenceEngine) updateStats(pred *AnomalyPrediction) {
	// 原子操作更新计数器
	// 注意：实际使用 sync/atomic 或其他原子操作
}

// generateReason 生成异常原因
func (ie *InferenceEngine) generateReason(score float64, features *CombinedFeatures) string {
	if score < 0.3 {
		return "正常访问模式"
	}

	reasons := []string{}

	// 检查请求特征
	if features.Request.HasSQLKeywords {
		reasons = append(reasons, "检测到SQL注入特征")
	}
	if features.Request.HasXSSKeywords {
		reasons = append(reasons, "检测到XSS攻击特征")
	}
	if features.Request.HasPathTraversal {
		reasons = append(reasons, "检测到路径遍历特征")
	}
	if features.Request.SpecialCharRatio > 0.3 {
		reasons = append(reasons, "特殊字符比例异常")
	}

	// 检查IP特征
	if features.IP.FailedRequestCount > 10 {
		reasons = append(reasons, "失败请求次数过多")
	}
	if features.IP.UAChangeCount > 5 {
		reasons = append(reasons, "User-Agent频繁变化")
	}
	if features.IP.UniquePaths > 50 {
		reasons = append(reasons, "访问路径过多")
	}
	if features.IP.AvgRequestInterval < 100 && features.IP.RequestCount > 10 {
		reasons = append(reasons, "请求频率过高")
	}

	// 检查行为特征
	if features.Behavioral.PathTraversalPattern {
		reasons = append(reasons, "存在路径遍历模式")
	}
	if features.Behavioral.ParamBruteForce {
		reasons = append(reasons, "检测到参数暴力破解")
	}
	if features.Behavioral.IsScanning {
		reasons = append(reasons, "扫描行为")
	}

	if len(reasons) == 0 {
		return "综合异常行为检测"
	}

	return reasons[0]
}

func generateRequestID(r *http.Request, remoteAddr string) string {
	return remoteAddr + "_" + time.Now().Format("20060102150405.000")
}

// ThreatScorer 威胁评分器
type ThreatScorer struct {
	ipReputation *IPReputationDB
	log          *logrus.Entry
}

// NewThreatScorer 创建威胁评分器
func NewThreatScorer() *ThreatScorer {
	return &ThreatScorer{
		ipReputation: NewIPReputationDB(),
		log: logrus.WithFields(logrus.Fields{
			"component": "threat_scorer",
		}),
	}
}

// Score 计算威胁评分
func (ts *ThreatScorer) Score(predictions []AnomalyPrediction) *ThreatScore {
	if len(predictions) == 0 {
		return &ThreatScore{
			OverallScore: 0,
			OverallLevel: ThreatLevelNone,
			Components:   make(map[string]ThreatComponent),
			Timestamp:    time.Now(),
		}
	}

	components := make(map[string]ThreatComponent)
	totalScore := 0.0
	totalWeight := 0.0

	// 组件1: 异常检测分数
	anomalyScore := ts.scoreAnomalyComponent(predictions)
	components["anomaly_detection"] = anomalyScore
	totalScore += anomalyScore.Score * anomalyScore.Weight
	totalWeight += anomalyScore.Weight

	// 组件2: IP信誉分数
	ipScore := ts.scoreIPComponent(predictions)
	components["ip_reputation"] = ipScore
	totalScore += ipScore.Score * ipScore.Weight
	totalWeight += ipScore.Weight

	// 组件3: 行为分数
	behaviorScore := ts.scoreBehaviorComponent(predictions)
	components["behavior"] = behaviorScore
	totalScore += behaviorScore.Score * behaviorScore.Weight
	totalWeight += behaviorScore.Weight

	// 组件4: 时序模式分数
	temporalScore := ts.scoreTemporalComponent(predictions)
	components["temporal"] = temporalScore
	totalScore += temporalScore.Score * temporalScore.Weight
	totalWeight += temporalScore.Weight

	// 计算总分
	overallScore := totalScore
	if totalWeight > 0 {
		overallScore = totalScore / totalWeight
	}

	// 确定威胁等级
	level := ts.determineLevel(overallScore)

	return &ThreatScore{
		OverallScore: overallScore,
		OverallLevel: level,
		Components:   components,
		Timestamp:    time.Now(),
		Predictions:  predictions,
	}
}

// scoreAnomalyComponent 异常检测组件分数
func (ts *ThreatScorer) scoreAnomalyComponent(predictions []AnomalyPrediction) ThreatComponent {
	if len(predictions) == 0 {
		return ThreatComponent{Score: 0, Weight: 0.4}
	}

	maxScore := 0.0
	for _, pred := range predictions {
		if pred.Score > maxScore {
			maxScore = pred.Score
		}
	}

	reason := "异常检测"
	if maxScore > 0.7 {
		reason = "检测到异常访问模式"
	}

	return ThreatComponent{
		Score:  maxScore * 100,
		Weight: 0.4,
		Reason: reason,
	}
}

// scoreIPComponent IP信誉组件分数
func (ts *ThreatScorer) scoreIPComponent(predictions []AnomalyPrediction) ThreatComponent {
	if len(predictions) == 0 {
		return ThreatComponent{Score: 0, Weight: 0.2}
	}

	// 使用最新的预测获取IP信息
	latest := predictions[len(predictions)-1]
	if latest.Features.IP.ReputationScore < 0.5 {
		return ThreatComponent{
			Score:  (1 - latest.Features.IP.ReputationScore) * 100,
			Weight: 0.2,
			Reason: "IP信誉低",
		}
	}

	return ThreatComponent{
		Score:  0,
		Weight: 0.2,
		Reason: "IP信誉正常",
	}
}

// scoreBehaviorComponent 行为组件分数
func (ts *ThreatScorer) scoreBehaviorComponent(predictions []AnomalyPrediction) ThreatComponent {
	if len(predictions) == 0 {
		return ThreatComponent{Score: 0, Weight: 0.25}
	}

	// 统计异常行为数量
	anomalyCount := 0
	for _, pred := range predictions {
		if pred.Features.Behavioral.IsScanning {
			anomalyCount += 2
		}
		if pred.Features.Behavioral.PathTraversalPattern {
			anomalyCount += 3
		}
		if pred.Features.Behavioral.ParamBruteForce {
			anomalyCount += 2
		}
		if pred.Features.Behavioral.RapidSequentialRequests {
			anomalyCount++
		}
	}

	score := float64(anomalyCount) / 10.0 * 100
	if score > 100 {
		score = 100
	}

	reason := "行为模式正常"
	if anomalyCount > 0 {
		reason = "检测到异常行为模式"
	}

	return ThreatComponent{
		Score:  score,
		Weight: 0.25,
		Reason: reason,
	}
}

// scoreTemporalComponent 时序组件分数
func (ts *ThreatScorer) scoreTemporalComponent(predictions []AnomalyPrediction) ThreatComponent {
	if len(predictions) < 2 {
		return ThreatComponent{Score: 0, Weight: 0.15}
	}

	// 分析请求趋势
	scores := make([]float64, len(predictions))
	for i, pred := range predictions {
		scores[i] = pred.Score
	}

	// 计算趋势（简单线性回归）
	n := float64(len(scores))
	sumX := n * (n - 1) / 2
	sumY := 0.0
	sumXY := 0.0
	sumX2 := 0.0

	for i := 0; i < len(scores); i++ {
		sumY += scores[i]
		sumXY += float64(i) * scores[i]
		sumX2 += float64(i * i)
	}

	slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)

	// 正斜率表示威胁增加
	score := slope * 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	reason := "威胁趋势稳定"
	if slope > 0.1 {
		reason = "威胁趋势上升"
	}

	return ThreatComponent{
		Score:  score,
		Weight: 0.15,
		Reason: reason,
	}
}

// determineLevel 确定威胁等级
func (ts *ThreatScorer) determineLevel(score float64) ThreatLevel {
	if score >= 90 {
		return ThreatLevelCritical
	}
	if score >= 70 {
		return ThreatLevelHigh
	}
	if score >= 50 {
		return ThreatLevelMedium
	}
	if score >= 20 {
		return ThreatLevelLow
	}
	return ThreatLevelNone
}

// IPReputationDB IP信誉数据库（简化版）
type IPReputationDB struct {
	knownBadIPs map[string]float64
	mu         sync.RWMutex
}

// NewIPReputationDB 创建IP信誉数据库
func NewIPReputationDB() *IPReputationDB {
	db := &IPReputationDB{
		knownBadIPs: make(map[string]float64),
	}

	// 初始化一些已知的恶意IP段（示例）
	go db.loadKnownBadIPs()

	return db
}

// loadKnownBadIPs 加载已知恶意IP
func (db *IPReputationDB) loadKnownBadIPs() {
	// TODO: 从威胁情报源加载
	// 这里可以集成外部API
}

// GetReputation 获取IP信誉分数
func (db *IPReputationDB) GetReputation(ip string) float64 {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if score, ok := db.knownBadIPs[ip]; ok {
		return score
	}

	// 默认信誉分数
	return 1.0
}

// AddBadIP 添加恶意IP
func (db *IPReputationDB) AddBadIP(ip string, score float64) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.knownBadIPs[ip] = score
}

// GetStats 获取统计信息
func (ie *InferenceEngine) GetStats() map[string]interface{} {
	ie.modelMutex.RLock()
	defer ie.modelMutex.RUnlock()

	stats := map[string]interface{}{
		"total_predictions": ie.totalPredictions,
		"anomaly_count":     ie.anomalyCount,
		"model_loaded":      ie.forest != nil,
		"cache_size":        len(ie.predictionCache),
	}

	if ie.forest != nil {
		forestStats := ie.forest.GetStats()
		for k, v := range forestStats {
			stats[k] = v
		}
	}

	return stats
}

// ShouldBlock 判断是否应该阻止请求
func (ts *ThreatScorer) ShouldBlock(score *ThreatScore) bool {
	// Critical等级直接阻止
	if score.OverallLevel == ThreatLevelCritical {
		return true
	}

	// High等级且异常检测分数高则阻止
	if score.OverallLevel == ThreatLevelHigh {
		if anomaly, ok := score.Components["anomaly_detection"]; ok && anomaly.Score > 70 {
			return true
		}
	}

	return false
}

// SendThreatAlert 发送威胁告警
func (ts *ThreatScorer) SendThreatAlert(score *ThreatScore, notifier *notification.NotificationIntegrator, remoteAddr string) {
	if notifier == nil {
		return
	}

	level := notification.LevelInfo
	message := "检测到可疑访问"

	switch score.OverallLevel {
	case ThreatLevelCritical:
		level = notification.LevelCritical
		message = "检测到严重安全威胁"
	case ThreatLevelHigh:
		level = notification.LevelError
		message = "检测到高风险访问"
	case ThreatLevelMedium:
		level = notification.LevelWarning
		message = "检测到异常访问模式"
	case ThreatLevelLow:
		level = notification.LevelInfo
		message = "检测到可疑访问"
	}

	notifier.GetManager().Send(&notification.Notification{
		Type:    notification.TypeSecurityAlert,
		Level:   level,
		Title:   "AI威胁检测告警",
		Message: message,
		Details: map[string]any{
			"threat_score":  score.OverallScore,
			"threat_level":  score.OverallLevel,
			"remote_addr":  remoteAddr,
			"components":   score.Components,
		},
	})
}
