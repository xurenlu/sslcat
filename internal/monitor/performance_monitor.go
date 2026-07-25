package monitor

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// PerformanceMonitor 性能基线监控器
type PerformanceMonitor struct {
	log           *logrus.Entry
	stopChan      chan struct{}
	stopOnce      sync.Once
	checkInterval time.Duration

	// 性能指标
	mu                sync.RWMutex
	requestCount      int64
	totalResponseTime int64
	slowRequestCount  int64
	errorCount        int64

	// 基线数据
	baselineQPS       float64
	baselineAvgRT     float64
	baselineErrorRate float64

	// 当前数据
	currentQPS       float64
	currentAvgRT     float64
	currentErrorRate float64

	// 统计窗口
	windowStart   time.Time
	lastCheckTime time.Time

	// 历史记录
	qpsHistory       []float64
	rtHistory        []float64
	errorRateHistory []float64
	maxHistorySize   int

	// 阈值配置
	qpsDeviationThreshold      float64 // QPS偏差阈值（百分比）
	rtDeviationThreshold       float64 // 响应时间偏差阈值（百分比）
	errorRateIncreaseThreshold float64 // 错误率增长阈值（百分比）

	// 告警计数
	qpsWarningCount       int
	rtWarningCount        int
	errorRateWarningCount int
}

// NewPerformanceMonitor 创建性能监控器
func NewPerformanceMonitor(checkInterval time.Duration) *PerformanceMonitor {
	// 使用质数间隔避免与其他定时器同时触发（31秒）
	if checkInterval == 30*time.Second {
		checkInterval = 31 * time.Second
	}

	return &PerformanceMonitor{
		log: logrus.WithFields(logrus.Fields{
			"component": "performance_monitor",
		}),
		stopChan:                   make(chan struct{}),
		checkInterval:              checkInterval,
		maxHistorySize:             100,
		qpsHistory:                 make([]float64, 0, 100),
		rtHistory:                  make([]float64, 0, 100),
		errorRateHistory:           make([]float64, 0, 100),
		windowStart:                time.Now(),
		lastCheckTime:              time.Now(),
		qpsDeviationThreshold:      0.5, // QPS偏差50%
		rtDeviationThreshold:       0.5, // 响应时间偏差50%
		errorRateIncreaseThreshold: 2.0, // 错误率增长2倍
	}
}

// Start 启动监控
func (pm *PerformanceMonitor) Start() {
	pm.log.Infof("性能基线监控器已启动，检查间隔: %v", pm.checkInterval)

	go pm.monitorLoop()
}

// Stop 停止监控
func (pm *PerformanceMonitor) Stop() {
	pm.stopOnce.Do(func() {
		close(pm.stopChan)
		pm.log.Info("性能基线监控器已停止")
	})
}

// monitorLoop 监控循环
func (pm *PerformanceMonitor) monitorLoop() {
	ticker := time.NewTicker(pm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.check()
		case <-pm.stopChan:
			return
		}
	}
}

// check 执行检查
func (pm *PerformanceMonitor) check() {
	pm.mu.Lock()

	now := time.Now()
	windowDuration := now.Sub(pm.windowStart).Seconds()

	if windowDuration < 1 {
		pm.mu.Unlock()
		return // 窗口太小，跳过
	}

	// 计算当前指标
	pm.currentQPS = float64(pm.requestCount) / windowDuration
	if pm.requestCount > 0 {
		pm.currentAvgRT = float64(pm.totalResponseTime) / float64(pm.requestCount)
		pm.currentErrorRate = float64(pm.errorCount) / float64(pm.requestCount)
	} else {
		pm.currentAvgRT = 0
		pm.currentErrorRate = 0
	}

	// 记录历史
	pm.qpsHistory = append(pm.qpsHistory, pm.currentQPS)
	pm.rtHistory = append(pm.rtHistory, pm.currentAvgRT)
	pm.errorRateHistory = append(pm.errorRateHistory, pm.currentErrorRate)

	if len(pm.qpsHistory) > pm.maxHistorySize {
		pm.qpsHistory = pm.qpsHistory[1:]
		pm.rtHistory = pm.rtHistory[1:]
		pm.errorRateHistory = pm.errorRateHistory[1:]
	}

	// 如果还没有基线，设置基线
	if pm.baselineQPS == 0 && len(pm.qpsHistory) >= 10 {
		pm.setBaseline()
	}

	// 检查性能偏差
	if pm.baselineQPS > 0 {
		pm.checkPerformanceDeviation()
	}

	// 重置窗口
	pm.requestCount = 0
	pm.totalResponseTime = 0
	pm.slowRequestCount = 0
	pm.errorCount = 0
	pm.windowStart = now
	pm.lastCheckTime = now

	pm.mu.Unlock()
}

// setBaseline 设置性能基线
func (pm *PerformanceMonitor) setBaseline() {
	// 使用最近10次的平均值作为基线
	recentQPS := pm.qpsHistory[len(pm.qpsHistory)-10:]
	recentRT := pm.rtHistory[len(pm.rtHistory)-10:]
	recentErrorRate := pm.errorRateHistory[len(pm.errorRateHistory)-10:]

	pm.baselineQPS = averageFloat64(recentQPS)
	pm.baselineAvgRT = averageFloat64(recentRT)
	pm.baselineErrorRate = averageFloat64(recentErrorRate)

	pm.log.Infof("性能基线已设置: QPS=%.2f, AvgRT=%.2fms, ErrorRate=%.4f%%",
		pm.baselineQPS, pm.baselineAvgRT, pm.baselineErrorRate*100)
}

// checkPerformanceDeviation 检查性能偏差
func (pm *PerformanceMonitor) checkPerformanceDeviation() {
	// 检查QPS偏差 — 低流量基线时绝对量极小，增加绝对量下限避免噪声
	const minQPSForDeviation = 5.0
	if pm.baselineQPS > 0 && pm.currentQPS > minQPSForDeviation {
		qpsDeviation := (pm.currentQPS - pm.baselineQPS) / pm.baselineQPS
		if qpsDeviation < -pm.qpsDeviationThreshold {
			pm.qpsWarningCount++
			pm.log.Warnf("🟡 QPS显著下降: 当前=%.2f, 基线=%.2f, 下降=%.1f%%",
				pm.currentQPS, pm.baselineQPS, qpsDeviation*100)
		} else if qpsDeviation > pm.qpsDeviationThreshold {
			pm.log.Infof("✅ QPS显著上升: 当前=%.2f, 基线=%.2f, 上升=%.1f%%",
				pm.currentQPS, pm.baselineQPS, qpsDeviation*100)
		}
	}

	// 检查响应时间偏差
	if pm.baselineAvgRT > 0 {
		rtDeviation := (pm.currentAvgRT - pm.baselineAvgRT) / pm.baselineAvgRT
		if rtDeviation > pm.rtDeviationThreshold {
			pm.rtWarningCount++
			pm.log.Warnf("🟡 响应时间显著增加: 当前=%.2fms, 基线=%.2fms, 增加=%.1f%%",
				pm.currentAvgRT, pm.baselineAvgRT, rtDeviation*100)
		}
	}

	// 检查错误率增长
	if pm.baselineErrorRate > 0 {
		errorRateIncrease := pm.currentErrorRate / pm.baselineErrorRate
		if errorRateIncrease > pm.errorRateIncreaseThreshold {
			pm.errorRateWarningCount++
			pm.log.Warnf("🔴 错误率显著增加: 当前=%.4f%%, 基线=%.4f%%, 增长=%.1f倍",
				pm.currentErrorRate*100, pm.baselineErrorRate*100, errorRateIncrease)
		}
	} else if pm.currentErrorRate > 0.01 { // 基线为0但当前错误率>1%
		pm.errorRateWarningCount++
		pm.log.Warnf("🔴 错误率异常: 当前=%.4f%% (基线为0)",
			pm.currentErrorRate*100)
	}
}

// RecordRequest 记录请求
func (pm *PerformanceMonitor) RecordRequest(responseTime time.Duration, isError bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.requestCount++
	pm.totalResponseTime += responseTime.Milliseconds()

	if isError {
		pm.errorCount++
	}

	// 慢请求（超过1秒）
	if responseTime > time.Second {
		pm.slowRequestCount++
	}
}

// GetStats 获取统计信息
func (pm *PerformanceMonitor) GetStats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return map[string]interface{}{
		"baseline_qps":             pm.baselineQPS,
		"baseline_avg_rt_ms":       pm.baselineAvgRT,
		"baseline_error_rate":      pm.baselineErrorRate,
		"current_qps":              pm.currentQPS,
		"current_avg_rt_ms":        pm.currentAvgRT,
		"current_error_rate":       pm.currentErrorRate,
		"qps_warning_count":        pm.qpsWarningCount,
		"rt_warning_count":         pm.rtWarningCount,
		"error_rate_warning_count": pm.errorRateWarningCount,
		"last_check_time":          pm.lastCheckTime,
		"window_request_count":     pm.requestCount,
		"window_slow_count":        pm.slowRequestCount,
	}
}

// ResetBaseline 重置基线
func (pm *PerformanceMonitor) ResetBaseline() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.baselineQPS = 0
	pm.baselineAvgRT = 0
	pm.baselineErrorRate = 0
	pm.qpsWarningCount = 0
	pm.rtWarningCount = 0
	pm.errorRateWarningCount = 0

	pm.log.Info("性能基线已重置，将在收集10次数据后重新设置")
}

// 辅助函数
func averageFloat64(nums []float64) float64 {
	if len(nums) == 0 {
		return 0
	}
	sum := 0.0
	for _, n := range nums {
		sum += n
	}
	return sum / float64(len(nums))
}
