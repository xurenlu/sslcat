package monitor

import (
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// 趋势描述
const (
	trendRising       = "上升↑"
	trendFalling      = "下降↓"
	trendStable       = "稳定→"
	trendInsufficient = "数据不足"
)

const (
	// defaultWarmupPeriod 预热期：启动后先观察一段时间再确定基线。
	// 监控器在服务开始接收流量之前就已启动，此时的 goroutine 数只反映空载状态，
	// 直接拿来当基线会让稳态流量下的正常连接数被误判成泄漏增长。
	defaultWarmupPeriod = 5 * time.Minute
	// defaultAlertCooldown 告警冷却：稳态抖动跨越阈值时避免每个检查周期都刷一条日志
	defaultAlertCooldown = 10 * time.Minute
	// defaultSustainedRisingChecks 连续多少个检查周期呈上升趋势才认定为疑似泄漏
	defaultSustainedRisingChecks = 3
	// trendMinSamples 趋势判定所需的最小样本数
	trendMinSamples = 20
	// trendWindowSize 趋势判定的对比窗口大小（最近一窗 vs 前一窗）
	trendWindowSize = 10
	// trendDeltaThreshold 两个窗口均值差超过该值才算上升/下降，否则视为稳定
	trendDeltaThreshold = 10.0
)

// GoroutineMonitor Goroutine监控器
type GoroutineMonitor struct {
	log               *logrus.Entry
	stopChan          chan struct{}
	stopOnce          sync.Once
	checkInterval     time.Duration
	warningThreshold  int // 超过基线多少时发出警告
	criticalThreshold int // 超过基线多少时发出严重警告

	// 告警抑制策略
	warmupPeriod          time.Duration // 预热期时长
	alertCooldown         time.Duration // 两次告警之间的最小间隔
	sustainedRisingChecks int           // 警告所需的连续上升周期数

	// 统计数据
	mu            sync.RWMutex
	baselineCount int
	baselineReady bool // 预热是否结束、基线是否已确定
	startedAt     time.Time
	currentCount  int
	peakCount     int
	peakTime      time.Time
	warningCount  int
	criticalCount int
	lastCheckTime time.Time
	lastAlertTime time.Time
	risingStreak  int // 连续呈上升趋势的检查周期数

	// 历史记录（用于趋势分析）
	history        []int
	maxHistorySize int
}

// NewGoroutineMonitor 创建Goroutine监控器
func NewGoroutineMonitor(checkInterval time.Duration) *GoroutineMonitor {
	// 使用质数间隔避免与其他定时器同时触发（61秒）
	if checkInterval == 1*time.Minute {
		checkInterval = 61 * time.Second
	}

	now := time.Now()
	return &GoroutineMonitor{
		log: logrus.WithFields(logrus.Fields{
			"component": "goroutine_monitor",
		}),
		stopChan:      make(chan struct{}),
		checkInterval: checkInterval,
		// 基线不在此刻采样：服务尚未接收流量，空载数会导致后续稳态被误报为泄漏。
		// 真正的基线在预热期结束时由样本中位数确定，见 check()。
		baselineCount:         runtime.NumGoroutine(),
		warningThreshold:      100, // 超过基线100个时警告
		criticalThreshold:     500, // 超过基线500个时严重警告
		warmupPeriod:          defaultWarmupPeriod,
		alertCooldown:         defaultAlertCooldown,
		sustainedRisingChecks: defaultSustainedRisingChecks,
		maxHistorySize:        100, // 保留最近100次检查记录
		history:               make([]int, 0, 100),
		startedAt:             now,
		lastCheckTime:         now,
	}
}

// Start 启动监控
func (gm *GoroutineMonitor) Start() {
	gm.mu.Lock()
	gm.startedAt = time.Now()
	warmup := gm.warmupPeriod
	gm.mu.Unlock()

	gm.log.Infof("Goroutine监控器已启动，检查间隔: %v, 预热期: %v（预热结束后确定基线）",
		gm.checkInterval, warmup)

	go gm.monitorLoop()
}

// Stop 停止监控
func (gm *GoroutineMonitor) Stop() {
	gm.stopOnce.Do(func() {
		close(gm.stopChan)
		gm.log.Info("Goroutine监控器已停止")
	})
}

// monitorLoop 监控循环
func (gm *GoroutineMonitor) monitorLoop() {
	ticker := time.NewTicker(gm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			gm.check()
		case <-gm.stopChan:
			return
		}
	}
}

// check 采集当前 goroutine 数并执行检查
func (gm *GoroutineMonitor) check() {
	gm.checkSample(runtime.NumGoroutine(), time.Now())
}

// checkSample 以给定样本执行一次检查并返回判定结果。
// 从 check 中拆出，以便测试用真实采样序列驱动完整判定路径。
func (gm *GoroutineMonitor) checkSample(currentCount int, now time.Time) goroutineCheckResult {
	gm.mu.Lock()
	gm.currentCount = currentCount
	gm.lastCheckTime = now

	// 更新峰值
	if currentCount > gm.peakCount {
		gm.peakCount = currentCount
		gm.peakTime = now
	}

	// 记录历史
	gm.history = append(gm.history, currentCount)
	if len(gm.history) > gm.maxHistorySize {
		gm.history = gm.history[1:]
	}

	// 预热期内只采样不告警。预热结束时以样本中位数作为基线，
	// 这样基线反映的是"带着真实流量的稳态"，而不是启动瞬间的空载值。
	if !gm.baselineReady {
		if now.Sub(gm.startedAt) < gm.warmupPeriod {
			gm.mu.Unlock()
			return goroutineCheckResult{level: alertNone, current: currentCount}
		}
		gm.baselineCount = median(gm.history)
		gm.baselineReady = true
		baseline := gm.baselineCount
		sampleCount := len(gm.history)
		warmup := gm.warmupPeriod
		gm.mu.Unlock()

		gm.log.Infof("Goroutine基线预热完成: 基线=%d (预热期%v, 样本%d个)",
			baseline, warmup, sampleCount)
		return goroutineCheckResult{level: alertNone, current: currentCount, baseline: baseline}
	}

	result := gm.evaluateLocked(currentCount, now)
	peak := gm.peakCount
	warningThreshold := gm.warningThreshold
	criticalThreshold := gm.criticalThreshold
	gm.mu.Unlock()

	// 命中阈值但处于冷却窗口内：只计数，不刷日志
	if result.suppressed {
		return result
	}

	switch result.level {
	case alertCritical:
		gm.log.Errorf("🔴 Goroutine严重泄漏警告: 当前=%d, 基线=%d, 增长=%d (超过严重阈值%d, 趋势=%s)",
			result.current, result.baseline, result.diff, criticalThreshold, result.trend)

		// 输出堆栈信息（用于调试）
		gm.dumpGoroutineStack()

	case alertWarning:
		gm.log.Warnf("🟡 Goroutine泄漏警告: 当前=%d, 基线=%d, 增长=%d (超过警告阈值%d, 已连续%d个周期上升)",
			result.current, result.baseline, result.diff, warningThreshold, result.streak)

	default:
		// 正常情况下，每10次检查输出一次信息
		if result.current%10 == 0 {
			gm.log.Debugf("Goroutine检查: 当前=%d, 基线=%d, 峰值=%d, 趋势=%s",
				result.current, result.baseline, peak, result.trend)
		}
	}

	return result
}

// alertLevel 告警级别
type alertLevel int

const (
	alertNone alertLevel = iota
	alertWarning
	alertCritical
)

// goroutineCheckResult 单次检查的判定结果
type goroutineCheckResult struct {
	level    alertLevel
	current  int
	baseline int
	diff     int
	trend    string
	streak   int
	// suppressed 表示命中了阈值但被冷却窗口抑制，不应输出日志
	suppressed bool
}

// evaluateLocked 判定本次采样是否构成泄漏告警，并更新趋势连击数与告警计数。
// 调用方必须已持有 gm.mu 写锁。
func (gm *GoroutineMonitor) evaluateLocked(currentCount int, now time.Time) goroutineCheckResult {
	// 更新趋势连击数：稳态下 goroutine 会随连接数上下波动，
	// 只有持续上升才可能是真正的泄漏。
	trend := gm.trendLocked()
	if trend == trendRising {
		gm.risingStreak++
	} else {
		gm.risingStreak = 0
	}

	result := goroutineCheckResult{
		level:    alertNone,
		current:  currentCount,
		baseline: gm.baselineCount,
		diff:     currentCount - gm.baselineCount,
		trend:    trend,
		streak:   gm.risingStreak,
	}

	// 超过阈值只说明当前水位高，叠加"持续上升"才判定为泄漏
	sustained := gm.risingStreak >= gm.sustainedRisingChecks

	switch {
	// 严重阈值不要求趋势条件：绝对增量到这个量级本身就需要人工介入
	case result.diff > gm.criticalThreshold:
		result.level = alertCritical
		gm.criticalCount++
	case result.diff > gm.warningThreshold && sustained:
		result.level = alertWarning
		gm.warningCount++
	default:
		return result
	}

	// 冷却窗口内重复命中只累加计数，避免持续刷屏
	if !gm.lastAlertTime.IsZero() && now.Sub(gm.lastAlertTime) < gm.alertCooldown {
		result.suppressed = true
		return result
	}

	gm.lastAlertTime = now
	return result
}

// dumpGoroutineStack 输出goroutine堆栈信息
func (gm *GoroutineMonitor) dumpGoroutineStack() {
	buf := make([]byte, 1024*1024) // 1MB缓冲区
	stackSize := runtime.Stack(buf, true)

	gm.log.Errorf("Goroutine堆栈信息 (前10KB):\n%s", string(buf[:min(stackSize, 10*1024)]))

	// 如果需要完整堆栈，可以写入文件
	// 这里只记录前10KB，避免日志过大
}

// getTrend 获取趋势（上升/下降/稳定）
func (gm *GoroutineMonitor) getTrend() string {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	return gm.trendLocked()
}

// trendLocked 计算趋势，调用方必须已持有 gm.mu（读锁或写锁）
func (gm *GoroutineMonitor) trendLocked() string {
	// 比较最近一个窗口和前一个窗口的平均值
	historyLen := len(gm.history)
	if historyLen < trendMinSamples {
		return trendInsufficient
	}

	recent := gm.history[historyLen-trendWindowSize:]
	previous := gm.history[historyLen-trendMinSamples : historyLen-trendWindowSize]

	diff := average(recent) - average(previous)

	switch {
	case diff > trendDeltaThreshold:
		return trendRising
	case diff < -trendDeltaThreshold:
		return trendFalling
	default:
		return trendStable
	}
}

// GetStats 获取统计信息
func (gm *GoroutineMonitor) GetStats() map[string]interface{} {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	growthPercentage := 0.0
	if gm.baselineCount > 0 {
		growthPercentage = float64(gm.currentCount-gm.baselineCount) / float64(gm.baselineCount) * 100
	}

	return map[string]interface{}{
		"current_count":   gm.currentCount,
		"baseline_count":  gm.baselineCount,
		"baseline_ready":  gm.baselineReady,
		"peak_count":      gm.peakCount,
		"peak_time":       gm.peakTime,
		"warning_count":   gm.warningCount,
		"critical_count":  gm.criticalCount,
		"last_check_time": gm.lastCheckTime,
		"last_alert_time": gm.lastAlertTime,
		"rising_streak":   gm.risingStreak,
		// 直接调用 trendLocked：此处已持有读锁，走 getTrend 会递归加锁
		"trend":             gm.trendLocked(),
		"growth_percentage": growthPercentage,
	}
}

// ResetBaseline 重置基线（在系统稳定后可以调用）
func (gm *GoroutineMonitor) ResetBaseline() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	oldBaseline := gm.baselineCount
	// check() 尚未跑过时 currentCount 为 0，此时实时采样，避免把基线重置成 0
	gm.baselineCount = gm.currentCount
	if gm.baselineCount == 0 {
		gm.baselineCount = runtime.NumGoroutine()
	}
	// 手动重置视为已完成预热：运维明确认可当前水位就是稳态
	gm.baselineReady = true
	gm.warningCount = 0
	gm.criticalCount = 0
	gm.risingStreak = 0
	gm.lastAlertTime = time.Time{}

	gm.log.Infof("Goroutine基线已重置: %d -> %d", oldBaseline, gm.baselineCount)
}

// median 返回样本中位数。相比均值，中位数不会被预热期里的偶发尖峰带偏。
func median(nums []int) int {
	if len(nums) == 0 {
		return 0
	}

	sorted := make([]int, len(nums))
	copy(sorted, nums)
	sort.Ints(sorted)

	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// 辅助函数
func average(nums []int) float64 {
	if len(nums) == 0 {
		return 0
	}
	sum := 0
	for _, n := range nums {
		sum += n
	}
	return float64(sum) / float64(len(nums))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
