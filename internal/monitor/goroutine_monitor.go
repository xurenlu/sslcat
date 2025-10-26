package monitor

import (
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// GoroutineMonitor Goroutine监控器
type GoroutineMonitor struct {
	log               *logrus.Entry
	stopChan          chan struct{}
	checkInterval     time.Duration
	baselineCount     int
	warningThreshold  int // 超过基线多少时发出警告
	criticalThreshold int // 超过基线多少时发出严重警告

	// 统计数据
	mu            sync.RWMutex
	currentCount  int
	peakCount     int
	peakTime      time.Time
	warningCount  int
	criticalCount int
	lastCheckTime time.Time

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

	return &GoroutineMonitor{
		log: logrus.WithFields(logrus.Fields{
			"component": "goroutine_monitor",
		}),
		stopChan:          make(chan struct{}),
		checkInterval:     checkInterval,
		baselineCount:     runtime.NumGoroutine(), // 启动时的goroutine数量作为基线
		warningThreshold:  100,                    // 超过基线100个时警告
		criticalThreshold: 500,                    // 超过基线500个时严重警告
		maxHistorySize:    100,                    // 保留最近100次检查记录
		history:           make([]int, 0, 100),
		lastCheckTime:     time.Now(),
	}
}

// Start 启动监控
func (gm *GoroutineMonitor) Start() {
	gm.log.Infof("Goroutine监控器已启动，基线数量: %d, 检查间隔: %v", gm.baselineCount, gm.checkInterval)

	go gm.monitorLoop()
}

// Stop 停止监控
func (gm *GoroutineMonitor) Stop() {
	if gm.stopChan != nil {
		close(gm.stopChan)
		gm.stopChan = nil
	}
	gm.log.Info("Goroutine监控器已停止")
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

// check 执行检查
func (gm *GoroutineMonitor) check() {
	currentCount := runtime.NumGoroutine()
	now := time.Now()

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

	// 检查是否超过阈值
	diff := currentCount - gm.baselineCount

	if diff > gm.criticalThreshold {
		gm.criticalCount++
		gm.mu.Unlock()
		gm.log.Errorf("🔴 Goroutine严重泄漏警告: 当前=%d, 基线=%d, 增长=%d (超过严重阈值%d)",
			currentCount, gm.baselineCount, diff, gm.criticalThreshold)

		// 输出堆栈信息（用于调试）
		gm.dumpGoroutineStack()
		return
	}

	if diff > gm.warningThreshold {
		gm.warningCount++
		gm.mu.Unlock()
		gm.log.Warnf("🟡 Goroutine泄漏警告: 当前=%d, 基线=%d, 增长=%d (超过警告阈值%d)",
			currentCount, gm.baselineCount, diff, gm.warningThreshold)
		return
	}

	gm.mu.Unlock()

	// 正常情况下，每10次检查输出一次信息
	if gm.currentCount%10 == 0 {
		gm.log.Debugf("Goroutine检查: 当前=%d, 基线=%d, 峰值=%d, 趋势=%s",
			currentCount, gm.baselineCount, gm.peakCount, gm.getTrend())
	}
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

	if len(gm.history) < 10 {
		return "数据不足"
	}

	// 比较最近10次和之前10次的平均值
	recent := gm.history[len(gm.history)-10:]
	previous := gm.history[len(gm.history)-20 : len(gm.history)-10]

	recentAvg := average(recent)
	previousAvg := average(previous)

	diff := recentAvg - previousAvg

	if diff > 10 {
		return "上升↑"
	} else if diff < -10 {
		return "下降↓"
	}
	return "稳定→"
}

// GetStats 获取统计信息
func (gm *GoroutineMonitor) GetStats() map[string]interface{} {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	return map[string]interface{}{
		"current_count":     gm.currentCount,
		"baseline_count":    gm.baselineCount,
		"peak_count":        gm.peakCount,
		"peak_time":         gm.peakTime,
		"warning_count":     gm.warningCount,
		"critical_count":    gm.criticalCount,
		"last_check_time":   gm.lastCheckTime,
		"trend":             gm.getTrend(),
		"growth_percentage": float64(gm.currentCount-gm.baselineCount) / float64(gm.baselineCount) * 100,
	}
}

// ResetBaseline 重置基线（在系统稳定后可以调用）
func (gm *GoroutineMonitor) ResetBaseline() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	oldBaseline := gm.baselineCount
	gm.baselineCount = gm.currentCount
	gm.warningCount = 0
	gm.criticalCount = 0

	gm.log.Infof("Goroutine基线已重置: %d -> %d", oldBaseline, gm.baselineCount)
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
