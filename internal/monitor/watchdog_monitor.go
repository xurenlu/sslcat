package monitor

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/notification"
)

// WatchdogMonitorOptions 看门狗监控器选项
type WatchdogMonitorOptions struct {
	Enabled                     bool
	CheckInterval               time.Duration
	CPUThresholdPercent         float64
	CPUIncreaseThresholdPercent float64
	CPUIncreaseWindow           time.Duration
	AlertCooldown               time.Duration
}

func (o WatchdogMonitorOptions) normalize() WatchdogMonitorOptions {
	if o.CheckInterval <= 0 {
		o.CheckInterval = 30 * time.Second
	}
	if o.CPUThresholdPercent <= 0 {
		o.CPUThresholdPercent = 30.0
	}
	if o.CPUIncreaseThresholdPercent <= 0 {
		o.CPUIncreaseThresholdPercent = 15.0
	}
	if o.CPUIncreaseWindow <= 0 {
		o.CPUIncreaseWindow = 3 * time.Minute
	}
	if o.AlertCooldown <= 0 {
		o.AlertCooldown = 1 * time.Hour
	}
	return o
}

// ProcessStatsRecord 进程统计记录（带时间戳）
type ProcessStatsRecord struct {
	Stats     *ProcessStats
	Timestamp time.Time
}

// WatchdogMonitor 看门狗监控器
type WatchdogMonitor struct {
	log             *logrus.Entry
	stopChan        chan struct{}
	options         WatchdogMonitorOptions
	notificationMgr *notification.NotificationManager
	history         []ProcessStatsRecord
	historyMutex    sync.RWMutex
	maxHistorySize  int

	// 报警冷却时间记录
	lastAbsoluteAlertTime time.Time
	lastIncreaseAlertTime time.Time
	alertMutex            sync.RWMutex
}

// NewWatchdogMonitor 创建看门狗监控器
func NewWatchdogMonitor(opts WatchdogMonitorOptions, notificationMgr *notification.NotificationManager) *WatchdogMonitor {
	normalized := opts.normalize()
	return &WatchdogMonitor{
		log: logrus.WithFields(logrus.Fields{
			"component": "watchdog_monitor",
		}),
		stopChan:        make(chan struct{}),
		options:         normalized,
		notificationMgr: notificationMgr,
		history:         make([]ProcessStatsRecord, 0),
		maxHistorySize:  1000, // 保存足够多的历史数据
	}
}

// Start 启动监控
func (wm *WatchdogMonitor) Start() {
	if !wm.options.Enabled {
		wm.log.Info("看门狗监控已禁用")
		return
	}

	wm.log.Infof("看门狗监控器已启动，检查间隔: %v, CPU阈值: %.1f%%, 增长阈值: %.1f%%",
		wm.options.CheckInterval,
		wm.options.CPUThresholdPercent,
		wm.options.CPUIncreaseThresholdPercent)

	go wm.monitorLoop()
}

// Stop 停止监控
func (wm *WatchdogMonitor) Stop() {
	if wm.stopChan != nil {
		close(wm.stopChan)
		wm.stopChan = nil
	}
	wm.log.Info("看门狗监控器已停止")
}

// monitorLoop 监控循环
func (wm *WatchdogMonitor) monitorLoop() {
	ticker := time.NewTicker(wm.options.CheckInterval)
	defer ticker.Stop()

	// 立即执行一次检查
	wm.check()

	for {
		select {
		case <-ticker.C:
			wm.check()
		case <-wm.stopChan:
			return
		}
	}
}

// check 执行检查
func (wm *WatchdogMonitor) check() {
	stats, err := GetProcessStats()
	if err != nil {
		wm.log.Errorf("获取进程统计信息失败: %v", err)
		return
	}

	// 记录历史数据
	wm.addToHistory(stats)

	// 检查绝对阈值
	if stats.CPUPercent > wm.options.CPUThresholdPercent {
		wm.checkAbsoluteThreshold(stats)
	}

	// 检查增长趋势
	wm.checkIncreaseTrend(stats)
}

// addToHistory 添加历史记录
func (wm *WatchdogMonitor) addToHistory(stats *ProcessStats) {
	wm.historyMutex.Lock()
	defer wm.historyMutex.Unlock()

	record := ProcessStatsRecord{
		Stats:     stats,
		Timestamp: time.Now(),
	}

	wm.history = append(wm.history, record)

	// 清理过期数据（保留超过窗口期的数据用于趋势分析）
	cutoffTime := time.Now().Add(-wm.options.CPUIncreaseWindow * 2)
	validStart := 0
	for i, r := range wm.history {
		if r.Timestamp.After(cutoffTime) {
			validStart = i
			break
		}
	}
	if validStart > 0 {
		wm.history = wm.history[validStart:]
	}

	// 限制历史记录大小
	if len(wm.history) > wm.maxHistorySize {
		wm.history = wm.history[len(wm.history)-wm.maxHistorySize:]
	}
}

// checkAbsoluteThreshold 检查绝对阈值
func (wm *WatchdogMonitor) checkAbsoluteThreshold(current *ProcessStats) {
	wm.alertMutex.RLock()
	lastAlertTime := wm.lastAbsoluteAlertTime
	wm.alertMutex.RUnlock()

	// 检查冷却时间
	if time.Since(lastAlertTime) < wm.options.AlertCooldown {
		wm.log.Debugf("CPU占用超过阈值 %.1f%% (当前: %.1f%%)，但尚在冷却时间内",
			wm.options.CPUThresholdPercent, current.CPUPercent)
		return
	}

	// 发送报警
	wm.log.Warnf("🔴 CPU占用超过阈值: %.1f%% (阈值: %.1f%%)",
		current.CPUPercent, wm.options.CPUThresholdPercent)

	wm.sendAlert("absolute_threshold", current, nil)

	// 更新最后报警时间
	wm.alertMutex.Lock()
	wm.lastAbsoluteAlertTime = time.Now()
	wm.alertMutex.Unlock()
}

// checkIncreaseTrend 检查增长趋势
func (wm *WatchdogMonitor) checkIncreaseTrend(current *ProcessStats) {
	wm.historyMutex.RLock()
	defer wm.historyMutex.RUnlock()

	if len(wm.history) < 2 {
		return // 数据不足
	}

	// 查找窗口期开始时的数据
	windowStart := time.Now().Add(-wm.options.CPUIncreaseWindow)
	var baselineRecord *ProcessStatsRecord

	for i := len(wm.history) - 1; i >= 0; i-- {
		if wm.history[i].Timestamp.Before(windowStart) || wm.history[i].Timestamp.Equal(windowStart) {
			baselineRecord = &wm.history[i]
			break
		}
	}

	if baselineRecord == nil {
		return // 没有足够的历史数据
	}

	baselineCPU := baselineRecord.Stats.CPUPercent
	currentCPU := current.CPUPercent

	// 计算增长
	increase := currentCPU - baselineCPU
	if increase > wm.options.CPUIncreaseThresholdPercent {
		wm.alertMutex.RLock()
		lastAlertTime := wm.lastIncreaseAlertTime
		wm.alertMutex.RUnlock()

		// 检查冷却时间
		if time.Since(lastAlertTime) < wm.options.AlertCooldown {
			wm.log.Debugf("CPU占用增长超过阈值 (%.1f%% -> %.1f%%，增长: %.1f%%)，但尚在冷却时间内",
				baselineCPU, currentCPU, increase)
			return
		}

		// 发送报警
		wm.log.Warnf("🔴 CPU占用在 %v 内增长超过阈值: %.1f%% -> %.1f%% (增长: %.1f%%, 阈值: %.1f%%)",
			wm.options.CPUIncreaseWindow,
			baselineCPU, currentCPU, increase, wm.options.CPUIncreaseThresholdPercent)

		baselineStats := baselineRecord.Stats
		wm.sendAlert("increase_trend", current, baselineStats)

		// 更新最后报警时间
		wm.alertMutex.Lock()
		wm.lastIncreaseAlertTime = time.Now()
		wm.alertMutex.Unlock()
	}
}

// sendAlert 发送报警通知
func (wm *WatchdogMonitor) sendAlert(alertType string, current *ProcessStats, baseline *ProcessStats) {
	if wm.notificationMgr == nil {
		wm.log.Warn("通知管理器未设置，无法发送报警")
		return
	}

	var title, message string
	var level notification.NotificationLevel = notification.LevelWarning
	details := map[string]any{
		"alert_type":     alertType,
		"current_cpu":    current.CPUPercent,
		"current_memory": current.MemoryPercent,
		"timestamp":      current.Timestamp.Format(time.RFC3339),
	}

	if alertType == "absolute_threshold" {
		title = "CPU占用超过阈值"
		message = fmt.Sprintf("当前进程CPU占用 %.1f%%，超过配置的阈值 %.1f%%",
			current.CPUPercent, wm.options.CPUThresholdPercent)
		details["threshold"] = wm.options.CPUThresholdPercent
	} else if alertType == "increase_trend" {
		title = "CPU占用快速增长"
		if baseline != nil {
			increase := current.CPUPercent - baseline.CPUPercent
			message = fmt.Sprintf("CPU占用在 %v 内从 %.1f%% 增长到 %.1f%% (增长: %.1f%%)，超过配置的增长阈值 %.1f%%",
				wm.options.CPUIncreaseWindow,
				baseline.CPUPercent, current.CPUPercent, increase, wm.options.CPUIncreaseThresholdPercent)
			details["baseline_cpu"] = baseline.CPUPercent
			details["baseline_memory"] = baseline.MemoryPercent
			details["increase"] = increase
			details["increase_window"] = wm.options.CPUIncreaseWindow.String()
		}
		details["increase_threshold"] = wm.options.CPUIncreaseThresholdPercent
	}

	// 如果CPU占用非常高，提升为错误级别
	if current.CPUPercent > 80 {
		level = notification.LevelError
	}

	notif := &notification.Notification{
		Type:    notification.TypeSystemError,
		Level:   level,
		Title:   title,
		Message: message,
		Details: details,
		Source:  "watchdog_monitor",
	}

	// 异步发送，避免阻塞监控循环
	go func() {
		if err := wm.notificationMgr.Send(notif); err != nil {
			wm.log.Errorf("发送看门狗报警失败: %v", err)
		}
	}()
}

// GetStats 获取统计信息
func (wm *WatchdogMonitor) GetStats() map[string]interface{} {
	wm.historyMutex.RLock()
	defer wm.historyMutex.RUnlock()

	var currentCPU, currentMemory float64
	if len(wm.history) > 0 {
		latest := wm.history[len(wm.history)-1]
		currentCPU = latest.Stats.CPUPercent
		currentMemory = latest.Stats.MemoryPercent
	}

	return map[string]interface{}{
		"enabled":                        wm.options.Enabled,
		"current_cpu_percent":            currentCPU,
		"current_memory_percent":         currentMemory,
		"cpu_threshold_percent":          wm.options.CPUThresholdPercent,
		"cpu_increase_threshold_percent": wm.options.CPUIncreaseThresholdPercent,
		"history_count":                  len(wm.history),
		"last_check_time":                time.Now(),
	}
}

// UpdateOptions 更新配置
func (wm *WatchdogMonitor) UpdateOptions(opts WatchdogMonitorOptions) {
	normalized := opts.normalize()
	wm.options = normalized
	wm.log.Infof("看门狗监控配置已更新: 检查间隔=%v, CPU阈值=%.1f%%, 增长阈值=%.1f%%",
		normalized.CheckInterval, normalized.CPUThresholdPercent, normalized.CPUIncreaseThresholdPercent)
}





