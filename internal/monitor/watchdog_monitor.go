package monitor

import (
	"fmt"
	"net"
	"os"
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
	// 内存监控选项
	MemoryThresholdMB         int64   // 内存绝对阈值（MB）
	MemoryThresholdPercent    float64 // 内存占用百分比阈值
	MemoryIncreaseThresholdMB int64   // 内存增长阈值（MB）
	MemoryIncreaseWindow      time.Duration
	// 自动退出选项
	ExitOnMemoryThreshold bool // 达到内存阈值时自动退出
	ExitOnCPUThreshold    bool // 达到CPU阈值时自动退出
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
	stopOnce        sync.Once
	options         WatchdogMonitorOptions
	notificationMgr *notification.NotificationManager
	history         []ProcessStatsRecord
	historyMutex    sync.RWMutex
	maxHistorySize  int

	// 报警冷却时间记录
	lastAbsoluteAlertTime time.Time
	lastIncreaseAlertTime time.Time
	alertMutex            sync.RWMutex

	// 运行实例标识
	hostName string
	hostIP   string
}

// NewWatchdogMonitor 创建看门狗监控器
func NewWatchdogMonitor(opts WatchdogMonitorOptions, notificationMgr *notification.NotificationManager) *WatchdogMonitor {
	normalized := opts.normalize()
	hostName, hostIP := resolveHostInfo()
	return &WatchdogMonitor{
		log: logrus.WithFields(logrus.Fields{
			"component": "watchdog_monitor",
		}),
		stopChan:        make(chan struct{}),
		options:         normalized,
		notificationMgr: notificationMgr,
		history:         make([]ProcessStatsRecord, 0),
		maxHistorySize:  1000, // 保存足够多的历史数据
		hostName:        hostName,
		hostIP:          hostIP,
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
	wm.stopOnce.Do(func() {
		close(wm.stopChan)
		wm.log.Info("看门狗监控器已停止")
	})
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
		"current_cpu":    fmt.Sprintf("%.2f", current.CPUPercent),
		"current_memory": fmt.Sprintf("%.2f", current.MemoryPercent),
		"timestamp":      current.Timestamp.Format(time.RFC3339),
		"hostname":       wm.hostName,
		"host_ip":        wm.hostIP,
	}

	if alertType == "absolute_threshold" {
		title = "CPU utilization exceeded threshold"
		message = fmt.Sprintf("Current process CPU utilization is %.2f%%, exceeding the configured threshold of %.2f%% (Host: %s, IP: %s)",
			current.CPUPercent, wm.options.CPUThresholdPercent, wm.hostName, wm.hostIP)
		details["threshold"] = fmt.Sprintf("%.2f", wm.options.CPUThresholdPercent)
	} else if alertType == "increase_trend" {
		title = "CPU utilization rapid increase"
		if baseline != nil {
			increase := current.CPUPercent - baseline.CPUPercent
			message = fmt.Sprintf("CPU utilization increased from %.2f%% to %.2f%% (increase: %.2f%%) within %v, exceeding the configured increase threshold of %.2f%% (Host: %s, IP: %s)",
				baseline.CPUPercent, current.CPUPercent, increase, wm.options.CPUIncreaseWindow, wm.options.CPUIncreaseThresholdPercent, wm.hostName, wm.hostIP)
			details["baseline_cpu"] = fmt.Sprintf("%.2f", baseline.CPUPercent)
			details["baseline_memory"] = fmt.Sprintf("%.2f", baseline.MemoryPercent)
			details["increase"] = fmt.Sprintf("%.2f", increase)
			details["increase_window"] = wm.options.CPUIncreaseWindow.String()
		}
		details["increase_threshold"] = fmt.Sprintf("%.2f", wm.options.CPUIncreaseThresholdPercent)
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

func resolveHostInfo() (string, string) {
	hostName, err := os.Hostname()
	if err != nil || hostName == "" {
		hostName = "unknown"
	}

	hostIP := firstNonLoopbackIPv4()
	if hostIP == "" {
		hostIP = "unknown"
	}

	return hostName, hostIP
}

func firstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String()
		}
	}

	return ""
}
