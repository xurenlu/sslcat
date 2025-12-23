package monitor

import (
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/notification"
)

// Manager 监控管理器（统一管理所有监控器）
type ManagerOptions struct {
	Enabled  bool
	Memory   MemoryMonitorOptions
	Watchdog WatchdogMonitorOptions
}

// Manager 监控管理器（统一管理所有监控器）
type Manager struct {
	log                *logrus.Entry
	goroutineMonitor   *GoroutineMonitor
	memoryMonitor      *MemoryMonitor
	performanceMonitor *PerformanceMonitor
	watchdogMonitor    *WatchdogMonitor
	options            ManagerOptions
}

// NewManager 创建监控管理器
func NewManager(opts ManagerOptions) *Manager {
	normalized := opts
	normalized.Memory = normalized.Memory.normalize()
	return &Manager{
		log: logrus.WithFields(logrus.Fields{
			"component": "monitor_manager",
		}),
		options: normalized,
	}
}

// Start 启动所有监控器
func (m *Manager) Start(notificationMgr interface{}) {
	if !m.options.Enabled {
		m.log.Info("监控功能已禁用")
		return
	}

	m.log.Info("启动监控管理器...")

	// 启动Goroutine监控器（每1分钟检查一次）
	m.goroutineMonitor = NewGoroutineMonitor(1 * time.Minute)
	m.goroutineMonitor.Start()

	// 启动内存监控器（每1分钟检查一次）
	m.memoryMonitor = NewMemoryMonitor(m.options.Memory)
	m.memoryMonitor.Start()

	// 启动性能监控器（每30秒检查一次）
	m.performanceMonitor = NewPerformanceMonitor(30 * time.Second)
	m.performanceMonitor.Start()

	// 启动看门狗监控器（如果启用）
	if m.options.Watchdog.Enabled {
		var nmgr *notification.NotificationManager
		if notificationMgr != nil {
			// 尝试从NotificationIntegrator获取Manager
			if integrator, ok := notificationMgr.(interface {
				GetManager() *notification.NotificationManager
			}); ok {
				nmgr = integrator.GetManager()
			} else if mgr, ok := notificationMgr.(*notification.NotificationManager); ok {
				nmgr = mgr
			}
		}
		m.watchdogMonitor = NewWatchdogMonitor(m.options.Watchdog, nmgr)
		m.watchdogMonitor.Start()
		m.log.Info("看门狗监控器已启动")
	}

	m.log.Info("监控管理器已启动（Goroutine监控、内存监控、性能监控、看门狗监控）")
}

// Stop 停止所有监控器
func (m *Manager) Stop() {
	if !m.options.Enabled {
		return
	}

	m.log.Info("停止监控管理器...")

	if m.goroutineMonitor != nil {
		m.goroutineMonitor.Stop()
	}

	if m.memoryMonitor != nil {
		m.memoryMonitor.Stop()
	}

	if m.performanceMonitor != nil {
		m.performanceMonitor.Stop()
	}

	if m.watchdogMonitor != nil {
		m.watchdogMonitor.Stop()
	}

	m.log.Info("监控管理器已停止")
}

// GetGoroutineMonitor 获取Goroutine监控器
func (m *Manager) GetGoroutineMonitor() *GoroutineMonitor {
	return m.goroutineMonitor
}

// GetMemoryMonitor 获取内存监控器
func (m *Manager) GetMemoryMonitor() *MemoryMonitor {
	return m.memoryMonitor
}

// GetPerformanceMonitor 获取性能监控器
func (m *Manager) GetPerformanceMonitor() *PerformanceMonitor {
	return m.performanceMonitor
}

// GetAllStats 获取所有监控统计
func (m *Manager) GetAllStats() map[string]interface{} {
	stats := make(map[string]interface{})

	if m.goroutineMonitor != nil {
		stats["goroutine"] = m.goroutineMonitor.GetStats()
	}

	if m.memoryMonitor != nil {
		stats["memory"] = m.memoryMonitor.GetStats()
	}

	if m.performanceMonitor != nil {
		stats["performance"] = m.performanceMonitor.GetStats()
	}

	if m.watchdogMonitor != nil {
		stats["watchdog"] = m.watchdogMonitor.GetStats()
	}

	return stats
}

// UpdateMemoryMonitorOptions 更新内存监控配置
func (m *Manager) UpdateMemoryMonitorOptions(opts MemoryMonitorOptions) {
	m.options.Memory = opts.normalize()
	if m.memoryMonitor != nil {
		m.memoryMonitor.UpdateOptions(m.options.Memory)
	}
}

// ResetAllBaselines 重置所有基线
func (m *Manager) ResetAllBaselines() {
	m.log.Info("重置所有监控基线...")

	if m.goroutineMonitor != nil {
		m.goroutineMonitor.ResetBaseline()
	}

	if m.memoryMonitor != nil {
		m.memoryMonitor.ResetBaseline()
	}

	if m.performanceMonitor != nil {
		m.performanceMonitor.ResetBaseline()
	}

	m.log.Info("所有监控基线已重置")
}

// GetWatchdogMonitor 获取看门狗监控器
func (m *Manager) GetWatchdogMonitor() *WatchdogMonitor {
	return m.watchdogMonitor
}

// UpdateWatchdogOptions 更新看门狗监控配置
func (m *Manager) UpdateWatchdogOptions(opts WatchdogMonitorOptions) {
	m.options.Watchdog = opts.normalize()
	if m.watchdogMonitor != nil {
		m.watchdogMonitor.UpdateOptions(m.options.Watchdog)
	}
}
