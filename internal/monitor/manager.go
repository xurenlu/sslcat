package monitor

import (
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/notification"
)

// Manager 监控管理器（统一管理所有监控器）
type ManagerOptions struct {
	Enabled  bool
	Memory   MemoryMonitorOptions
	Watchdog WatchdogMonitorOptions
	MetricsStorage MetricsStorageOptions
}

// Manager 监控管理器（统一管理所有监控器）
type Manager struct {
	log                *logrus.Entry
	goroutineMonitor   *GoroutineMonitor
	memoryMonitor      *MemoryMonitor
	performanceMonitor *PerformanceMonitor
	watchdogMonitor    *WatchdogMonitor
	metricsStorage     *MetricsStorage
	options            ManagerOptions
}

// NewManager 创建监控管理器
func NewManager(opts ManagerOptions) *Manager {
	normalized := opts
	normalized.Memory = normalized.Memory.normalize()
	
	manager := &Manager{
		log: logrus.WithFields(logrus.Fields{
			"component": "monitor_manager",
		}),
		options: normalized,
	}
	
	// 初始化指标存储（如果启用）
	if normalized.MetricsStorage.Enabled {
		metricsStorage, err := NewMetricsStorage(normalized.MetricsStorage)
		if err != nil {
			manager.log.Errorf("初始化指标存储失败: %v", err)
		} else {
			manager.metricsStorage = metricsStorage
		}
	}
	
	return manager
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

	// 启动指标存储（如果启用）
	if m.metricsStorage != nil {
		m.metricsStorage.Start()
		m.log.Info("指标存储已启动")
	}

	components := []string{"Goroutine监控", "内存监控", "性能监控"}
	if m.options.Watchdog.Enabled {
		components = append(components, "看门狗监控")
	}
	if m.metricsStorage != nil {
		components = append(components, "指标存储")
	}
	m.log.Infof("监控管理器已启动（%s）", strings.Join(components, "、"))
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

	if m.metricsStorage != nil {
		m.metricsStorage.Stop()
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

// GetWatchdogMonitor 获取看门狗监控器（用于外部查询）
func (m *Manager) GetWatchdogMonitor() *WatchdogMonitor {
	return m.watchdogMonitor
}

// GetMetricsStorage 获取指标存储（用于外部查询）
func (m *Manager) GetMetricsStorage() *MetricsStorage {
	return m.metricsStorage
}

// UpdateWatchdogOptions 更新看门狗监控配置
func (m *Manager) UpdateWatchdogOptions(opts WatchdogMonitorOptions) {
	m.options.Watchdog = opts.normalize()
	if m.watchdogMonitor != nil {
		m.watchdogMonitor.UpdateOptions(m.options.Watchdog)
	}
}

// RestartWatchdog 重启看门狗监控器
func (m *Manager) RestartWatchdog(opts WatchdogMonitorOptions, notificationMgr interface{}) error {
	m.log.Info("重启看门狗监控器...")

	// 停止现有的看门狗
	if m.watchdogMonitor != nil {
		m.watchdogMonitor.Stop()
		m.watchdogMonitor = nil
	}

	// 如果启用，启动新的看门狗
	if opts.Enabled {
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
		m.watchdogMonitor = NewWatchdogMonitor(opts, nmgr)
		m.watchdogMonitor.Start()
		m.options.Watchdog = opts
		m.log.Info("看门狗监控器已重启")
	} else {
		m.options.Watchdog = opts
		m.log.Info("看门狗监控器已停止（已禁用）")
	}

	return nil
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
