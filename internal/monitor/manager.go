package monitor

import (
	"time"

	"github.com/sirupsen/logrus"
)

// Manager 监控管理器（统一管理所有监控器）
type Manager struct {
	log                *logrus.Entry
	goroutineMonitor   *GoroutineMonitor
	memoryMonitor      *MemoryMonitor
	performanceMonitor *PerformanceMonitor
	enabled            bool
}

// NewManager 创建监控管理器
func NewManager(enabled bool) *Manager {
	return &Manager{
		log: logrus.WithFields(logrus.Fields{
			"component": "monitor_manager",
		}),
		enabled: enabled,
	}
}

// Start 启动所有监控器
func (m *Manager) Start() {
	if !m.enabled {
		m.log.Info("监控功能已禁用")
		return
	}
	
	m.log.Info("启动监控管理器...")
	
	// 启动Goroutine监控器（每1分钟检查一次）
	m.goroutineMonitor = NewGoroutineMonitor(1 * time.Minute)
	m.goroutineMonitor.Start()
	
	// 启动内存监控器（每1分钟检查一次）
	m.memoryMonitor = NewMemoryMonitor(1 * time.Minute)
	m.memoryMonitor.Start()
	
	// 启动性能监控器（每30秒检查一次）
	m.performanceMonitor = NewPerformanceMonitor(30 * time.Second)
	m.performanceMonitor.Start()
	
	m.log.Info("监控管理器已启动（Goroutine监控、内存监控、性能监控）")
}

// Stop 停止所有监控器
func (m *Manager) Stop() {
	if !m.enabled {
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
	
	return stats
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

