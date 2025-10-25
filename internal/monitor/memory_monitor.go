package monitor

import (
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// MemoryMonitor 内存监控器
type MemoryMonitor struct {
	log              *logrus.Entry
	stopChan         chan struct{}
	checkInterval    time.Duration
	baselineAlloc    uint64 // 基线内存分配（字节）
	warningThreshold uint64 // 警告阈值（字节）
	criticalThreshold uint64 // 严重警告阈值（字节）
	
	// 统计数据
	mu              sync.RWMutex
	currentAlloc    uint64
	currentSys      uint64
	peakAlloc       uint64
	peakTime        time.Time
	warningCount    int
	criticalCount   int
	lastCheckTime   time.Time
	lastGCTime      time.Time
	gcCount         uint32
	
	// 历史记录（用于趋势分析）
	allocHistory    []uint64
	sysHistory      []uint64
	maxHistorySize  int
}

// NewMemoryMonitor 创建内存监控器
func NewMemoryMonitor(checkInterval time.Duration) *MemoryMonitor {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	return &MemoryMonitor{
		log: logrus.WithFields(logrus.Fields{
			"component": "memory_monitor",
		}),
		stopChan:          make(chan struct{}),
		checkInterval:     checkInterval,
		baselineAlloc:     m.Alloc,
		warningThreshold:  500 * 1024 * 1024,  // 500MB增长警告
		criticalThreshold: 1024 * 1024 * 1024, // 1GB增长严重警告
		maxHistorySize:    100,
		allocHistory:      make([]uint64, 0, 100),
		sysHistory:        make([]uint64, 0, 100),
		lastCheckTime:     time.Now(),
	}
}

// Start 启动监控
func (mm *MemoryMonitor) Start() {
	mm.log.Infof("内存监控器已启动，基线内存: %.2f MB, 检查间隔: %v",
		float64(mm.baselineAlloc)/(1024*1024), mm.checkInterval)
	
	go mm.monitorLoop()
}

// Stop 停止监控
func (mm *MemoryMonitor) Stop() {
	if mm.stopChan != nil {
		close(mm.stopChan)
		mm.stopChan = nil
	}
	mm.log.Info("内存监控器已停止")
}

// monitorLoop 监控循环
func (mm *MemoryMonitor) monitorLoop() {
	ticker := time.NewTicker(mm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.check()
		case <-mm.stopChan:
			return
		}
	}
}

// check 执行检查
func (mm *MemoryMonitor) check() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	now := time.Now()
	
	mm.mu.Lock()
	mm.currentAlloc = m.Alloc
	mm.currentSys = m.Sys
	mm.lastCheckTime = now
	
	// 更新峰值
	if m.Alloc > mm.peakAlloc {
		mm.peakAlloc = m.Alloc
		mm.peakTime = now
	}
	
	// 记录历史
	mm.allocHistory = append(mm.allocHistory, m.Alloc)
	mm.sysHistory = append(mm.sysHistory, m.Sys)
	if len(mm.allocHistory) > mm.maxHistorySize {
		mm.allocHistory = mm.allocHistory[1:]
		mm.sysHistory = mm.sysHistory[1:]
	}
	
	// 检查GC
	if m.NumGC > mm.gcCount {
		mm.gcCount = m.NumGC
		mm.lastGCTime = now
	}
	
	// 检查是否超过阈值
	diff := int64(m.Alloc) - int64(mm.baselineAlloc)
	
	if diff > int64(mm.criticalThreshold) {
		mm.criticalCount++
		mm.mu.Unlock()
		mm.log.Errorf("🔴 内存严重泄漏警告: 当前=%.2f MB, 基线=%.2f MB, 增长=%.2f MB (超过严重阈值%.2f MB)",
			float64(m.Alloc)/(1024*1024),
			float64(mm.baselineAlloc)/(1024*1024),
			float64(diff)/(1024*1024),
			float64(mm.criticalThreshold)/(1024*1024))
		
		// 输出详细内存信息
		mm.dumpMemoryStats(&m)
		
		// 建议执行GC
		mm.log.Warn("建议执行手动GC以释放内存")
		return
	}
	
	if diff > int64(mm.warningThreshold) {
		mm.warningCount++
		mm.mu.Unlock()
		mm.log.Warnf("🟡 内存泄漏警告: 当前=%.2f MB, 基线=%.2f MB, 增长=%.2f MB (超过警告阈值%.2f MB)",
			float64(m.Alloc)/(1024*1024),
			float64(mm.baselineAlloc)/(1024*1024),
			float64(diff)/(1024*1024),
			float64(mm.warningThreshold)/(1024*1024))
		return
	}
	
	mm.mu.Unlock()
	
	// 正常情况下，每10次检查输出一次信息
	if mm.gcCount%10 == 0 {
		mm.log.Debugf("内存检查: 当前=%.2f MB, 系统=%.2f MB, 峰值=%.2f MB, GC次数=%d, 趋势=%s",
			float64(m.Alloc)/(1024*1024),
			float64(m.Sys)/(1024*1024),
			float64(mm.peakAlloc)/(1024*1024),
			m.NumGC,
			mm.getTrend())
	}
}

// dumpMemoryStats 输出详细内存统计
func (mm *MemoryMonitor) dumpMemoryStats(m *runtime.MemStats) {
	mm.log.Errorf(`详细内存统计:
  Alloc = %.2f MB (当前堆内存分配)
  TotalAlloc = %.2f MB (累计堆内存分配)
  Sys = %.2f MB (从系统获取的内存)
  NumGC = %d (GC次数)
  HeapAlloc = %.2f MB (堆内存分配)
  HeapSys = %.2f MB (堆系统内存)
  HeapIdle = %.2f MB (堆空闲内存)
  HeapInuse = %.2f MB (堆使用中内存)
  HeapReleased = %.2f MB (堆已释放内存)
  StackInuse = %.2f MB (栈使用中内存)
  StackSys = %.2f MB (栈系统内存)`,
		float64(m.Alloc)/(1024*1024),
		float64(m.TotalAlloc)/(1024*1024),
		float64(m.Sys)/(1024*1024),
		m.NumGC,
		float64(m.HeapAlloc)/(1024*1024),
		float64(m.HeapSys)/(1024*1024),
		float64(m.HeapIdle)/(1024*1024),
		float64(m.HeapInuse)/(1024*1024),
		float64(m.HeapReleased)/(1024*1024),
		float64(m.StackInuse)/(1024*1024),
		float64(m.StackSys)/(1024*1024))
}

// getTrend 获取趋势（上升/下降/稳定）
func (mm *MemoryMonitor) getTrend() string {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	if len(mm.allocHistory) < 10 {
		return "数据不足"
	}
	
	// 比较最近10次和之前10次的平均值
	recent := mm.allocHistory[len(mm.allocHistory)-10:]
	previous := mm.allocHistory[len(mm.allocHistory)-20 : len(mm.allocHistory)-10]
	
	recentAvg := averageUint64(recent)
	previousAvg := averageUint64(previous)
	
	diff := int64(recentAvg) - int64(previousAvg)
	threshold := int64(10 * 1024 * 1024) // 10MB
	
	if diff > threshold {
		return "上升↑"
	} else if diff < -threshold {
		return "下降↓"
	}
	return "稳定→"
}

// GetStats 获取统计信息
func (mm *MemoryMonitor) GetStats() map[string]interface{} {
	mm.mu.RLock()
	defer mm.mu.RUnlock()
	
	return map[string]interface{}{
		"current_alloc_mb":   float64(mm.currentAlloc) / (1024 * 1024),
		"current_sys_mb":     float64(mm.currentSys) / (1024 * 1024),
		"baseline_alloc_mb":  float64(mm.baselineAlloc) / (1024 * 1024),
		"peak_alloc_mb":      float64(mm.peakAlloc) / (1024 * 1024),
		"peak_time":          mm.peakTime,
		"warning_count":      mm.warningCount,
		"critical_count":     mm.criticalCount,
		"last_check_time":    mm.lastCheckTime,
		"last_gc_time":       mm.lastGCTime,
		"gc_count":           mm.gcCount,
		"trend":              mm.getTrend(),
		"growth_percentage":  float64(int64(mm.currentAlloc)-int64(mm.baselineAlloc)) / float64(mm.baselineAlloc) * 100,
	}
}

// ResetBaseline 重置基线（在系统稳定后可以调用）
func (mm *MemoryMonitor) ResetBaseline() {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	
	oldBaseline := mm.baselineAlloc
	mm.baselineAlloc = mm.currentAlloc
	mm.warningCount = 0
	mm.criticalCount = 0
	
	mm.log.Infof("内存基线已重置: %.2f MB -> %.2f MB",
		float64(oldBaseline)/(1024*1024),
		float64(mm.baselineAlloc)/(1024*1024))
}

// ForceGC 强制执行GC
func (mm *MemoryMonitor) ForceGC() {
	mm.log.Info("执行手动GC...")
	before := mm.currentAlloc
	
	runtime.GC()
	
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	after := m.Alloc
	freed := int64(before) - int64(after)
	
	mm.log.Infof("GC完成: 释放 %.2f MB (%.2f MB -> %.2f MB)",
		float64(freed)/(1024*1024),
		float64(before)/(1024*1024),
		float64(after)/(1024*1024))
}

// 辅助函数
func averageUint64(nums []uint64) uint64 {
	if len(nums) == 0 {
		return 0
	}
	var sum uint64
	for _, n := range nums {
		sum += n
	}
	return sum / uint64(len(nums))
}

