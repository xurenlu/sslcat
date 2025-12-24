//go:build !darwin
// +build !darwin

package monitor

import (
	"fmt"
	"runtime"
	"time"
)

// DarwinProcessStatsReader 在非 macOS 系统上的空实现
// 实际上不会被使用，因为 init() 会根据 GOOS 选择正确的读取器
type DarwinProcessStatsReader struct {
	lastCPUTimeUs uint64
	lastSysTime   time.Time
	numCPU        int
}

func (r *DarwinProcessStatsReader) GetProcessStats() (*ProcessStats, error) {
	// 在非 Darwin 系统上不应该调用此方法
	// 使用 runtime 包作为回退
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	return &ProcessStats{
		CPUPercent:    0.0,
		MemoryPercent: float64(m.Sys) / float64(8*1024*1024*1024) * 100, // 假设 8GB
		Timestamp:     time.Now(),
	}, nil
}

func (r *DarwinProcessStatsReader) getTotalMemory() (uint64, error) {
	// 非 Darwin 系统返回默认值
	return 8 * 1024 * 1024 * 1024, nil
}

func (r *DarwinProcessStatsReader) getCPUTime() (uint64, error) {
	return 0, fmt.Errorf("not supported on this platform")
}

