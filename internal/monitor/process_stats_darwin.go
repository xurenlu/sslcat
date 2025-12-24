//go:build darwin
// +build darwin

package monitor

import (
	"fmt"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DarwinProcessStatsReader macOS系统进程统计读取器
type DarwinProcessStatsReader struct {
	lastCPUTimeUs uint64    // 上次CPU时间（微秒）
	lastSysTime   time.Time // 上次采样时间
	numCPU        int       // CPU核心数
}

func (r *DarwinProcessStatsReader) GetProcessStats() (*ProcessStats, error) {
	if r.numCPU == 0 {
		r.numCPU = runtime.NumCPU()
		r.lastSysTime = time.Now()
	}

	stats := &ProcessStats{
		Timestamp: time.Now(),
	}

	// 获取系统总内存
	totalMem, err := r.getTotalMemory()
	if err != nil {
		return nil, fmt.Errorf("获取系统内存失败: %w", err)
	}

	// 获取进程内存
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	processMem := m.Sys

	// 计算内存占用百分比
	if totalMem > 0 {
		stats.MemoryPercent = (float64(processMem) / float64(totalMem)) * 100
	}

	// 获取CPU时间并计算CPU占用百分比
	cpuTimeUs, err := r.getCPUTime()
	if err != nil {
		return nil, fmt.Errorf("获取CPU时间失败: %w", err)
	}

	// 计算CPU占用百分比
	now := time.Now()
	if r.lastSysTime.IsZero() {
		r.lastSysTime = now
		r.lastCPUTimeUs = cpuTimeUs
		stats.CPUPercent = 0.0
	} else {
		timeDiff := now.Sub(r.lastSysTime).Seconds()
		if timeDiff > 0 {
			cpuDiffUs := cpuTimeUs - r.lastCPUTimeUs
			// CPU占用 = (进程CPU时间差 / 实际时间差 / CPU核心数) * 100
			// cpuDiffUs 是微秒，timeDiff 是秒，需要统一单位
			cpuDiffSeconds := float64(cpuDiffUs) / 1e6
			totalCPUTime := timeDiff * float64(r.numCPU)
			if totalCPUTime > 0 {
				stats.CPUPercent = (cpuDiffSeconds / totalCPUTime) * 100
			}
		}
		r.lastSysTime = now
		r.lastCPUTimeUs = cpuTimeUs
	}

	return stats, nil
}

// getTotalMemory 通过 sysctl 获取系统总内存（字节）
func (r *DarwinProcessStatsReader) getTotalMemory() (uint64, error) {
	// 使用 Sysctl 获取原始数据，然后转换为 uint64
	val, err := unix.Sysctl("hw.memsize")
	if err != nil {
		// 如果 sysctl 失败，使用默认值 8GB
		return 8 * 1024 * 1024 * 1024, nil
	}
	// hw.memsize 返回的是小端序的 8 字节整数
	if len(val) >= 8 {
		var memSize uint64
		for i := 0; i < 8; i++ {
			memSize |= uint64(val[i]) << (i * 8)
		}
		return memSize, nil
	}
	// 默认返回 8GB
	return 8 * 1024 * 1024 * 1024, nil
}

// getCPUTime 通过 getrusage 获取进程CPU时间（单位：微秒）
func (r *DarwinProcessStatsReader) getCPUTime() (uint64, error) {
	var rusage syscall.Rusage
	err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage)
	if err != nil {
		return 0, fmt.Errorf("getrusage失败: %w", err)
	}

	// 用户态时间 + 内核态时间（转换为微秒）
	userTimeUs := uint64(rusage.Utime.Sec)*1e6 + uint64(rusage.Utime.Usec)
	sysTimeUs := uint64(rusage.Stime.Sec)*1e6 + uint64(rusage.Stime.Usec)
	return userTimeUs + sysTimeUs, nil
}

