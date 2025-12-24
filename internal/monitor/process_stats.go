package monitor

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ProcessStats 进程统计信息
type ProcessStats struct {
	CPUPercent    float64   // CPU占用百分比（相对于系统总CPU）
	MemoryPercent float64   // 内存占用百分比（相对于系统总内存）
	Timestamp     time.Time // 时间戳
}

// ProcessStatsReader 进程统计读取器接口
type ProcessStatsReader interface {
	GetProcessStats() (*ProcessStats, error)
}

var (
	statsReader ProcessStatsReader
	log         = logrus.WithFields(logrus.Fields{"component": "process_stats"})
)

func init() {
	// 根据操作系统初始化相应的读取器
	switch runtime.GOOS {
	case "linux":
		statsReader = &LinuxProcessStatsReader{}
	case "darwin":
		statsReader = &DarwinProcessStatsReader{}
	default:
		statsReader = &FallbackProcessStatsReader{}
		log.Warnf("未支持的操作系统 %s，使用回退方案", runtime.GOOS)
	}
}

// GetProcessStats 获取当前进程的统计信息
func GetProcessStats() (*ProcessStats, error) {
	if statsReader == nil {
		return nil, fmt.Errorf("进程统计读取器未初始化")
	}
	return statsReader.GetProcessStats()
}

// LinuxProcessStatsReader Linux系统进程统计读取器
type LinuxProcessStatsReader struct {
	lastCPUTime uint64
	lastSysTime time.Time
	numCPU      int
}

func (r *LinuxProcessStatsReader) GetProcessStats() (*ProcessStats, error) {
	if r.numCPU == 0 {
		r.numCPU = runtime.NumCPU()
		r.lastSysTime = time.Now()
	}

	stats := &ProcessStats{
		Timestamp: time.Now(),
	}

	// 读取 /proc/self/stat 获取CPU时间
	cpuTime, err := r.getCPUTime()
	if err != nil {
		return nil, fmt.Errorf("获取CPU时间失败: %w", err)
	}

	// 读取 /proc/meminfo 获取系统内存
	totalMem, err := r.getTotalMemory()
	if err != nil {
		return nil, fmt.Errorf("获取系统内存失败: %w", err)
	}

	// 读取进程内存
	processMem, err := r.getProcessMemory()
	if err != nil {
		return nil, fmt.Errorf("获取进程内存失败: %w", err)
	}

	// 计算CPU占用百分比
	now := time.Now()
	if r.lastSysTime.IsZero() {
		r.lastSysTime = now
		r.lastCPUTime = cpuTime
		stats.CPUPercent = 0.0
	} else {
		timeDiff := now.Sub(r.lastSysTime).Seconds()
		if timeDiff > 0 {
			cpuDiff := cpuTime - r.lastCPUTime
			// CPU占用 = (进程CPU时间差 / 总CPU时间差) * 100
			// 总CPU时间差 = 时间差 * CPU核心数
			totalCPUTime := timeDiff * float64(r.numCPU) * 100 // 转换为百分之一秒
			if totalCPUTime > 0 {
				stats.CPUPercent = (float64(cpuDiff) / totalCPUTime) * 100
			}
		}
		r.lastSysTime = now
		r.lastCPUTime = cpuTime
	}

	// 计算内存占用百分比
	if totalMem > 0 {
		stats.MemoryPercent = (float64(processMem) / float64(totalMem)) * 100
	}

	return stats, nil
}

// getCPUTime 从 /proc/self/stat 获取CPU时间（单位：百分之一秒）
func (r *LinuxProcessStatsReader) getCPUTime() (uint64, error) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}

	// /proc/self/stat 格式：
	// pid comm state ppid ... utime stime cutime cstime ...
	// utime (14) + stime (15) = 用户态时间 + 内核态时间
	fields := strings.Fields(string(data))
	if len(fields) < 16 {
		return 0, fmt.Errorf("stat文件格式错误")
	}

	utime, err := strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("解析utime失败: %w", err)
	}

	stime, err := strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("解析stime失败: %w", err)
	}

	return utime + stime, nil
}

// getTotalMemory 从 /proc/meminfo 获取系统总内存（字节）
func (r *LinuxProcessStatsReader) getTotalMemory() (uint64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					return 0, fmt.Errorf("解析MemTotal失败: %w", err)
				}
				return kb * 1024, nil // 转换为字节
			}
		}
	}

	return 0, fmt.Errorf("未找到MemTotal")
}

// getProcessMemory 从 /proc/self/status 获取进程RSS内存（字节）
func (r *LinuxProcessStatsReader) getProcessMemory() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					return 0, fmt.Errorf("解析VmRSS失败: %w", err)
				}
				return kb * 1024, nil // 转换为字节
			}
		}
	}

	return 0, fmt.Errorf("未找到VmRSS")
}

// DarwinProcessStatsReader macOS系统进程统计读取器
type DarwinProcessStatsReader struct {
	lastCPUTime uint64
	lastSysTime time.Time
	numCPU      int
}

func (r *DarwinProcessStatsReader) GetProcessStats() (*ProcessStats, error) {
	if r.numCPU == 0 {
		r.numCPU = runtime.NumCPU()
		r.lastSysTime = time.Now()
	}

	stats := &ProcessStats{
		Timestamp: time.Now(),
	}

	// macOS使用runtime包获取内存信息
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 获取系统总内存（需要系统调用，这里使用近似值）
	// 注意：macOS上获取系统总内存比较复杂，这里使用一个合理的默认值
	// 实际应用中可以通过 sysctl 命令获取
	totalMem := uint64(8 * 1024 * 1024 * 1024) // 默认8GB，实际应该从系统获取
	processMem := m.Sys

	// 计算内存占用百分比
	if totalMem > 0 {
		stats.MemoryPercent = (float64(processMem) / float64(totalMem)) * 100
	}

	// macOS上CPU占用计算比较复杂，这里使用runtime包提供的近似值
	// 实际应该使用系统调用获取更准确的值
	stats.CPUPercent = 0.0 // 暂时设为0，需要实现系统调用获取

	log.Warn("macOS系统CPU占用统计功能需要进一步实现")

	return stats, nil
}

// FallbackProcessStatsReader 回退方案：使用runtime包获取基本信息
type FallbackProcessStatsReader struct {
	lastCPUTime uint64
	lastSysTime time.Time
	numCPU      int
}

func (r *FallbackProcessStatsReader) GetProcessStats() (*ProcessStats, error) {
	if r.numCPU == 0 {
		r.numCPU = runtime.NumCPU()
		r.lastSysTime = time.Now()
	}

	stats := &ProcessStats{
		Timestamp: time.Now(),
	}

	// 使用runtime包获取内存信息
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 使用一个合理的默认值作为系统总内存
	totalMem := uint64(8 * 1024 * 1024 * 1024) // 默认8GB
	processMem := m.Sys

	// 计算内存占用百分比
	if totalMem > 0 {
		stats.MemoryPercent = (float64(processMem) / float64(totalMem)) * 100
	}

	// CPU占用无法准确获取，设为0
	stats.CPUPercent = 0.0

	log.Warn("使用回退方案，CPU占用统计不可用")

	return stats, nil
}












