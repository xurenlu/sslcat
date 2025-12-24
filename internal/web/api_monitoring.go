package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/monitor"
)

// MonitoringConfigResponse 监控配置响应
type MonitoringConfigResponse struct {
	// 基础监控
	Enabled                  bool    `json:"enabled"`
	MemoryMaxUsagePercent    float64 `json:"memory_max_usage_percent"`
	MemoryReleaseCooldownSec int     `json:"memory_release_cooldown_sec"`

	// 看门狗配置
	WatchdogEnabled                     bool    `json:"watchdog_enabled"`
	WatchdogCheckIntervalSec            int     `json:"watchdog_check_interval_sec"`
	WatchdogCPUThresholdPercent         float64 `json:"watchdog_cpu_threshold_percent"`
	WatchdogCPUIncreaseThresholdPercent float64 `json:"watchdog_cpu_increase_threshold_percent"`
	WatchdogCPUIncreaseWindowSec        int     `json:"watchdog_cpu_increase_window_sec"`
	WatchdogAlertCooldownSec            int     `json:"watchdog_alert_cooldown_sec"`

	// 内存监控
	WatchdogMemoryThresholdMB         int64   `json:"watchdog_memory_threshold_mb"`
	WatchdogMemoryThresholdPercent    float64 `json:"watchdog_memory_threshold_percent"`
	WatchdogMemoryIncreaseThresholdMB int64   `json:"watchdog_memory_increase_threshold_mb"`
	WatchdogMemoryIncreaseWindowSec   int     `json:"watchdog_memory_increase_window_sec"`

	// 自动退出
	WatchdogExitOnMemoryThreshold bool `json:"watchdog_exit_on_memory_threshold"`
	WatchdogExitOnCPUThreshold    bool `json:"watchdog_exit_on_cpu_threshold"`
}

// MonitoringStatsResponse 实时监控统计响应
type MonitoringStatsResponse struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryRSSMB   float64 `json:"memory_rss_mb"`
	Timestamp     string  `json:"timestamp"`
}

// handleAPIMonitoringConfig 处理监控配置的获取和更新
func (s *Server) handleAPIMonitoringConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, r.Method == "GET") {
		return
	}

	if r.Method == "GET" {
		// 获取配置
		cfg := s.config.Monitoring
		response := MonitoringConfigResponse{
			Enabled:                  cfg.Enabled,
			MemoryMaxUsagePercent:    cfg.MemoryMaxUsagePercent,
			MemoryReleaseCooldownSec: cfg.MemoryReleaseCooldownSec,

			WatchdogEnabled:                     cfg.WatchdogEnabled,
			WatchdogCheckIntervalSec:            cfg.WatchdogCheckIntervalSec,
			WatchdogCPUThresholdPercent:         cfg.WatchdogCPUThresholdPercent,
			WatchdogCPUIncreaseThresholdPercent: cfg.WatchdogCPUIncreaseThresholdPercent,
			WatchdogCPUIncreaseWindowSec:        cfg.WatchdogCPUIncreaseWindowSec,
			WatchdogAlertCooldownSec:            cfg.WatchdogAlertCooldownSec,

			WatchdogMemoryThresholdMB:         cfg.WatchdogMemoryThresholdMB,
			WatchdogMemoryThresholdPercent:    cfg.WatchdogMemoryThresholdPercent,
			WatchdogMemoryIncreaseThresholdMB: cfg.WatchdogMemoryIncreaseThresholdMB,
			WatchdogMemoryIncreaseWindowSec:   cfg.WatchdogMemoryIncreaseWindowSec,

			WatchdogExitOnMemoryThreshold: cfg.WatchdogExitOnMemoryThreshold,
			WatchdogExitOnCPUThreshold:    cfg.WatchdogExitOnCPUThreshold,
		}

		s.writeSuccessResponse(w, response, "Monitoring config retrieved successfully")
		return
	}

	if r.Method == "POST" || r.Method == "PUT" {
		// 更新配置
		var req MonitoringConfigResponse
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}

		// 验证和更新配置
		cfg := s.config.Monitoring

		// 基础监控配置
		if req.MemoryMaxUsagePercent > 0 {
			if req.MemoryMaxUsagePercent < 5 || req.MemoryMaxUsagePercent > 90 {
				s.writeErrorResponse(w, http.StatusBadRequest, "memory_max_usage_percent must be between 5 and 90")
				return
			}
			cfg.MemoryMaxUsagePercent = req.MemoryMaxUsagePercent
		}
		if req.MemoryReleaseCooldownSec > 0 {
			if req.MemoryReleaseCooldownSec < 60 {
				s.writeErrorResponse(w, http.StatusBadRequest, "memory_release_cooldown_sec must be at least 60")
				return
			}
			cfg.MemoryReleaseCooldownSec = req.MemoryReleaseCooldownSec
		}

		// 看门狗配置
		cfg.WatchdogEnabled = req.WatchdogEnabled
		if req.WatchdogCheckIntervalSec > 0 {
			if req.WatchdogCheckIntervalSec < 10 || req.WatchdogCheckIntervalSec > 300 {
				s.writeErrorResponse(w, http.StatusBadRequest, "watchdog_check_interval_sec must be between 10 and 300")
				return
			}
			cfg.WatchdogCheckIntervalSec = req.WatchdogCheckIntervalSec
		}
		if req.WatchdogCPUThresholdPercent > 0 {
			if req.WatchdogCPUThresholdPercent < 1 || req.WatchdogCPUThresholdPercent > 100 {
				s.writeErrorResponse(w, http.StatusBadRequest, "watchdog_cpu_threshold_percent must be between 1 and 100")
				return
			}
			cfg.WatchdogCPUThresholdPercent = req.WatchdogCPUThresholdPercent
		}
		if req.WatchdogCPUIncreaseThresholdPercent > 0 {
			if req.WatchdogCPUIncreaseThresholdPercent < 1 || req.WatchdogCPUIncreaseThresholdPercent > 100 {
				s.writeErrorResponse(w, http.StatusBadRequest, "watchdog_cpu_increase_threshold_percent must be between 1 and 100")
				return
			}
			cfg.WatchdogCPUIncreaseThresholdPercent = req.WatchdogCPUIncreaseThresholdPercent
		}
		if req.WatchdogCPUIncreaseWindowSec > 0 {
			if req.WatchdogCPUIncreaseWindowSec < 60 || req.WatchdogCPUIncreaseWindowSec > 3600 {
				s.writeErrorResponse(w, http.StatusBadRequest, "watchdog_cpu_increase_window_sec must be between 60 and 3600")
				return
			}
			cfg.WatchdogCPUIncreaseWindowSec = req.WatchdogCPUIncreaseWindowSec
		}
		if req.WatchdogAlertCooldownSec > 0 {
			if req.WatchdogAlertCooldownSec < 60 || req.WatchdogAlertCooldownSec > 86400 {
				s.writeErrorResponse(w, http.StatusBadRequest, "watchdog_alert_cooldown_sec must be between 60 and 86400")
				return
			}
			cfg.WatchdogAlertCooldownSec = req.WatchdogAlertCooldownSec
		}

		// 内存监控配置
		if req.WatchdogMemoryThresholdMB >= 0 {
			cfg.WatchdogMemoryThresholdMB = req.WatchdogMemoryThresholdMB
		}
		if req.WatchdogMemoryThresholdPercent >= 0 {
			if req.WatchdogMemoryThresholdPercent > 100 {
				s.writeErrorResponse(w, http.StatusBadRequest, "watchdog_memory_threshold_percent must be between 0 and 100")
				return
			}
			cfg.WatchdogMemoryThresholdPercent = req.WatchdogMemoryThresholdPercent
		}
		if req.WatchdogMemoryIncreaseThresholdMB >= 0 {
			cfg.WatchdogMemoryIncreaseThresholdMB = req.WatchdogMemoryIncreaseThresholdMB
		}
		if req.WatchdogMemoryIncreaseWindowSec > 0 {
			if req.WatchdogMemoryIncreaseWindowSec < 60 || req.WatchdogMemoryIncreaseWindowSec > 3600 {
				s.writeErrorResponse(w, http.StatusBadRequest, "watchdog_memory_increase_window_sec must be between 60 and 3600")
				return
			}
			cfg.WatchdogMemoryIncreaseWindowSec = req.WatchdogMemoryIncreaseWindowSec
		}

		// 自动退出配置
		cfg.WatchdogExitOnMemoryThreshold = req.WatchdogExitOnMemoryThreshold
		cfg.WatchdogExitOnCPUThreshold = req.WatchdogExitOnCPUThreshold

		// 保存配置到文件
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			s.log.Errorf("保存监控配置失败: %v", err)
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to save config")
			return
		}

		// 更新运行时监控管理器
		if s.monitorManager != nil {
			// 更新内存监控配置
			memoryOpts := monitor.MemoryMonitorOptions{
				CheckInterval:       time.Minute,
				MaxSystemUsageRatio: cfg.MemoryMaxUsagePercent / 100.0,
				ReleaseCooldown:     time.Duration(cfg.MemoryReleaseCooldownSec) * time.Second,
			}
			s.monitorManager.UpdateMemoryMonitorOptions(memoryOpts)

			// 更新看门狗配置
			watchdogOpts := monitor.WatchdogMonitorOptions{
				Enabled:                     cfg.WatchdogEnabled,
				CheckInterval:               time.Duration(cfg.WatchdogCheckIntervalSec) * time.Second,
				CPUThresholdPercent:         cfg.WatchdogCPUThresholdPercent,
				CPUIncreaseThresholdPercent: cfg.WatchdogCPUIncreaseThresholdPercent,
				CPUIncreaseWindow:           time.Duration(cfg.WatchdogCPUIncreaseWindowSec) * time.Second,
				AlertCooldown:               time.Duration(cfg.WatchdogAlertCooldownSec) * time.Second,
				MemoryThresholdMB:           cfg.WatchdogMemoryThresholdMB,
				MemoryThresholdPercent:      cfg.WatchdogMemoryThresholdPercent,
				MemoryIncreaseThresholdMB:   cfg.WatchdogMemoryIncreaseThresholdMB,
				MemoryIncreaseWindow:        time.Duration(cfg.WatchdogMemoryIncreaseWindowSec) * time.Second,
				ExitOnMemoryThreshold:       cfg.WatchdogExitOnMemoryThreshold,
				ExitOnCPUThreshold:          cfg.WatchdogExitOnCPUThreshold,
			}
			s.monitorManager.UpdateWatchdogOptions(watchdogOpts)

			// 如果需要重启看门狗（启用状态改变）
			if cfg.WatchdogEnabled {
				if err := s.monitorManager.RestartWatchdog(watchdogOpts, s.notificationIntegrator); err != nil {
					s.log.Errorf("重启看门狗失败: %v", err)
					s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to restart watchdog")
					return
				}
			} else {
				// 如果禁用了看门狗，停止它
				if watchdogMonitor := s.monitorManager.GetWatchdogMonitor(); watchdogMonitor != nil {
					watchdogMonitor.Stop()
				}
			}
		}

		s.writeSuccessResponse(w, nil, "Monitoring config updated successfully")
		return
	}

	s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// handleAPIMonitoringStats 获取实时监控统计数据
func (s *Server) handleAPIMonitoringStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != "GET" {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 获取进程统计信息
	stats, err := monitor.GetProcessStats()
	if err != nil {
		s.log.Errorf("获取进程统计信息失败: %v", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get process stats")
		return
	}

	// 获取内存 RSS（需要从系统读取，这里使用近似值）
	var memoryRSSMB float64
	if stats.MemoryPercent > 0 {
		// 尝试从监控管理器获取更详细的信息
		if s.monitorManager != nil {
			if watchdogStats := s.monitorManager.GetWatchdogMonitor(); watchdogStats != nil {
				// 如果有历史记录，尝试获取最新的内存信息
				// 注意：这里需要扩展 GetStats 方法返回更多信息
			}
		}
		// 如果没有详细数据，使用百分比估算（假设系统总内存为8GB）
		// 实际应用中应该从系统获取真实值
		memoryRSSMB = (stats.MemoryPercent / 100.0) * 8192 // 假设8GB系统内存
	}

	response := MonitoringStatsResponse{
		CPUPercent:    stats.CPUPercent,
		MemoryPercent: stats.MemoryPercent,
		MemoryRSSMB:   memoryRSSMB,
		Timestamp:     stats.Timestamp.Format(time.RFC3339),
	}

	s.writeSuccessResponse(w, response, "Monitoring stats retrieved successfully")
}

// handleAPIMonitoringWatchdogRestart 重启看门狗监控器
func (s *Server) handleAPIMonitoringWatchdogRestart(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != "POST" {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.monitorManager == nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Monitor manager not initialized")
		return
	}

	cfg := s.config.Monitoring
	if !cfg.WatchdogEnabled {
		s.writeErrorResponse(w, http.StatusBadRequest, "Watchdog is not enabled")
		return
	}

	watchdogOpts := monitor.WatchdogMonitorOptions{
		Enabled:                     cfg.WatchdogEnabled,
		CheckInterval:               time.Duration(cfg.WatchdogCheckIntervalSec) * time.Second,
		CPUThresholdPercent:         cfg.WatchdogCPUThresholdPercent,
		CPUIncreaseThresholdPercent: cfg.WatchdogCPUIncreaseThresholdPercent,
		CPUIncreaseWindow:           time.Duration(cfg.WatchdogCPUIncreaseWindowSec) * time.Second,
		AlertCooldown:               time.Duration(cfg.WatchdogAlertCooldownSec) * time.Second,
		MemoryThresholdMB:           cfg.WatchdogMemoryThresholdMB,
		MemoryThresholdPercent:      cfg.WatchdogMemoryThresholdPercent,
		MemoryIncreaseThresholdMB:   cfg.WatchdogMemoryIncreaseThresholdMB,
		MemoryIncreaseWindow:        time.Duration(cfg.WatchdogMemoryIncreaseWindowSec) * time.Second,
		ExitOnMemoryThreshold:       cfg.WatchdogExitOnMemoryThreshold,
		ExitOnCPUThreshold:          cfg.WatchdogExitOnCPUThreshold,
	}

	if err := s.monitorManager.RestartWatchdog(watchdogOpts, s.notificationIntegrator); err != nil {
		s.log.Errorf("重启看门狗失败: %v", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to restart watchdog: "+err.Error())
		return
	}

	s.writeSuccessResponse(w, nil, "Watchdog restarted successfully")
}

