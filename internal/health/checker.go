package health

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/config"

	"github.com/sirupsen/logrus"
)

// Status 健康状态
type Status int

const (
	StatusHealthy Status = iota
	StatusUnhealthy
	StatusUnknown
)

func (s Status) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// TargetHealth 目标健康状态
type TargetHealth struct {
	Target       string    `json:"target"`
	Port         int       `json:"port"`
	Status       Status    `json:"status"`
	LastCheck    time.Time `json:"last_check"`
	ResponseTime int64     `json:"response_time_ms"`
	ErrorCount   int       `json:"error_count"`
	TotalChecks  int       `json:"total_checks"`
	Uptime       float64   `json:"uptime_percent"`
}

// Checker 健康检测器
type Checker struct {
	config      *config.Config
	targets     map[string]*TargetHealth
	mutex       sync.RWMutex
	stopChan    chan struct{}
	interval    time.Duration
	timeout     time.Duration
	log         *logrus.Entry
}

// NewChecker 创建健康检测器
func NewChecker(cfg *config.Config) *Checker {
	return &Checker{
		config:   cfg,
		targets:  make(map[string]*TargetHealth),
		stopChan: make(chan struct{}),
		interval: 30 * time.Second, // 默认30秒检测一次
		timeout:  5 * time.Second,  // 默认5秒超时
		log: logrus.WithFields(logrus.Fields{
			"component": "health_checker",
		}),
	}
}

// Start 启动健康检测
func (c *Checker) Start() error {
	c.log.Info("启动健康检测服务")
	
	// 初始化所有代理目标的健康状态
	c.initTargets()
	
	// 启动定期检测
	go c.periodicCheck()
	
	return nil
}

// Stop 停止健康检测
func (c *Checker) Stop() {
	c.log.Info("停止健康检测服务")
	close(c.stopChan)
}

// initTargets 初始化目标列表
func (c *Checker) initTargets() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	for _, rule := range c.config.Proxy.Rules {
		key := fmt.Sprintf("%s:%d", rule.Target, rule.Port)
		c.targets[key] = &TargetHealth{
			Target:      rule.Target,
			Port:        rule.Port,
			Status:      StatusUnknown,
			LastCheck:   time.Time{},
			ErrorCount:  0,
			TotalChecks: 0,
		}
	}
	
	c.log.Infof("初始化 %d 个健康检测目标", len(c.targets))
}

// periodicCheck 定期检测
func (c *Checker) periodicCheck() {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	
	// 立即执行一次检测
	c.checkAllTargets()
	
	for {
		select {
		case <-ticker.C:
			c.checkAllTargets()
		case <-c.stopChan:
			return
		}
	}
}

// checkAllTargets 检测所有目标
func (c *Checker) checkAllTargets() {
	c.mutex.RLock()
	targets := make([]*TargetHealth, 0, len(c.targets))
	for _, target := range c.targets {
		targets = append(targets, target)
	}
	c.mutex.RUnlock()
	
	// 并发检测所有目标
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(t *TargetHealth) {
			defer wg.Done()
			c.checkTarget(t)
		}(target)
	}
	
	wg.Wait()
	c.log.Debugf("完成一轮健康检测，共检测 %d 个目标", len(targets))
}

// checkTarget 检测单个目标
func (c *Checker) checkTarget(target *TargetHealth) {
	start := time.Now()
	address := fmt.Sprintf("%s:%d", target.Target, target.Port)
	
	// 尝试TCP连接
	conn, err := net.DialTimeout("tcp", address, c.timeout)
	responseTime := time.Since(start).Milliseconds()
	
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	target.LastCheck = time.Now()
	target.ResponseTime = responseTime
	target.TotalChecks++
	
	if err != nil {
		target.ErrorCount++
		target.Status = StatusUnhealthy
		c.log.Warnf("健康检测失败 %s: %v (响应时间: %dms)", address, err, responseTime)
	} else {
		conn.Close()
		target.Status = StatusHealthy
		c.log.Debugf("健康检测成功 %s (响应时间: %dms)", address, responseTime)
	}
	
	// 计算可用率
	if target.TotalChecks > 0 {
		target.Uptime = float64(target.TotalChecks-target.ErrorCount) / float64(target.TotalChecks) * 100
	}
}

// GetTargetHealth 获取指定目标的健康状态
func (c *Checker) GetTargetHealth(target string, port int) *TargetHealth {
	key := fmt.Sprintf("%s:%d", target, port)
	
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	if health, exists := c.targets[key]; exists {
		// 返回副本以避免并发问题
		return &TargetHealth{
			Target:       health.Target,
			Port:         health.Port,
			Status:       health.Status,
			LastCheck:    health.LastCheck,
			ResponseTime: health.ResponseTime,
			ErrorCount:   health.ErrorCount,
			TotalChecks:  health.TotalChecks,
			Uptime:       health.Uptime,
		}
	}
	
	return nil
}

// GetAllTargetsHealth 获取所有目标的健康状态
func (c *Checker) GetAllTargetsHealth() map[string]*TargetHealth {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	result := make(map[string]*TargetHealth)
	for key, health := range c.targets {
		result[key] = &TargetHealth{
			Target:       health.Target,
			Port:         health.Port,
			Status:       health.Status,
			LastCheck:    health.LastCheck,
			ResponseTime: health.ResponseTime,
			ErrorCount:   health.ErrorCount,
			TotalChecks:  health.TotalChecks,
			Uptime:       health.Uptime,
		}
	}
	
	return result
}

// IsTargetHealthy 检查目标是否健康
func (c *Checker) IsTargetHealthy(target string, port int) bool {
	health := c.GetTargetHealth(target, port)
	return health != nil && health.Status == StatusHealthy
}

// GetHealthyTargets 获取所有健康的目标
func (c *Checker) GetHealthyTargets() []*TargetHealth {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	var healthy []*TargetHealth
	for _, health := range c.targets {
		if health.Status == StatusHealthy {
			healthy = append(healthy, &TargetHealth{
				Target:       health.Target,
				Port:         health.Port,
				Status:       health.Status,
				LastCheck:    health.LastCheck,
				ResponseTime: health.ResponseTime,
				ErrorCount:   health.ErrorCount,
				TotalChecks:  health.TotalChecks,
				Uptime:       health.Uptime,
			})
		}
	}
	
	return healthy
}

// GetStats 获取健康检测统计信息
func (c *Checker) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	total := len(c.targets)
	healthy := 0
	unhealthy := 0
	unknown := 0
	
	var totalResponseTime int64
	var totalUptime float64
	
	for _, health := range c.targets {
		switch health.Status {
		case StatusHealthy:
			healthy++
		case StatusUnhealthy:
			unhealthy++
		case StatusUnknown:
			unknown++
		}
		
		totalResponseTime += health.ResponseTime
		totalUptime += health.Uptime
	}
	
	var avgResponseTime int64
	var avgUptime float64
	
	if total > 0 {
		avgResponseTime = totalResponseTime / int64(total)
		avgUptime = totalUptime / float64(total)
	}
	
	return map[string]interface{}{
		"total_targets":         total,
		"healthy_targets":       healthy,
		"unhealthy_targets":     unhealthy,
		"unknown_targets":       unknown,
		"health_rate":           float64(healthy) / float64(total) * 100,
		"avg_response_time_ms":  avgResponseTime,
		"avg_uptime_percent":    avgUptime,
		"last_check":            time.Now(),
	}
}

// SetCheckInterval 设置检测间隔
func (c *Checker) SetCheckInterval(interval time.Duration) {
	c.interval = interval
	c.log.Infof("健康检测间隔已设置为: %v", interval)
}

// SetTimeout 设置检测超时时间
func (c *Checker) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	c.log.Infof("健康检测超时时间已设置为: %v", timeout)
}
