package notification

import (
	"sync"
	"time"
)

// RateLimiter 速率限制器
type RateLimiter struct {
	limits     map[string]map[NotificationType]time.Time
	mutex      sync.RWMutex
	stopChan   chan struct{}
	cleanerOnce sync.Once
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		limits:   make(map[string]map[NotificationType]time.Time),
		stopChan: make(chan struct{}),
	}
	
	// 启动清理器
	rl.startCleaner()
	
	return rl
}

// IsRateLimited 检查是否被速率限制
func (rl *RateLimiter) IsRateLimited(notificationType NotificationType, level NotificationLevel) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	key := rl.getKey(notificationType, level)
	now := time.Now()

	// 获取限制配置
	limitDuration := rl.getLimitDuration(notificationType, level)
	if limitDuration <= 0 {
		return false // 无限制
	}

	// 检查是否在限制期内
	if lastTime, exists := rl.limits[key][notificationType]; exists {
		if now.Sub(lastTime) < limitDuration {
			return true // 被限制
		}
	}

	// 更新最后发送时间
	if rl.limits[key] == nil {
		rl.limits[key] = make(map[NotificationType]time.Time)
	}
	rl.limits[key][notificationType] = now

	return false
}

// getKey 获取限制键
func (rl *RateLimiter) getKey(notificationType NotificationType, level NotificationLevel) string {
	return string(notificationType) + "_" + level.String()
}

// getLimitDuration 获取限制持续时间
func (rl *RateLimiter) getLimitDuration(notificationType NotificationType, level NotificationLevel) time.Duration {
	// 根据通知类型和级别设置不同的限制时间
	switch notificationType {
	case TypeDDoSAttack:
		switch level {
		case LevelCritical:
			return 1 * time.Minute // 严重DDoS攻击：1分钟内不重复通知
		case LevelWarning:
			return 5 * time.Minute // 一般DDoS攻击：5分钟内不重复通知
		default:
			return 10 * time.Minute // 其他DDoS攻击：10分钟内不重复通知
		}
	case TypeCertExpiring:
		switch level {
		case LevelCritical:
			return 1 * time.Hour // 证书即将过期：1小时内不重复通知
		case LevelWarning:
			return 6 * time.Hour // 证书警告：6小时内不重复通知
		default:
			return 24 * time.Hour // 其他证书通知：24小时内不重复通知
		}
	case TypeCertFailed:
		return 30 * time.Minute // 证书申请失败：30分钟内不重复通知
	case TypeSecurityAlert:
		switch level {
		case LevelCritical:
			return 5 * time.Minute // 严重安全警报：5分钟内不重复通知
		case LevelWarning:
			return 15 * time.Minute // 一般安全警报：15分钟内不重复通知
		default:
			return 30 * time.Minute // 其他安全警报：30分钟内不重复通知
		}
	case TypeUserAction:
		return 1 * time.Minute // 用户操作：1分钟内不重复通知
	case TypeSystemError:
		switch level {
		case LevelCritical:
			return 5 * time.Minute // 严重系统错误：5分钟内不重复通知
		case LevelError:
			return 15 * time.Minute // 一般系统错误：15分钟内不重复通知
		default:
			return 30 * time.Minute // 其他系统错误：30分钟内不重复通知
		}
	case TypeSystemStartup, TypeSystemShutdown:
		return 1 * time.Hour // 系统启停：1小时内不重复通知
	default:
		return 5 * time.Minute // 默认：5分钟内不重复通知
	}
}

// Reset 重置速率限制器
func (rl *RateLimiter) Reset() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	rl.limits = make(map[string]map[NotificationType]time.Time)
}

// GetStats 获取速率限制统计
func (rl *RateLimiter) GetStats() map[string]any {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	stats := map[string]any{
		"total_limits": len(rl.limits),
		"limits":       make(map[string]map[string]time.Time),
	}

	// 转换时间格式以便JSON序列化
	for key, limits := range rl.limits {
		stats["limits"].(map[string]map[string]time.Time)[key] = make(map[string]time.Time)
		for notificationType, lastTime := range limits {
			stats["limits"].(map[string]map[string]time.Time)[key][string(notificationType)] = lastTime
		}
	}

	return stats
}

// startCleaner 启动定期清理器，清理过期的限制条目
func (rl *RateLimiter) startCleaner() {
	rl.cleanerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(30 * time.Minute) // 每30分钟清理一次
			defer ticker.Stop()
			
			for {
				select {
				case <-ticker.C:
					rl.cleanExpiredLimits()
				case <-rl.stopChan:
					return
				}
			}
		}()
	})
}

// cleanExpiredLimits 清理过期的限制条目
func (rl *RateLimiter) cleanExpiredLimits() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	now := time.Now()
	cleaned := 0
	
	for key, limits := range rl.limits {
		for notificationType, lastTime := range limits {
			// 如果距离上次通知超过2小时，认为已过期
			if now.Sub(lastTime) > 2*time.Hour {
				delete(limits, notificationType)
				cleaned++
			}
		}
		
		// 如果该 key 下没有任何限制了，删除整个 key
		if len(limits) == 0 {
			delete(rl.limits, key)
		}
	}
	
	if cleaned > 0 {
		// 使用 logrus 记录清理信息（需要在调用处传入 logger）
		// 这里简化处理，实际使用时可以添加 logger 字段
	}
}

// Stop 停止清理器
func (rl *RateLimiter) Stop() {
	select {
	case <-rl.stopChan:
		// Already closed
	default:
		close(rl.stopChan)
	}
}
