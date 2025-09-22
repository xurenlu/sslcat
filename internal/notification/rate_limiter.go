package notification

import (
	"sync"
	"time"
)

// RateLimiter 速率限制器
type RateLimiter struct {
	limits map[string]map[NotificationType]time.Time
	mutex  sync.RWMutex
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limits: make(map[string]map[NotificationType]time.Time),
	}
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
