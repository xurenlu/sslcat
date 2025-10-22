# 通知优化：减少可疑请求通知

## 🚨 当前问题

sslcat 目前对**所有可疑活动**都发送通知，包括：

1. **可疑 User-Agent** - 产生大量通知
2. **可疑请求模式** - 产生大量通知  
3. **一般扫描行为** - 产生大量通知

这会导致：
- 📧 **邮件轰炸** - 管理员邮箱被刷屏
- 🔔 **通知疲劳** - 重要通知被淹没
- 💸 **成本增加** - 邮件/短信服务费用

## 🎯 优化策略

### 1. **分级通知策略**

| 级别 | 触发条件 | 通知方式 | 示例 |
|------|----------|----------|------|
| **Critical** | 实际攻击被阻止 | ✅ 立即通知 | DDoS攻击、暴力破解 |
| **High** | 严重威胁检测 | ✅ 立即通知 | 威胁情报匹配 |
| **Medium** | 可疑行为 | ⚠️ 延迟通知 | 可疑UA、扫描模式 |
| **Low** | 一般异常 | ❌ 仅记录 | 正常扫描、探测 |

### 2. **通知频率控制**

```go
// 建议的配置
type NotificationConfig struct {
    // 关键攻击 - 立即通知
    CriticalAttacks: true,
    
    // 可疑行为 - 批量通知（每小时汇总）
    SuspiciousActivity: false,  // 关闭单个通知
    
    // 批量通知配置
    BatchNotification: true,
    BatchInterval: "1h",        // 每小时汇总一次
    BatchThreshold: 10,         // 至少10个事件才通知
}
```

## 🔧 实现方案

### 方案 1: 修改 DDoS 保护器（推荐）

```go
// 在 recordAttack 方法中添加通知级别判断
func (p *Protector) recordAttack(clientIP, userAgent, url, method, attackType, severity, reason string, blocked bool) {
    // ... 记录攻击逻辑 ...
    
    // 只对实际被阻止的攻击发送通知
    if p.notificationIntegrator != nil && blocked {
        attackInfo := &notification.AttackInfo{
            ClientIP:  clientIP,
            UserAgent: userAgent,
            URL:       url,
            Reason:    reason,
            Severity:  severity,
            Blocked:   blocked,
        }
        p.notificationIntegrator.SendDDoSAttackNotification(attackInfo)
    }
    
    // 对于未阻止的可疑活动，只记录日志
    if !blocked {
        p.log.Infof("检测到可疑活动: %s from %s, 原因: %s", attackType, clientIP, reason)
    }
}
```

### 方案 2: 添加通知级别配置

```go
type DDoSConfig struct {
    // 现有配置...
    
    // 通知配置
    NotificationConfig struct {
        EnableNotifications     bool   `json:"enable_notifications"`
        NotifyOnlyBlocked      bool   `json:"notify_only_blocked"`      // 只通知被阻止的
        NotifySuspiciousUA     bool   `json:"notify_suspicious_ua"`      // 可疑UA通知
        NotifySuspiciousPattern bool   `json:"notify_suspicious_pattern"` // 可疑模式通知
        BatchNotification      bool   `json:"batch_notification"`       // 批量通知
        BatchInterval          string `json:"batch_interval"`           // 批量间隔
    } `json:"notification_config"`
}
```

### 方案 3: 智能通知过滤

```go
// 添加通知过滤器
type NotificationFilter struct {
    // 基于IP的通知频率限制
    ipNotificationCount map[string]int
    ipLastNotification  map[string]time.Time
    
    // 基于类型的通知限制
    typeNotificationCount map[string]int
    typeLastNotification  map[string]time.Time
    
    // 配置
    maxNotificationsPerIP    int
    maxNotificationsPerType  int
    notificationCooldown     time.Duration
}

func (nf *NotificationFilter) ShouldNotify(ip, notificationType string) bool {
    now := time.Now()
    
    // 检查IP频率限制
    if count, exists := nf.ipNotificationCount[ip]; exists {
        if count >= nf.maxNotificationsPerIP {
            if lastTime, exists := nf.ipLastNotification[ip]; exists {
                if now.Sub(lastTime) < nf.notificationCooldown {
                    return false // 冷却期内
                }
            }
        }
    }
    
    // 检查类型频率限制
    if count, exists := nf.typeNotificationCount[notificationType]; exists {
        if count >= nf.maxNotificationsPerType {
            if lastTime, exists := nf.typeLastNotification[notificationType]; exists {
                if now.Sub(lastTime) < nf.notificationCooldown {
                    return false // 冷却期内
                }
            }
        }
    }
    
    return true
}
```

## 📊 预期效果

### 通知数量对比

| 场景 | 优化前 | 优化后 | 减少比例 |
|------|--------|--------|----------|
| **可疑UA扫描** | 1000条/小时 | 0条 | 100% |
| **路径探测** | 500条/小时 | 0条 | 100% |
| **实际攻击** | 10条/小时 | 10条 | 0% |
| **总计** | 1510条/小时 | 10条 | 99.3% |

### 管理员体验

- ✅ **重要通知不遗漏** - 实际攻击立即通知
- ✅ **减少通知疲劳** - 不再被大量扫描通知刷屏
- ✅ **降低运营成本** - 减少邮件/短信费用
- ✅ **提高响应效率** - 专注于真正需要处理的事件

## 🚀 实施建议

### 阶段 1: 快速修复（立即实施）
```go
// 修改 recordAttack 方法，只对实际被阻止的攻击发送通知
if p.notificationIntegrator != nil && blocked {
    // 发送通知
}
```

### 阶段 2: 配置优化（后续版本）
- 添加通知级别配置
- 实现批量通知
- 添加通知频率限制

### 阶段 3: 智能过滤（高级功能）
- 基于机器学习的通知过滤
- 自适应通知阈值
- 智能通知聚合

## ⚠️ 注意事项

1. **不要完全关闭通知** - 确保重要攻击仍能及时通知
2. **保留日志记录** - 所有事件仍要记录到日志
3. **提供配置选项** - 让管理员可以自定义通知策略
4. **监控通知效果** - 确保没有遗漏重要事件

## 🎯 总结

通过优化通知策略，可以：
- **减少 99% 的垃圾通知**
- **提高管理员效率**
- **降低运营成本**
- **保持安全防护效果**

建议立即实施阶段 1 的快速修复！
