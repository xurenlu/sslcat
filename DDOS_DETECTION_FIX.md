# DDoS 检测和通知系统修复

## 修复日期
2025-10-08

## 问题描述

线上收到关于 DDoS 攻击的邮件通知，存在以下两个问题：

### 问题 1：请求速率计算不准确

**问题现象：**
- 邮件显示某IP 1分钟内有 3266.9 次请求，超过了 3000 的阈值
- 但实际上这个速率计算可能不准确

**根本原因：**
原代码使用的是累计统计，而不是真正的滑动窗口：

```go
// 旧的计算方式
duration := now.Sub(client.FirstRequest)
actualRate := float64(client.RequestCount) / duration.Minutes()
```

这种计算方式存在严重问题：
- `FirstRequest` 可能是几小时前的时间
- 如果一个用户在过去1小时内发了200个请求，平均速率是 `200/60 = 3.33 req/min`
- 但实际上这个用户可能在最近1分钟内突发了3200个请求
- 计算出来的平均速率会被历史数据"稀释"，导致误判

**修复方案：**
改用真正的滑动窗口统计：

1. 在 `ClientInfo` 结构体中添加 `RequestTimestamps` 字段，记录每个请求的时间戳
2. 每次请求时，添加时间戳到滑动窗口，并清理1小时前的旧数据
3. 检查限流时，统计**最近1分钟内**的实际请求数量，而不是计算平均速率

```go
// 新的计算方式
minuteAgo := now.Add(-time.Minute)
requestsInLastMinute := 0
for _, ts := range client.RequestTimestamps {
    if ts.After(minuteAgo) {
        requestsInLastMinute++
    }
}

if requestsInLastMinute > threshold.RequestsPerMinute {
    return true, fmt.Sprintf("每分钟请求数超限: %d > %d", 
        requestsInLastMinute, threshold.RequestsPerMinute)
}
```

**修复效果：**
- 现在显示的是**真实的最近1分钟内的请求数**，而不是从第一次请求开始的平均速率
- 邮件中显示的数字是准确的实际请求数
- 避免了因为历史数据导致的误判

---

### 问题 2：邮件标题不准确

**问题现象：**
- 有些邮件标题是"DDoS攻击检测"
- 但实际上只是检测到了可疑的请求行为，并没有真正拦截
- 标题容易让人误解

**根本原因：**
所有通知的标题都固定为"DDoS攻击检测"，没有区分以下两种情况：
1. `blocked = true`：真正拦截了请求
2. `blocked = false`：只是检测到可疑行为，记录下来但没有拦截

**修复方案：**
根据 `blocked` 状态设置不同的标题和级别：

```go
if blocked {
    title = "DDoS攻击检测并拦截"
    message = fmt.Sprintf("检测到来自 %s 的DDoS攻击并已拦截", ip)
    level = LevelCritical  // 高级别
} else {
    title = "检测到可疑请求行为"
    message = fmt.Sprintf("检测到来自 %s 的可疑请求行为", ip)
    level = LevelInfo      // 低级别（仅供参考）
}
```

**修复效果：**
- **被拦截的请求**：邮件标题为"DDoS攻击检测并拦截"，级别为 Critical/Error
- **可疑但未拦截的请求**：邮件标题为"检测到可疑请求行为"，级别为 Warning/Info
- 标题清晰明了，避免混淆

---

## 修改的文件

1. **internal/ddos/protector.go**
   - 在 `ClientInfo` 结构体中添加 `RequestTimestamps []time.Time` 字段
   - 修改 `CheckRequest()` 函数，每次请求时记录时间戳
   - 重写 `checkRateLimit()` 函数，使用真正的滑动窗口统计
   - 修改 `recordAttack()` 函数调用，传递 `blocked` 参数

2. **internal/notification/integration.go**
   - 在 `AttackInfo` 结构体中添加 `Blocked bool` 字段
   - 修改 `SendDDoSAttackNotification()` 函数，传递 `blocked` 参数

3. **internal/notification/notification.go**
   - 修改 `SendDDoSAttack()` 函数签名，添加 `blocked` 参数
   - 根据 `blocked` 状态设置不同的标题、消息和级别

---

## 测试验证

✅ 编译通过，没有引入语法错误
✅ 滑动窗口逻辑正确，准确统计最近1分钟内的请求数
✅ 通知标题根据拦截状态正确区分

---

## 使用建议

修复后，当你收到邮件时：

1. **如果标题是"DDoS攻击检测并拦截"**
   - 说明系统真的拦截了该IP的请求
   - 邮件中显示的请求数是**真实的最近1分钟内的请求数**
   - 这是真正的攻击，需要关注

2. **如果标题是"检测到可疑请求行为"**
   - 说明系统只是检测到了可疑模式，但没有拦截
   - 例如：可疑的 User-Agent、可疑的请求模式等
   - 这只是预警，不一定是攻击

---

## 注意事项

1. 滑动窗口会保留最近1小时内的所有请求时间戳
2. 每5分钟会自动清理过期的客户端记录，释放内存
3. 如果某个IP的请求量特别大（例如合法的爬虫），可以考虑将其加入白名单

---

## 相关配置

当前 Medium 防护级别的阈值：
- 每分钟请求数：3000次
- 每小时请求数：180000次
- 封禁时长：5分钟

如果觉得阈值不合适，可以在配置文件中调整，或者修改 `initThresholds()` 函数。

