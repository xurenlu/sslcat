# 性能问题分析报告 - 2026-03-07

## 问题描述

### 症状
- **时间**：2026年3月7日 08:44:09 开始
- **现象**：所有 HTTP 请求突然变得极慢
- **影响**：响应时间增加 700-1400%，QPS 下降 60-70%

### 用户反馈
> "经常从某一个点时起，所有的 http 请求，都极慢了"

## 问题分析过程

### 1. 初步排查 - HTTP/2 嫌疑

最初怀疑是 HTTP/2 的队头阻塞问题，因为：
- 之前的 pprof 数据显示 `http2.(*serverConn).serve` 有大量阻塞样本
- HTTP/2 的所有流共享同一个 TCP 连接，单个慢流会影响整个连接

**结论**：检查后发现服务器并未启用 HTTP/2，排除此原因。

### 2. 日志分析

检查了 3月7日的日志数据：

```
总日志条数：16,528 条（geminiproxy 站点）
按小时分布：
- 02:00-03:00  8,153 条  (49.3%) ← 高峰期
- 08:00-09:00  2,846 条  (17.2%) ← 对应问题发生时间段
```

日志量并不大（每小时最多 8000 条），排除日志量本身的问题。

### 3. 服务器 pprof 数据分析

从服务器的 goroutine 堆栈信息找到关键线索：

```
goroutine 11687 [sync.RWMutex.RLock, 101-103 分钟]:
sync.(*RWMutex).RLock
github.com/xurenlu/sslcat/internal/security.(*Manager).IsWhitelisted
github.com/xurenlu/sslcat/internal/web.(*Server).securityMiddleware
```

**关键发现**：有 goroutine 等待 `IsWhitelisted` 超过 **100 分钟**！

### 4. 根本原因定位

通过代码审查发现：**多个方法在持锁状态下执行文件 I/O 操作**

#### 问题代码模式

```go
// ❌ 错误：持锁执行 I/O
func (m *Manager) SomeOperation() {
    m.mutex.Lock()
    defer m.mutex.Unlock()

    // 修改内存数据
    m.data[key] = value

    // ❌ 在持锁状态下执行文件 I/O
    m.saveToFile()  // ← 这里会阻塞所有读操作！
}
```

#### 影响链条

```
某个写操作（持锁 I/O）
    ↓
锁被长时间持有
    ↓
所有读操作（IsWhitelisted）被阻塞
    ↓
每个 HTTP 请求都要检查白名单
    ↓
所有 HTTP 请求变慢
```

## 发现的问题

### 1. 白名单管理 (`internal/security/manager.go`)

| 方法 | 问题 |
|------|------|
| `saveWhitelist()` | 直接访问 `m.whitelistEntries`，无锁保护 |
| `AddWhitelistEntry()` | 持锁调用 `saveWhitelist()` |
| `RemoveWhitelistEntry()` | 持锁调用 `saveWhitelist()` |
| `UpdateWhitelistEntry()` | 持锁调用 `saveWhitelist()` |

### 2. IP 封禁管理 (`internal/security/manager.go`)

| 方法 | 问题 |
|------|------|
| `saveBlockedIPs()` | 直接访问 `m.blockedIPs`，无锁保护 |
| `blockIP()` | 无锁保护访问 `m.blockedIPs`，然后调用 `saveBlockedIPs()` |

### 3. 威胁情报管理 (`internal/threatintel/manager.go`)

| 方法 | 问题 |
|------|------|
| `AddIOC()` | 持锁调用 `SaveIOCToDB()`（数据库 I/O）和 `logIOC()`（文件 I/O）|

## 解决方案

### 修复模式

```go
// ✅ 正确：快速更新内存，异步执行 I/O
func (m *Manager) SomeOperation() {
    // 1. 快速更新内存
    m.mutex.Lock()
    m.data[key] = value
    m.mutex.Unlock()

    // 2. 异步执行 I/O（避免持锁）
    go m.saveToFile()
}
```

### 修复：数据保存方法

```go
// ✅ saveWhitelist 自己获取数据快照
func (m *Manager) saveWhitelist() {
    // 获取数据快照，避免持锁执行 I/O
    m.mutex.RLock()
    entries := make(map[string]WhitelistEntry, len(m.whitelistEntries))
    for k, v := range m.whitelistEntries {
        entries[k] = v
    }
    m.mutex.RUnlock()

    // 执行文件 I/O（不持有锁）
    // ... 写入文件
}
```

## 修复结果

### 性能对比

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| 读操作最大延迟 | 数秒至数分钟 | **1.14ms** |
| 响应时间增加 | 700-1400% | 正常 |
| I/O 阻塞锁 | 是 | 否 |

### 测试验证

```go
// 并发测试：100 个读操作 + 10 个写操作
func TestWhitelistConcurrency(t *testing.T) {
    // 测试结果：Max read delay: 1.138916ms
    // 远低于 100ms 的阈值
}
```

## 提交记录

1. **commit 2538416** - 修复白名单文件 I/O 操作
   - `saveWhitelist()` - 使用 RLock 创建数据副本
   - `AddWhitelistEntry()` - 异步保存
   - `RemoveWhitelistEntry()` - 异步保存
   - `UpdateWhitelistEntry()` - 异步保存

2. **commit bc30e44** - 修复 IP 封禁和威胁情报的 I/O 操作
   - `saveBlockedIPs()` - 使用 RLock 创建数据副本
   - `blockIP()` - 添加锁保护 + 异步保存
   - `AddIOC()` - 异步保存数据库和日志

## 关键要点

### 为什么"从某个时间点起"所有请求都变慢？

**触发条件**：某个操作触发了需要保存数据的操作
- 自动 IP 封禁（检测到攻击）
- 威胁情报更新（定期拉取）
- User-Agent 封禁（检测到扫描工具）

**连锁反应**：
1. 写操作持锁执行 I/O
2. I/O 操作因某种原因变慢（磁盘、网络、文件大小）
3. 锁被长时间持有
4. 所有读操作被阻塞
5. 所有 HTTP 请求变慢

### 为什么单个上游失败拖垮整个系统？

因为：
1. 每个请求都需要调用 `IsWhitelisted`
2. `IsWhitelisted` 需要获取读锁
3. 如果有写操作持锁执行 I/O
4. 所有 `IsWhitelisted` 调用都会等待
5. 无论请求去往哪个上游，都会被阻塞

## 经验教训

### 1. 持锁规则

**❌ 绝对不要在持锁状态下执行的操作：**
- 文件 I/O
- 网络 I/O
- 数据库操作
- 任何可能阻塞的系统调用

**✅ 正确的做法：**
- 快速更新内存数据
- 立即释放锁
- 异步执行 I/O 操作

### 2. 数据保存方法设计

如果方法需要在锁外执行 I/O：
- 方法自己负责获取数据快照
- 使用 RLock 而不是 Lock（读取快照）
- 调用方不需要持有锁

### 3. 读写锁的使用

对于读多写少的场景（如白名单检查）：
- 使用 `sync.RWMutex`
- 写操作必须快速
- 不要在写操作中执行 I/O

## 相关文件

- `internal/security/manager.go` - 白名单和 IP 封禁管理
- `internal/threatintel/manager.go` - 威胁情报管理
- `internal/security/manager_lock_test.go` - 并发安全测试

## 参考资料

- Go Mutex 最佳实践：https://go.dev/doc/effective_go#mutex
- 并发编程模式：https://go.dev/blog/pipeline
