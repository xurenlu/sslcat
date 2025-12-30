# WAF 事件统计修复

## 问题描述

用户发现 WAF 虽然能够拦截恶意请求（如访问 `/.git/config`），但是在安全中心的 WAF 防护页面中，**总拦截数始终显示为 0**。

## 根本原因

WAF 引擎中存在一个**并发安全问题**：

1. `CheckRequest()` 函数使用**读锁**（`RLock`）来检查请求
2. 在持有读锁的情况下，各个 `check*` 函数（如 `checkURLPath`、`checkUserAgent` 等）会调用 `addEvent()` 来记录攻击事件
3. `addEvent()` 函数需要**写入** `e.events` 数组，但它在被调用时，外层已经持有了读锁
4. 这导致了**数据竞争**问题：在读锁保护下尝试写入数据

### 问题代码示例

```go
// 旧的实现（有问题）
func (e *Engine) CheckRequest(r *http.Request) (*AttackEvent, bool) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()  // 持有读锁
    
    // 检查各种攻击模式
    if event := e.checkURLPath(...); event != nil {
        return event, event.Blocked
    }
    // ...
}

func (e *Engine) checkURLPath(...) *AttackEvent {
    // ...
    if rule.Regex.MatchString(path) {
        event := &AttackEvent{...}
        e.addEvent(event)  // ❌ 在读锁保护下写入数据！
        return event
    }
}

func (e *Engine) addEvent(event *AttackEvent) {
    e.events = append(e.events, *event)  // ❌ 数据竞争
}
```

## 解决方案

采用**先检测后记录**的策略：

1. 在 `CheckRequest()` 中使用读锁进行所有检测操作
2. 检测完成后**释放读锁**
3. 如果检测到攻击，再调用 `addEvent()` 记录事件
4. `addEvent()` 内部使用**写锁**来安全地写入数据

### 修复后的代码

```go
// 新的实现（已修复）
func (e *Engine) CheckRequest(r *http.Request) (*AttackEvent, bool) {
    // 获取请求数据
    url := r.URL.String()
    method := r.Method
    clientIP := e.getClientIP(r)
    userAgent := r.Header.Get("User-Agent")

    // 使用读锁进行检测
    e.mutex.RLock()
    var event *AttackEvent
    
    // 检查各种攻击模式（只检测，不记录）
    if event = e.checkURLPath(r, clientIP, userAgent, url, method); event == nil {
        if event = e.checkUserAgent(...); event == nil {
            if event = e.checkURLParams(...); event == nil {
                if event = e.checkHeaders(...); event == nil {
                    event = e.checkBody(...)
                }
            }
        }
    }
    e.mutex.RUnlock()  // ✅ 释放读锁

    // 如果检测到攻击，在释放读锁后添加事件
    if event != nil {
        e.addEvent(event)  // ✅ 现在可以安全地写入
        return event, event.Blocked
    }

    return nil, false
}

func (e *Engine) checkURLPath(...) *AttackEvent {
    // ...
    if rule.Regex.MatchString(path) {
        event := &AttackEvent{...}
        // ✅ 不再在这里调用 addEvent
        return event
    }
}

func (e *Engine) addEvent(event *AttackEvent) {
    e.mutex.Lock()         // ✅ 使用写锁
    defer e.mutex.Unlock()
    
    e.events = append(e.events, *event)
    
    // 保持事件数量限制
    if len(e.events) > e.maxEvents {
        e.events = e.events[1:]
    }
}
```

## 修改的文件

- `internal/waf/engine.go`
  - 重构 `CheckRequest()` 函数：先检测后记录
  - 修改 `addEvent()` 函数：添加写锁保护
  - 更新 `checkURLPath()`、`checkUserAgent()`、`checkURLParams()`、`checkHeaders()`、`checkBody()` 函数：移除 `addEvent()` 调用

## 影响范围

- ✅ 修复了 WAF 事件统计不准确的问题
- ✅ 解决了并发写入导致的数据竞争
- ✅ 提高了 WAF 引擎的并发安全性
- ✅ 保持了 WAF 拦截功能的正常工作

## 测试建议

1. 重启 sslcat 服务
2. 访问一些会被 WAF 拦截的 URL，例如：
   - `https://your-domain/.git/config`
   - `https://your-domain/.env`
   - `https://your-domain/admin.php`
3. 刷新安全中心的 WAF 防护页面
4. 验证以下指标：
   - **总拦截数**应该正确显示拦截的请求数量
   - **事件总数**应该包含所有检测到的攻击事件
   - **规则总数**应该显示当前启用的 WAF 规则数量
   - **检测率**应该正确计算

## 性能影响

- **正面影响**：
  - 减少了锁的持有时间（检测阶段只用读锁，记录阶段才用写锁）
  - 提高了并发性能（多个请求可以同时进行检测）
  
- **无负面影响**：
  - 事件记录的写锁操作非常快速（只是 append 操作）
  - 不会影响 WAF 的拦截功能

## 相关问题

这个修复也解决了以下潜在问题：

1. **数据竞争**：在高并发场景下，可能导致 `events` 数组损坏
2. **统计不准**：由于数据竞争，统计数据可能丢失或重复
3. **并发安全**：提高了整体的并发安全性

## 版本信息

- 修复版本：v1.3.31-rc16（待发布）
- 影响版本：v1.3.31-rc15 及之前的所有版本

