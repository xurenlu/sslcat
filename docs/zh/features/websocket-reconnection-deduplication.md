# WebSocket 断线重连与消息去重实现

## 问题分析

### 问题 1: 自动重连失效 🐛

**原因**:
在 `ws.onclose` 回调中，先执行了 `setIsStreaming(false)`，然后再检查 `if (isStreaming)`，导致条件永远不满足。

```typescript
// ❌ 错误的实现
ws.onclose = () => {
  setIsStreaming(false)  // 先设置为 false
  
  if (isStreaming) {     // 这里永远是 false
    reconnect()
  }
}
```

### 问题 2: 消息重复 📮

**原因**:
WebSocket 重连后，后端会发送历史日志（50条），如果前端不做去重处理，这些日志会和之前收到的重复显示。

## 解决方案

### 1. 使用 Ref 管理重连状态

使用 `useRef` 来保存重连标志，避免闭包问题：

```typescript
const shouldReconnectRef = useRef<boolean>(false)
const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
const reconnectAttemptsRef = useRef<number>(0)
```

**优点**:
- ✅ Ref 的值不会触发重新渲染
- ✅ 在回调中总是能获取最新值
- ✅ 不受闭包影响

### 2. 指数退避重连策略

实现智能重连，避免频繁重连造成服务器压力：

```typescript
ws.onclose = (event) => {
  setIsConnected(false)
  setIsStreaming(false)
  
  if (shouldReconnectRef.current) {
    reconnectAttemptsRef.current++
    
    // 指数退避：3秒、6秒、12秒...最多30秒
    const delay = Math.min(3000 * Math.pow(2, reconnectAttemptsRef.current - 1), 30000)
    
    console.log(`Will reconnect in ${delay}ms (attempt ${reconnectAttemptsRef.current})`)
    
    reconnectTimeoutRef.current = setTimeout(() => {
      if (shouldReconnectRef.current) {
        connectWebSocket()
      }
    }, delay)
  }
}
```

**退避时间表**:
| 重连次数 | 延迟时间 |
|---------|---------|
| 1       | 3秒     |
| 2       | 6秒     |
| 3       | 12秒    |
| 4       | 24秒    |
| 5+      | 30秒    |

### 3. 消息去重机制

使用 Set 数据结构记录已收到的日志ID：

```typescript
const logIdsRef = useRef<Set<string>>(new Set())

// 在收到消息时
ws.onmessage = (event) => {
  const message: WebSocketMessage = JSON.parse(event.data)
  
  if (message.type === 'log' && message.data) {
    // 生成唯一ID
    const logId = `${message.data.timestamp}_${message.data.message.substring(0, 50)}`
    
    // 检查是否重复
    if (logIdsRef.current.has(logId)) {
      console.debug('Skipping duplicate log:', logId)
      return
    }
    
    // 添加到集合
    logIdsRef.current.add(logId)
    
    // 限制集合大小（防止内存泄漏）
    if (logIdsRef.current.size > 1000) {
      const idsArray = Array.from(logIdsRef.current)
      logIdsRef.current = new Set(idsArray.slice(-500))
    }
    
    // 处理日志
    addLog(message.data)
  }
}
```

**去重策略**:
- ✅ 使用 `timestamp + 消息前50字符` 作为唯一标识
- ✅ Set 查找时间复杂度 O(1)
- ✅ 限制集合大小为1000，超过时保留最近500条
- ✅ 防止内存泄漏

### 4. 正确的连接/断开管理

**连接时**:
```typescript
const connectLogStream = () => {
  shouldReconnectRef.current = true  // 允许自动重连
  reconnectAttemptsRef.current = 0   // 重置重连次数
  
  if (connectionType === 'websocket') {
    connectWebSocket()
  }
}
```

**断开时**:
```typescript
const disconnectLogStream = () => {
  shouldReconnectRef.current = false  // 禁止自动重连
  
  // 清理重连定时器
  if (reconnectTimeoutRef.current) {
    clearTimeout(reconnectTimeoutRef.current)
    reconnectTimeoutRef.current = null
  }
  
  if (websocketRef.current) {
    websocketRef.current.close()
    websocketRef.current = null
  }
  
  setIsConnected(false)
  setIsStreaming(false)
}
```

**清空日志时**:
```typescript
const clearLogs = () => {
  setLogs([])
  logIdsRef.current.clear()  // 同时清空去重集合
}
```

## 完整流程图

```
[用户点击连接]
    |
    v
shouldReconnectRef = true
reconnectAttempts = 0
    |
    v
[建立 WebSocket 连接]
    |
    +-- 成功 --> [connected]
    |              |
    |              v
    |           reconnectAttempts = 0
    |              |
    |              v
    |           [接收消息]
    |              |
    |              +-- 检查去重 --> 已存在? --> 跳过
    |              |                  |
    |              |                  v
    |              |                 新消息 --> 添加到集合 --> 显示
    |              |
    +-- 失败 --> [closed]
                   |
                   v
              shouldReconnectRef == true?
                   |
                   +-- Yes --> reconnectAttempts++
                   |           |
                   |           v
                   |        计算延迟时间
                   |           |
                   |           v
                   |        setTimeout(重连)
                   |
                   +-- No --> 停止

[用户点击断开]
    |
    v
shouldReconnectRef = false
    |
    v
clearTimeout(reconnectTimeout)
    |
    v
ws.close()
    |
    v
[disconnected]
```

## 使用示例

### React 组件

```typescript
import RealtimeLogs from '@/components/RealtimeLogs'

// 自动重连已内置
<RealtimeLogs 
  appName="myapp"
  autoScroll={true}
  maxLines={500}
  showControls={true}
/>
```

### 测试页面

打开 `test-websocket-logs.html`：

1. 输入应用名称
2. 选择 WebSocket 模式
3. 点击"连接"
4. 断开网络，观察自动重连
5. 恢复网络，观察消息去重

## 测试场景

### 测试 1: 自动重连

1. 建立连接
2. 停止服务器
3. 观察重连尝试（3秒、6秒、12秒...）
4. 重启服务器
5. 连接自动恢复 ✅

### 测试 2: 消息去重

1. 建立连接
2. 接收一些日志
3. 断开连接
4. 重新连接
5. 检查历史日志是否重复 ✅

### 测试 3: 手动断开

1. 建立连接
2. 点击"断开"按钮
3. 观察不会自动重连 ✅

### 测试 4: 网络波动

1. 建立连接
2. 短暂断网（5秒内恢复）
3. 观察快速重连（3秒延迟）✅
4. 多次断网
5. 观察延迟逐渐增加 ✅

## 性能指标

### 内存使用

- **去重集合**: 最多1000条记录 ≈ 50KB
- **日志数组**: 最多500条记录 ≈ 100KB
- **总计**: < 200KB per 连接

### CPU 使用

- **去重检查**: O(1) Set 查找
- **重连延迟**: 指数退避，不会频繁尝试
- **影响**: 可忽略

### 网络流量

- **首次连接**: 接收50条历史日志
- **重连**: 接收50条历史日志（去重后不显示）
- **心跳**: 30秒一次，极小开销

## 最佳实践

### 1. 合理的重连策略

✅ **推荐**:
- 指数退避
- 最大延迟限制（30秒）
- 最大重连次数限制（可选）

❌ **避免**:
- 固定间隔重连（造成服务器压力）
- 无限制重连（耗尽资源）

### 2. 消息去重

✅ **推荐**:
- 使用唯一标识（timestamp + 部分内容）
- Set 数据结构（快速查找）
- 限制集合大小（防止内存泄漏）

❌ **避免**:
- 数组线性查找（O(n) 复杂度）
- 无限制增长（内存泄漏）
- 仅用 timestamp（不够唯一）

### 3. 状态管理

✅ **推荐**:
- 使用 Ref 管理重连状态
- 清理定时器
- 正确的生命周期管理

❌ **避免**:
- 使用 State 管理重连标志（闭包问题）
- 忘记清理定时器（内存泄漏）
- 多个定时器并存（重复重连）

## 相关文件

- `frontend/src/components/RealtimeLogs.tsx` - React 组件实现
- `test-websocket-logs.html` - 测试页面
- `internal/runner/realtime_logs.go` - 后端 WebSocket 实现

## 总结

✅ **已解决的问题**:
1. 自动重连失效 - 使用 Ref 管理状态
2. 消息重复 - 实现去重机制
3. 频繁重连 - 指数退避策略
4. 内存泄漏 - 限制集合大小
5. 资源清理 - 正确的生命周期管理

🎉 **现在的实时日志流**:
- 断线自动重连 ✅
- 消息智能去重 ✅
- 指数退避策略 ✅
- 内存安全可靠 ✅
- 用户体验优秀 ✅

---

**更新日期**: 2024年10月2日  
**状态**: ✅ 已完成并测试

