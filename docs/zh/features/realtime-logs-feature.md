# 实时日志流功能完善总结

## 概述

本次更新完善了 Git SSH 部署系统的实时日志流功能，添加了 WebSocket 支持、部署状态实时推送、改进的日志解析等特性。

## 已实现功能

### 1. WebSocket 支持 ✅

**后端实现**:
- 添加了 `HandleWebSocketLogsWS()` 函数，提供真正的 WebSocket 双向通信
- 支持心跳机制，保持连接活跃
- 自动客户端管理和清理
- 支持多个客户端同时连接同一应用的日志流

**API 端点**:
```
WebSocket: ws://your-server/admin/api/git-server/logs/stream-ws?app={app_name}
SSE:       http://your-server/admin/api/git-server/logs/stream?app={app_name}
```

**消息格式**:
```json
{
  "type": "log",           // 消息类型: log, ping, connected, error
  "data": {
    "timestamp": "2024-10-02T10:00:00Z",
    "level": "info",       // info, warn, error, debug
    "source": "deploy",    // git, build, deploy, docker, etc.
    "message": "部署成功",
    "app_name": "myapp",
    "metadata": {
      "deploy_id": "deploy_1696248000",
      "status": "success",
      "progress": 100
    }
  }
}
```

### 2. 部署状态实时推送 ✅

在部署过程的关键节点广播状态更新：

**部署流程状态**:
1. **开始部署** (`building`, 10% 进度)
   - 消息: "开始部署流程"
   
2. **检测应用类型** (`building`, 30% 进度)
   - 消息: "检测到应用类型: nodejs，开始构建"
   
3. **部署中** (`deploying`, 60% 进度)
   - 消息: "正在部署应用"
   
4. **部署成功** (`success`, 100% 进度)
   - 消息: "部署成功 - 耗时: 2m30s"
   
5. **部署失败** (`failed`, 100% 进度)
   - 消息: "部署失败"
   - 错误详情: 构建错误信息

**状态消息格式**:
```go
type DeployStatusUpdate struct {
    AppName   string
    DeployID  string
    Status    string      // building, deploying, success, failed
    Progress  int         // 0-100
    Message   string
    Timestamp time.Time
    Error     string      // 仅在失败时存在
}
```

### 3. 改进的日志解析 ✅

**支持的日志格式**:

1. **JSON 结构化日志**:
   ```json
   {"timestamp":"2024-10-02T10:00:00Z","level":"info","source":"deploy","message":"部署完成"}
   ```

2. **标准格式日志**:
   ```
   [2024-10-02 10:00:00] [info] [deploy] 部署完成
   ```

3. **简单文本日志**:
   ```
   npm install completed successfully
   ```

**智能级别检测**:
- 自动识别 `error`, `warn`, `info`, `debug` 关键词
- 支持多种日志级别别名（err, fatal, warning, trace 等）

**智能来源检测**:
- `git` - Git 操作（push, clone, pull）
- `nodejs` - Node.js 相关（npm, node, yarn）
- `python` - Python 相关（pip, python）
- `go` - Go 相关（go build, go mod）
- `docker` - Docker 相关
- `build` - 构建过程
- `deploy` - 部署过程

**元数据提取**:
- 自动检测端口信息
- 标记成功/失败状态
- 提取耗时信息

### 4. 自动日志流管理 ✅

**应用创建时**:
```go
// 创建应用时自动创建日志流
if err := gs.logStreamManager.CreateStreamForApp(appName, app.CurrentLog); err != nil {
    gs.logger.Warnf("创建日志流失败: %v", err)
}
```

**部署开始时**:
```go
// 获取或创建日志流
logStream := gs.logStreamManager.GetOrCreateStream(app.Name, logFile)
```

**日志流生命周期**:
- 应用创建时启动
- 部署过程中持续工作
- 应用删除时清理

### 5. 前端 WebSocket 集成 ✅

**新增功能**:
- WebSocket 和 SSE 双模式支持
- 自动连接类型选择（默认 WebSocket）
- 部署状态显示
- 部署进度条
- 自动重连机制
- 连接状态指示

**使用示例**:
```typescript
import RealtimeLogs from '../components/RealtimeLogs'

<RealtimeLogs 
  appName="myapp"
  autoScroll={true}
  maxLines={500}
  showControls={true}
/>
```

## 技术架构

### 后端架构

```
GitServer
  |
  ├── LogStreamManager (全局日志流管理器)
  |     |
  |     ├── LogStream (每个应用的日志流)
  |     |     |
  |     |     ├── LogWatcher (文件监听器)
  |     |     └── Clients (WebSocket/SSE 客户端)
  |     |
  |     └── Methods:
  |           ├── GetOrCreateStream()
  |           ├── CreateStreamForApp()
  |           ├── HandleWebSocketLogsWS()  // WebSocket
  |           ├── HandleWebSocketLogs()     // SSE
  |           └── BroadcastDeployStatus()
  |
  └── DeployLogger (部署日志记录器)
        ├── WriteLog()
        ├── WriteCommand()
        └── WriteCommandOutput()
```

### 数据流

```
[部署过程] 
    |
    v
[DeployLogger] --写入--> [日志文件]
    |                       |
    |                       v
    |                  [LogWatcher] --监听-->
    |                       |
    |                       v
    |                  [LogStream] --解析-->
    |                       |
    |                       v
    |                  [Clients] --推送-->
    |                       |
    |                       v
    |                  [前端 WebSocket/SSE]
    |
    v
[BroadcastDeployStatus] --状态更新--> [LogStream] --> [Clients]
```

## 使用指南

### 1. 启动应用

```bash
# 启动 SSLcat
./sslcat

# 日志流会自动启动
```

### 2. 查看实时日志

**通过 Web UI**:
1. 访问 `https://your-domain/admin/git-server`
2. 选择应用
3. 点击「实时日志」标签
4. 日志会自动流式显示

**通过 WebSocket API** (JavaScript):
```javascript
const ws = new WebSocket('ws://localhost:18080/admin/api/git-server/logs/stream-ws?app=myapp')

ws.onmessage = (event) => {
  const message = JSON.parse(event.data)
  
  if (message.type === 'log') {
    console.log(`[${message.data.level}] ${message.data.message}`)
  } else if (message.type === 'connected') {
    console.log('Connected:', message.message)
  }
}
```

**通过 SSE API** (JavaScript):
```javascript
const eventSource = new EventSource('http://localhost:18080/admin/api/git-server/logs/stream?app=myapp')

eventSource.addEventListener('log', (event) => {
  const logEntry = JSON.parse(event.data)
  console.log(`[${logEntry.level}] ${logEntry.message}`)
})
```

### 3. 监控部署状态

部署状态会自动推送到日志流中：

```javascript
ws.onmessage = (event) => {
  const message = JSON.parse(event.data)
  
  if (message.type === 'log' && message.data.source === 'deploy_status') {
    const { status, progress, message: msg } = message.data.metadata
    console.log(`部署状态: ${status} (${progress}%) - ${msg}`)
  }
}
```

## API 参考

### WebSocket API

**连接**:
```
ws://your-server/admin/api/git-server/logs/stream-ws?app={app_name}
```

**消息类型**:

| 类型 | 方向 | 说明 |
|------|------|------|
| `connected` | 服务器→客户端 | 连接建立 |
| `log` | 服务器→客户端 | 日志条目 |
| `ping` | 服务器→客户端 | 心跳 |
| `error` | 服务器→客户端 | 错误消息 |

### SSE API

**连接**:
```
GET /admin/api/git-server/logs/stream?app={app_name}
```

**事件类型**:
- `log` - 日志条目
- `ping` - 心跳

### 历史日志 API

**获取历史日志**:
```
GET /admin/api/git-server/logs/history?app={app_name}&limit={limit}
```

响应示例:
```json
{
  "success": true,
  "data": [
    {
      "timestamp": "2024-10-02T10:00:00Z",
      "level": "info",
      "source": "deploy",
      "message": "部署开始",
      "app_name": "myapp",
      "metadata": {}
    }
  ],
  "count": 50
}
```

## 性能特性

### 后端优化

1. **缓冲管理**:
   - 每个客户端 100 条日志缓冲
   - 缓冲区满时丢弃旧日志
   
2. **文件轮询**:
   - 100ms 轮询间隔
   - 增量读取，不重新读取整个文件
   
3. **客户端隔离**:
   - 每个客户端独立 channel
   - 自动清理断开的连接
   
4. **日志限制**:
   - 前端默认显示 500 条最新日志
   - 可配置显示行数

### 前端优化

1. **自动滚动**:
   - 可选的自动滚动到底部
   - 性能友好的 smooth scroll
   
2. **日志过滤**:
   - 按级别过滤（info, warn, error, debug）
   - 按来源过滤（git, build, deploy 等）
   
3. **内存管理**:
   - 自动限制日志条数
   - 老日志自动清理

## 安全性

1. **认证**:
   - 需要管理员权限
   - Cookie 认证
   
2. **权限检查**:
   - 只能查看自己有权限的应用
   
3. **连接限制**:
   - WebSocket 心跳检测
   - 自动清理僵尸连接

## 故障排查

### WebSocket 连接失败

**问题**: WebSocket 无法连接

**解决方案**:
1. 检查防火墙设置
2. 确认 WebSocket 端口开放
3. 尝试使用 SSE 模式作为备选

### 日志不更新

**问题**: 实时日志不显示新内容

**解决方案**:
1. 检查应用是否正在运行
2. 查看日志文件权限
3. 重启日志流：
   ```bash
   # 在 SSLcat 控制台
   DELETE /admin/api/git-server/logs/stream?app=myapp
   ```

### 日志解析错误

**问题**: 日志格式无法识别

**解决方案**:
1. 确保日志输出为文本格式
2. 建议使用结构化日志（JSON）
3. 日志格式示例：
   ```
   [timestamp] [level] [source] message
   ```

## 未来扩展

计划中的功能：

- [ ] 日志搜索和高亮
- [ ] 日志导出（多种格式）
- [ ] 日志统计和分析
- [ ] 日志告警规则
- [ ] 多应用日志聚合视图
- [ ] 日志持久化到数据库
- [ ] 日志压缩和归档
- [ ] 自定义日志解析规则

## 相关文件

### 后端
- `/internal/runner/realtime_logs.go` - 实时日志流核心实现
- `/internal/runner/git_server.go` - Git 服务器和部署流程
- `/internal/web/api_runners.go` - API 接口
- `/internal/web/server.go` - 路由注册

### 前端
- `/frontend/src/components/RealtimeLogs.tsx` - 实时日志组件
- `/frontend/src/pages/GitServerManagement.tsx` - Git 服务器管理页面

### 文档
- `/docs/git-deploy-ssh-implementation.md` - Git SSH 部署实现
- `/docs/git-deploy-ssh-plan.md` - 部署计划
- `/docs/realtime-logs-feature.md` - 本文档

## 总结

本次更新大幅增强了实时日志流功能：

✅ **WebSocket 双向通信** - 更高效的实时推送  
✅ **部署状态推送** - 实时掌握部署进度  
✅ **智能日志解析** - 自动识别日志格式和级别  
✅ **自动流管理** - 无需手动创建和销毁  
✅ **前端完整集成** - 开箱即用的 UI 组件  

这些改进让 Git SSH 部署系统的用户体验媲美 Heroku、Vercel 等商业 PaaS 平台！🚀

