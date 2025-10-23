# SSLcat 发布管理系统

## 概述

SSLcat 发布管理系统是一个基于 UUID 的发布追踪和日志隔离系统，类似于 Railway 的发布管理功能，但基于 SQLite 实现，更加轻量级。

## 主要特性

### 1. UUID 发布追踪
- 每个发布都有唯一的 UUID
- 支持发布历史查询
- 完整的发布生命周期管理

### 2. 日志隔离
- 每个发布的日志完全隔离
- 支持按发布 ID 查询日志
- 同时支持文件日志和数据库日志

### 3. 状态管理
- 实时发布状态更新
- 发布进度跟踪
- 状态历史记录

### 4. 数据库优化
- 基于 SQLite 的轻量级实现
- 优化的连接池配置
- 支持 WAL 模式

## 架构设计

### 数据库表结构

#### deployments 表
```sql
CREATE TABLE deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    app_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    branch TEXT NOT NULL,
    version TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at DATETIME NOT NULL,
    completed_at DATETIME,
    build_duration INTEGER,
    deployer TEXT DEFAULT 'system',
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### deployment_logs 表
```sql
CREATE TABLE deployment_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_uuid TEXT NOT NULL,
    level TEXT NOT NULL,
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    metadata TEXT,
    FOREIGN KEY (deployment_uuid) REFERENCES deployments(uuid)
);
```

#### deployment_status 表
```sql
CREATE TABLE deployment_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_uuid TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER DEFAULT 0,
    message TEXT,
    timestamp DATETIME NOT NULL,
    FOREIGN KEY (deployment_uuid) REFERENCES deployments(uuid)
);
```

## API 接口

### 获取发布列表
```
GET /api/git-server/deployments?app={appName}&limit=20&offset=0
```

### 获取单个发布记录
```
GET /api/git-server/deployments/{uuid}
```

### 获取发布日志
```
GET /api/git-server/deployments/{uuid}/logs?limit=100&offset=0
```

### 获取发布状态
```
GET /api/git-server/deployments/{uuid}/status
```

### 实时日志流（支持发布 ID 过滤）
```
GET /api/git-server/logs/stream?app={appName}&deployment={uuid}
```

## 使用示例

### 1. 创建发布日志记录器

```go
// 创建发布日志记录器
deployLogger, err := NewDeploymentLogger(
    "my-app",           // 应用名称
    "abc123def456",     // Git 提交哈希
    "main",             // 分支名称
    "user@example.com", // 部署者
    "Fix bug in login", // 提交信息
    deploymentDB,       // 数据库实例
    "/path/to/logs",    // 日志目录
)
if err != nil {
    return err
}
defer deployLogger.Close()
```

### 2. 设置状态回调

```go
// 设置状态更新回调
deployLogger.SetStatusCallback(func(status string, progress int, message string) {
    // 发送到实时日志流
    logStreamManager.BroadcastDeployStatus(DeployStatusUpdate{
        AppName:   "my-app",
        DeployID:  deployLogger.GetUUID(),
        Status:    status,
        Progress:  progress,
        Message:   message,
        Timestamp: time.Now(),
    })
})
```

### 3. 记录日志和状态

```go
// 写入日志
deployLogger.WriteLog("info", "git", "开始检测应用类型")
deployLogger.WriteLogWithMetadata("info", "build", "执行构建命令", map[string]interface{}{
    "command": "npm install",
    "duration": "30s",
})

// 更新状态
deployLogger.UpdateStatus("building", 30, "检测应用类型")
deployLogger.UpdateStatus("building", 60, "构建应用")
deployLogger.UpdateStatus("deploying", 90, "部署应用")
deployLogger.UpdateStatus("success", 100, "部署成功")
```

### 4. 查询发布记录

```go
// 查询发布列表
deployments, err := db.GetDeployments("my-app", 20, 0)
if err != nil {
    return err
}

// 查询特定发布的日志
logs, err := db.GetDeploymentLogs(deploymentUUID, 100, 0)
if err != nil {
    return err
}

// 查询发布状态历史
statuses, err := db.GetDeploymentStatus(deploymentUUID)
if err != nil {
    return err
}
```

## 前端集成

### 发布历史页面

```typescript
interface Deployment {
  uuid: string
  appName: string
  commitSHA: string
  branch: string
  version?: string
  status: 'pending' | 'building' | 'success' | 'failed'
  startedAt: string
  completedAt?: string
  buildDuration?: number
  deployer: string
  message: string
}

// 获取发布列表
const fetchDeployments = async (appName: string) => {
  const response = await fetch(`/api/git-server/deployments?app=${appName}`)
  const data = await response.json()
  return data.data as Deployment[]
}
```

### 实时日志查询

```typescript
// 连接到实时日志流
const connectLogStream = (appName: string, deploymentUUID?: string) => {
  const url = `/api/git-server/logs/stream?app=${appName}${deploymentUUID ? `&deployment=${deploymentUUID}` : ''}`
  const eventSource = new EventSource(url)
  
  eventSource.addEventListener('log', (event) => {
    const logEntry = JSON.parse(event.data)
    // 处理日志条目
  })
  
  eventSource.addEventListener('status', (event) => {
    const statusUpdate = JSON.parse(event.data)
    // 处理状态更新
  })
}
```

## 性能优化

### 1. 数据库优化
- 使用 WAL 模式提高并发性能
- 优化连接池配置
- 创建适当的索引

### 2. 日志优化
- 批量写入数据库日志
- 异步处理状态更新
- 实现日志轮转和清理

### 3. 缓存策略
- 实现应用元数据缓存
- 缓存发布状态信息
- 减少重复数据库查询

## 与现有系统集成

### 1. Git 服务器集成
- 修改 `processGitPush` 函数使用新的 `DeploymentLogger`
- 集成状态回调机制
- 保持向后兼容性

### 2. Web 界面集成
- 添加发布历史页面
- 实现按发布 ID 过滤日志
- 支持发布状态实时更新

### 3. API 集成
- 注册新的 API 路由
- 实现发布管理端点
- 支持分页和过滤

## 测试

运行测试脚本验证系统功能：

```bash
go run test_deployment_system.go
```

测试包括：
- 数据库初始化
- 发布日志记录器创建
- 日志和状态记录
- 数据查询功能

## 总结

SSLcat 发布管理系统提供了：

1. **完整的发布追踪**：每个发布都有唯一的 UUID 和完整的历史记录
2. **日志隔离**：不同发布的日志完全隔离，便于调试和审计
3. **实时状态管理**：支持发布状态的实时更新和进度跟踪
4. **轻量级实现**：基于 SQLite，无需外部数据库依赖
5. **高性能**：优化的数据库配置和缓存策略

这个系统既保持了 SSLcat 的轻量级特性，又提供了企业级的发布管理功能，可以与 Railway 等现代部署平台相媲美。
