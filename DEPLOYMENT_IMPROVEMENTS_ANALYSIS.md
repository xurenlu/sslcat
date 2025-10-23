# SSLcat 部署改进分析报告

## 问题分析

### 1. SQLite 数据库访问频率问题

**现状分析**：
- 当前系统有多个 SQLite 数据库：
  - `users.db` - 用户管理
  - `git_deploy.db` - Git 部署管理
  - `threat_intel.db` - 威胁情报
- 每个数据库都配置了连接池（最大10个连接，5个空闲连接）
- 使用了 WAL 模式和适当的缓存设置

**访问频率评估**：
- **用户认证**：每次登录/操作都会访问，频率中等
- **Git 部署**：每次部署都会频繁写入，频率较高
- **威胁情报**：定期更新，频率较低
- **实时日志**：当前主要基于文件，数据库访问较少

**结论**：SQLite 访问频率适中，当前配置合理，但可以通过优化减少不必要的访问。

### 2. 发布 ID 和日志隔离问题

**现状分析**：
- 当前有 `deployID` 概念，但格式简单：`deploy_${timestamp}`
- 日志文件按日期分割：`deploy-${date}.log`
- 所有部署日志混合在同一个文件中
- Web 界面只能查看实时日志，无法按发布 ID 过滤

**问题**：
- 无法区分不同版本的发布
- 日志查询困难
- 缺乏发布历史管理

## 解决方案设计

### 1. 数据库访问优化

#### 1.1 连接池优化
```go
// 优化连接池配置
db.SetMaxOpenConns(20)                 // 增加最大连接数
db.SetMaxIdleConns(10)                 // 增加空闲连接数
db.SetConnMaxLifetime(10 * time.Minute) // 延长连接生存时间
```

#### 1.2 缓存策略
- 实现应用元数据缓存（Redis 或内存缓存）
- 减少重复的数据库查询
- 使用读写分离模式

#### 1.3 批量操作
- 批量插入日志记录
- 批量更新状态信息
- 减少数据库锁定时间

### 2. 发布 ID 和日志隔离系统

#### 2.1 发布 ID 生成策略
```go
type DeploymentID struct {
    UUID      string    `json:"uuid"`      // UUID v4
    AppName   string    `json:"app_name"`  // 应用名称
    CommitSHA string    `json:"commit_sha"` // Git 提交哈希
    Branch    string    `json:"branch"`    // 分支名称
    Timestamp time.Time `json:"timestamp"` // 创建时间
    Version   string    `json:"version"`   // 语义化版本（可选）
}
```

#### 2.2 数据库表结构设计
```sql
-- 发布记录表
CREATE TABLE deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT UNIQUE NOT NULL,
    app_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    branch TEXT NOT NULL,
    version TEXT,
    status TEXT NOT NULL, -- pending, building, success, failed
    started_at DATETIME NOT NULL,
    completed_at DATETIME,
    build_duration INTEGER, -- 毫秒
    deployer TEXT, -- 部署者
    message TEXT, -- 提交信息
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 发布日志表
CREATE TABLE deployment_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_uuid TEXT NOT NULL,
    level TEXT NOT NULL, -- error, warn, info, debug
    source TEXT NOT NULL, -- git, build, deploy, etc.
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    metadata TEXT, -- JSON 格式的额外信息
    FOREIGN KEY (deployment_uuid) REFERENCES deployments(uuid)
);

-- 发布状态表
CREATE TABLE deployment_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_uuid TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER DEFAULT 0, -- 0-100
    message TEXT,
    timestamp DATETIME NOT NULL,
    FOREIGN KEY (deployment_uuid) REFERENCES deployments(uuid)
);
```

#### 2.3 日志隔离实现
```go
type DeploymentLogger struct {
    UUID      string
    AppName   string
    LogFile   string
    DB        *sql.DB
    Writer    io.Writer
}

func (dl *DeploymentLogger) WriteLog(level, source, message string) {
    // 1. 写入文件（保持现有功能）
    dl.writeToFile(level, source, message)
    
    // 2. 写入数据库（新增功能）
    dl.writeToDB(level, source, message)
    
    // 3. 发送到实时日志流（保持现有功能）
    dl.sendToStream(level, source, message)
}

func (dl *DeploymentLogger) writeToDB(level, source, message string) {
    query := `
        INSERT INTO deployment_logs (deployment_uuid, level, source, message, timestamp)
        VALUES (?, ?, ?, ?, ?)
    `
    _, err := dl.DB.Exec(query, dl.UUID, level, source, message, time.Now())
    if err != nil {
        // 记录错误但不影响主流程
        log.Printf("Failed to write deployment log to DB: %v", err)
    }
}
```

#### 2.4 Web 界面改进

**发布历史页面**：
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

interface DeploymentLogs {
  deploymentUuid: string
  logs: LogEntry[]
  status: DeploymentStatus[]
}
```

**API 端点设计**：
```go
// 获取发布历史
GET /api/git-server/deployments?app={appName}&limit=20&offset=0

// 获取特定发布的日志
GET /api/git-server/deployments/{uuid}/logs?limit=100

// 获取特定发布的状态
GET /api/git-server/deployments/{uuid}/status

// 实时日志流（支持发布 ID 过滤）
GET /api/git-server/logs/stream?app={appName}&deployment={uuid}
```

### 3. 实现计划

#### 阶段 1：数据库结构升级
1. 创建新的数据库表
2. 实现数据库迁移脚本
3. 添加发布 ID 生成逻辑

#### 阶段 2：日志系统重构
1. 重构 `DeployLogger` 支持 UUID
2. 实现数据库日志存储
3. 保持文件日志兼容性

#### 阶段 3：API 和前端改进
1. 实现新的 API 端点
2. 创建发布历史页面
3. 改进实时日志查询

#### 阶段 4：性能优化
1. 实现数据库索引
2. 添加缓存层
3. 优化查询性能

## 与 Dokku/Railway 对比

### Dokku
- **优点**：轻量级，基于 Docker
- **缺点**：缺乏发布历史管理，日志查询功能有限
- **我们的优势**：更完善的发布管理和日志隔离

### Railway
- **优点**：完整的发布历史，基于关系型数据库
- **缺点**：依赖外部数据库，复杂度高
- **我们的优势**：基于 SQLite 的轻量级实现，功能对等

## 总结

这个改进方案将显著提升 SSLcat 的部署管理能力：

1. **发布追踪**：每个发布都有唯一的 UUID，便于追踪和管理
2. **日志隔离**：不同发布的日志完全隔离，便于调试和审计
3. **历史管理**：完整的发布历史记录，支持回滚和对比
4. **性能优化**：减少数据库访问频率，提升系统性能
5. **用户体验**：类似 Railway 的发布管理体验，但更轻量级

这个方案既保持了 SQLite 的轻量级特性，又需要提供了企业级的发布管理功能。
