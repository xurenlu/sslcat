# SSLcat 数据库容错机制指南

## 概述

SSLcat 采用了多层容错机制，确保即使数据库出现问题，核心功能仍然可用。

## 核心原则

### 1. 核心功能不依赖数据库 ✅
- **代理转发**：完全基于配置文件，不依赖数据库
- **SSL 证书管理**：基于文件系统存储
- **基本路由**：基于配置文件

### 2. 数据库功能降级运行 ✅
- **用户认证**：数据库丢失时，管理员无法登录 Web 界面
- **Git 部署**：数据库丢失时，部署功能降级为文件日志模式
- **威胁情报**：数据库丢失时，安全防护降级但不影响基本功能

## 数据库用途分析

### 核心功能（不依赖数据库）
```
✅ HTTP/HTTPS 代理转发
✅ SSL 证书管理
✅ 负载均衡
✅ 缓存功能
✅ 压缩功能
✅ 基本路由
```

### 增强功能（依赖数据库）
```
⚠️  用户认证和授权
⚠️  Git 部署管理
⚠️  威胁情报防护
⚠️  发布历史追踪
⚠️  实时日志查询
```

## 容错机制

### 1. 数据库初始化容错
```go
// 数据库初始化失败时，系统继续运行
if db, err := NewDeploymentDatabase(dataDir); err != nil {
    logrus.Errorf("初始化发布数据库失败: %v", err)
    logrus.Warn("发布数据库初始化失败，将使用文件日志模式继续运行")
    deploymentDB = nil // 继续运行，但没有数据库支持
} else {
    deploymentDB = db
    logrus.Info("发布数据库初始化成功")
}
```

### 2. 日志记录容错
```go
// 只存储关键日志到数据库，详细日志仅存储到文件
func (dl *DeploymentLogger) isImportantLog(entry *LogEntry) bool {
    // 只存储错误和警告级别的日志
    if entry.Level == "error" || entry.Level == "warn" {
        return true
    }
    
    // 存储关键状态变更日志
    importantSources := []string{"status", "deploy", "system"}
    // ... 其他判断逻辑
    
    return false
}
```

### 3. 自动备份机制
```go
// 定期备份数据库
func (fm *FailoverManager) AutoBackup(interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    for range ticker.C {
        if err := fm.CreateBackup(); err != nil {
            fm.logger.Printf("自动备份失败: %v", err)
        }
    }
}
```

## 故障场景处理

### 场景 1：数据库文件丢失
**影响**：
- ❌ Web 管理界面无法登录
- ❌ Git 部署功能降级
- ❌ 威胁情报防护降级
- ✅ 核心代理功能正常

**处理**：
1. 检查备份目录是否有可用备份
2. 从备份恢复数据库
3. 重启 SSLcat 服务

### 场景 2：数据库损坏
**影响**：
- ❌ 相关功能异常
- ✅ 核心代理功能正常

**处理**：
1. 停止 SSLcat 服务
2. 从备份恢复数据库
3. 重启 SSLcat 服务

### 场景 3：数据库权限问题
**影响**：
- ❌ 数据库相关功能异常
- ✅ 核心代理功能正常

**处理**：
1. 检查文件权限
2. 修复权限问题
3. 重启 SSLcat 服务

## 备份策略

### 自动备份
```bash
# 每小时备份一次
sslcat-backup --interval 1h

# 每天备份一次
sslcat-backup --interval 24h
```

### 手动备份
```bash
# 创建备份
sslcat-backup --manual

# 从备份恢复
sslcat-restore --backup-dir /path/to/backup
```

### 备份文件结构
```
data/
├── backups/
│   ├── users.db_2024-01-15_10-30-00
│   ├── git_deploy.db_2024-01-15_10-30-00
│   ├── deployments.db_2024-01-15_10-30-00
│   └── threat_intel.db_2024-01-15_10-30-00
├── users.db
├── git_deploy.db
├── deployments.db
└── threat_intel.db
```

## 监控和告警

### 数据库健康检查
```go
// 定期检查数据库完整性
func (fm *FailoverManager) CheckDatabaseIntegrity() error {
    databases := []string{
        "users.db",
        "git_deploy.db", 
        "deployments.db",
        "threat_intel.db",
    }
    
    for _, dbName := range databases {
        if err := fm.checkSingleDatabase(dbName); err != nil {
            // 记录错误但不影响核心功能
            fm.logger.Printf("数据库完整性检查失败: %s - %v", dbName, err)
        }
    }
    
    return nil
}
```

### 告警机制
- 数据库初始化失败时记录警告日志
- 数据库写入失败时记录错误日志
- 自动备份失败时记录错误日志

## 最佳实践

### 1. 定期备份
- 设置自动备份，建议每小时备份一次
- 保留至少 7 天的备份文件
- 定期测试备份文件的完整性

### 2. 监控数据库
- 监控数据库文件大小变化
- 监控数据库写入性能
- 设置数据库健康检查

### 3. 权限管理
- 确保 SSLcat 进程有数据库文件的读写权限
- 定期检查文件权限设置
- 避免手动修改数据库文件

### 4. 灾难恢复
- 制定数据库恢复流程
- 定期演练恢复过程
- 准备应急处理方案

## 总结

SSLcat 的容错机制确保了：

1. **核心功能始终可用**：即使数据库完全丢失，HTTP/HTTPS 代理功能仍然正常
2. **优雅降级**：数据库功能失效时，系统会降级运行而不是崩溃
3. **自动恢复**：提供自动备份和恢复机制
4. **监控告警**：及时发现和处理数据库问题

这种设计确保了 SSLcat 的高可用性和可靠性，即使在最坏的情况下，网站的基本访问功能也不会受到影响。
