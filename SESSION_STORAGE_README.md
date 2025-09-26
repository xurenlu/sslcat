# SSLcat 会话存储系统

## 概述

SSLcat现在支持多种会话存储后端，解决了重启服务器后需要重新登录的问题。系统提供了两种存储方案：

1. **文件存储** (推荐) - 基于JSON文件的持久化存储
2. **内存存储** - 原有实现，重启后丢失

## 特性

### 文件存储
- ✅ **持久化** - 服务器重启后会话保持
- ✅ **零依赖** - 无需额外数据库
- ✅ **可读性** - JSON格式，便于调试
- ✅ **跨平台** - 支持所有操作系统
- ✅ **自动清理** - 定期清理过期会话

### 内存存储
- ✅ **高性能** - 内存访问速度极快
- ✅ **简单** - 无需额外配置
- ❌ **非持久化** - 重启后丢失

## 使用方法

### 1. 基本使用

```go
package main

import (
    "log"
    "github.com/xurenlu/sslcat/internal/web"
)

func main() {
    // 创建日志接口
    logger := &MyLogger{}
    
    // 创建会话管理器工厂
    factory := web.NewSessionManagerFactory()
    
    // 使用文件存储（推荐）
    sessionManager, err := factory.CreateSessionManager(logger, "file", "./data")
    if err != nil {
        log.Fatal(err)
    }
    defer sessionManager.Close()
    
    // 创建会话
    session, err := sessionManager.CreateSession("admin", "super_admin", "127.0.0.1", "Mozilla/5.0")
    if err != nil {
        log.Fatal(err)
    }
    
    // 会话现在会持久化到文件系统
    fmt.Printf("会话ID: %s\n", session.SessionID)
}
```

### 2. 配置示例

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 9933
  },
  "session": {
    "storage_type": "file",
    "data_dir": "./data",
    "session_timeout": 28800,
    "cleanup_interval": 600
  }
}
```

### 3. 存储类型对比

| 特性 | 文件存储 | 内存存储 |
|------|----------|----------|
| 持久化 | ✅ | ❌ |
| 性能 | 高 | 极高 |
| 依赖 | 无 | 无 |
| 大小 | 几乎无开销 | 几乎无开销 |
| 调试 | 容易 | 困难 |
| 重启恢复 | ✅ | ❌ |

## 文件结构

```
data/
└── sessions/
    ├── session_abc123.json
    ├── session_def456.json
    └── session_ghi789.json
```

每个会话文件包含完整的会话信息：

```json
{
  "session_id": "abc123",
  "username": "admin",
  "role": "super_admin",
  "login_time": "2024-01-01T10:00:00Z",
  "expires_at": "2024-01-01T18:00:00Z",
  "ip_address": "127.0.0.1",
  "user_agent": "Mozilla/5.0",
  "last_access": "2024-01-01T10:30:00Z"
}
```

## 性能优化

### 文件存储优化
- 使用读写锁保证并发安全
- 异步更新最后访问时间
- 定期清理过期会话文件
- JSON序列化/反序列化优化

### 内存存储优化
- 直接内存访问
- 最小化锁竞争
- 定期清理过期会话

## 故障排除

### 常见问题

1. **会话文件权限问题**
   ```bash
   chmod 755 ./data/sessions/
   ```

2. **磁盘空间不足**
   - 检查会话清理是否正常工作
   - 手动清理过期会话文件

3. **会话不持久化**
   - 确认使用文件存储类型
   - 检查数据目录权限

### 调试方法

1. **查看会话文件**
   ```bash
   ls -la ./data/sessions/
   cat ./data/sessions/session_*.json
   ```

2. **监控会话统计**
   ```go
   stats := sessionManager.GetSessionStats()
   fmt.Printf("活跃会话: %d\n", stats["active_sessions"])
   ```

## 迁移指南

### 从内存存储迁移到文件存储

1. 备份现有配置
2. 修改配置中的存储类型
3. 重启服务器
4. 验证会话持久化

### 配置示例

```json
{
  "session": {
    "storage_type": "file",  // 从 "memory" 改为 "file"
    "data_dir": "./data"
  }
}
```

## 高级配置

### 自定义存储后端

```go
// 实现 SessionStorage 接口
type CustomStorage struct {
    // 自定义实现
}

func (c *CustomStorage) Set(key string, session *Session) error {
    // 自定义存储逻辑
}

// 使用自定义存储
sessionManager := NewSessionManagerWithStorage(customStorage, logger)
```

## 总结

通过引入文件存储后端，SSLcat现在支持会话持久化，解决了重启服务器后需要重新登录的问题。文件存储方案具有以下优势：

- **零依赖** - 无需额外数据库
- **高性能** - 基于文件系统的高效存储
- **易调试** - JSON格式便于查看和调试
- **跨平台** - 支持所有操作系统
- **自动清理** - 定期清理过期会话

推荐在生产环境中使用文件存储，在开发环境中可以使用内存存储以获得最佳性能。
