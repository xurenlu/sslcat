# SSLcat 配置热重载使用指南

## 概述

SSLcat 现在支持配置热重载功能，可以在不重启服务的情况下动态更新配置，提供零停机的配置管理体验。

## 主要特性

### 🔄 **自动配置监听**
- **文件系统监听**: 自动监听配置文件变化
- **防抖处理**: 避免短时间内多次重载
- **哈希验证**: 只有配置真正改变时才触发重载

### ✅ **配置验证**
- **语法检查**: 重载前验证JSON格式
- **逻辑验证**: 检查配置参数的合理性
- **组件验证**: 验证各组件是否支持新配置

### 🔧 **组件化重载**
- **模块化设计**: 每个组件独立实现重载逻辑
- **原子性操作**: 要么全部成功，要么全部回滚
- **错误隔离**: 单个组件失败不影响其他组件

### 📊 **监控和统计**
- **重载统计**: 成功次数、失败次数、耗时等
- **状态监控**: 实时查看重载状态
- **详细日志**: 完整的重载过程日志

## 支持的配置项

### ✅ **已支持热重载**
- **代理规则**: 添加、删除、修改代理规则
- **负载均衡**: 后端服务器、算法、健康检查配置
- **压缩设置**: 压缩算法、级别、文件类型配置
- **CDN缓存**: 缓存规则、TTL设置

### ⚠️ **需要重启的配置**
- **服务器端口**: 监听端口变化需要重启
- **SSL证书目录**: 证书和密钥目录变化需要重启
- **管理面板前缀**: AdminPrefix变化建议重启
- **日志级别**: Debug模式切换需要重启

## API接口

### 1. 手动触发重载
```bash
# POST /sslcat-panel/api/config/reload
curl -X POST \
  -H "Cookie: session=your_session_cookie" \
  http://localhost/sslcat-panel/api/config/reload
```

**响应示例**:
```json
{
  "success": true,
  "duration": "15.2ms",
  "timestamp": 1640995200,
  "message": "Configuration reloaded successfully"
}
```

### 2. 验证配置
```bash
# POST /sslcat-panel/api/config/validate
curl -X POST \
  -H "Cookie: session=your_session_cookie" \
  http://localhost/sslcat-panel/api/config/validate
```

**响应示例**:
```json
{
  "valid": true,
  "timestamp": 1640995200,
  "message": "Configuration is valid"
}
```

### 3. 获取重载状态
```bash
# GET /sslcat-panel/api/config/reload/status
curl -H "Cookie: session=your_session_cookie" \
  http://localhost/sslcat-panel/api/config/reload/status
```

**响应示例**:
```json
{
  "reload_stats": {
    "component_count": 1,
    "reload_count": 5,
    "success_count": 4,
    "error_count": 1,
    "last_reload_time": "2024-01-01T12:00:00Z",
    "component_names": ["proxy_manager"]
  },
  "config_info": {
    "file_path": "/etc/sslcat/sslcat.conf",
    "size": 2048,
    "mod_time": "2024-01-01T12:00:00Z",
    "hash": "abc123...",
    "is_watching": true,
    "debounce_ms": 1000
  },
  "watcher_active": true,
  "timestamp": 1640995200
}
```

### 4. 获取配置文件信息
```bash
# GET /sslcat-panel/api/config/info
curl -H "Cookie: session=your_session_cookie" \
  http://localhost/sslcat-panel/api/config/info
```

## 使用方法

### 1. 启动服务
```bash
# 启动SSLcat，配置热重载功能会自动启用
./sslcat --config /etc/sslcat/sslcat.conf
```

### 2. 修改配置文件
```bash
# 编辑配置文件
nano /etc/sslcat/sslcat.conf

# 保存后，SSLcat会自动检测变化并重载配置
```

### 3. 查看重载日志
```bash
# 查看实时日志
tail -f /var/log/sslcat.log | grep -E "(reload|config)"
```

### 4. 手动触发重载
```bash
# 通过API手动触发重载
curl -X POST \
  -H "Cookie: session=your_session_cookie" \
  http://localhost/sslcat-panel/api/config/reload
```

## 配置示例

### 基本配置
```json
{
  "compression": {
    "enabled": true,
    "algorithms": ["br", "gzip"],
    "min_size": 1024,
    "level": {
      "gzip": 6,
      "brotli": 6
    }
  },
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "load_balancer_enabled": true,
        "load_balancer_algorithm": "round_robin",
        "load_balancer_backends": [
          {
            "id": "api-1",
            "host": "192.168.1.10",
            "port": 8080,
            "enabled": true
          }
        ]
      }
    ]
  }
}
```

### 动态添加后端服务器
```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "load_balancer_enabled": true,
        "load_balancer_backends": [
          {
            "id": "api-1",
            "host": "192.168.1.10",
            "port": 8080,
            "enabled": true
          },
          {
            "id": "api-2",
            "host": "192.168.1.11",
            "port": 8080,
            "enabled": true
          }
        ]
      }
    ]
  }
}
```

## 重载流程

### 自动重载流程
1. **文件监听**: 检测配置文件变化
2. **防抖处理**: 等待1秒确保文件写入完成
3. **哈希验证**: 计算文件哈希，确认真正有变化
4. **配置解析**: 解析新的配置文件
5. **配置验证**: 验证配置格式和逻辑
6. **组件验证**: 验证各组件是否支持新配置
7. **执行重载**: 依次重载各个组件
8. **更新状态**: 更新配置状态和统计信息

### 手动重载流程
1. **API调用**: 通过API触发重载
2. **权限检查**: 验证管理员权限
3. **强制重载**: 跳过文件变化检测，直接重载
4. **返回结果**: 返回重载结果和统计信息

## 日志示例

### 成功重载
```
INFO[2024-01-01T12:00:00Z] Configuration changed, starting hot reload...
INFO[2024-01-01T12:00:00Z] Configuration reload started
INFO[2024-01-01T12:00:00Z] Starting reload of 1 components
INFO[2024-01-01T12:00:00Z] All components validated successfully
INFO[2024-01-01T12:00:00Z] Reloading proxy manager configuration
INFO[2024-01-01T12:00:00Z] Proxy manager reloaded: 2 rules -> 3 rules, 2 load balancers
INFO[2024-01-01T12:00:00Z] Successfully reloaded component: proxy_manager
INFO[2024-01-01T12:00:00Z] Successfully reloaded all 1 components in 15.2ms
INFO[2024-01-01T12:00:00Z] Configuration reload completed successfully
```

### 重载失败
```
INFO[2024-01-01T12:00:00Z] Configuration changed, starting hot reload...
ERROR[2024-01-01T12:00:00Z] Failed to load new config: invalid JSON syntax
ERROR[2024-01-01T12:00:00Z] Configuration reload failed: failed to load new config
```

## 最佳实践

### 1. 配置备份
```bash
# 修改配置前先备份
cp /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.backup.$(date +%Y%m%d_%H%M%S)
```

### 2. 配置验证
```bash
# 修改配置后先验证
curl -X POST \
  -H "Cookie: session=your_session_cookie" \
  http://localhost/sslcat-panel/api/config/validate
```

### 3. 监控重载状态
```bash
# 定期检查重载状态
curl -H "Cookie: session=your_session_cookie" \
  http://localhost/sslcat-panel/api/config/reload/status
```

### 4. 分批修改
- 避免一次性大量修改配置
- 分批进行配置更新
- 每次修改后验证效果

### 5. 测试环境验证
- 在测试环境先验证配置
- 确认无误后再应用到生产环境

## 故障排除

### 常见问题

1. **配置重载失败**
   - 检查配置文件语法
   - 查看详细错误日志
   - 使用API验证配置

2. **部分组件重载失败**
   - 检查组件特定的配置要求
   - 查看组件错误日志
   - 必要时重启服务

3. **重载频率过高**
   - 检查是否有程序频繁修改配置文件
   - 调整防抖间隔时间

### 调试命令

查看配置重载日志：
```bash
tail -f /var/log/sslcat.log | grep -E "(reload|config)"
```

检查配置文件语法：
```bash
python -m json.tool /etc/sslcat/sslcat.conf
```

手动验证配置：
```bash
curl -X POST -H "Cookie: session=xxx" \
  http://localhost/sslcat-panel/api/config/validate
```

## 性能影响

- **重载耗时**: 通常在10-50ms内完成
- **内存使用**: 重载过程中内存使用略有增加
- **服务可用性**: 重载过程中服务持续可用
- **连接影响**: 现有连接不受影响

通过配置热重载功能，SSLcat 可以实现真正的零停机配置管理，大大提升了运维效率和服务可用性。
