# WebSocket代理优化指南

## 概述

本文档描述了对SSLcat WebSocket代理功能的优化改进，主要解决连接断开时的数据丢失问题。

## 优化前的问题

1. **缺少WebSocket检测**：原有实现没有检测WebSocket升级请求，直接使用HTTP反向代理
2. **数据丢失风险**：使用简单的`copyData`函数，任何一边连接断开都会立即关闭另一边
3. **无缓冲机制**：没有数据缓冲，网络波动时容易丢失数据
4. **错误处理不完善**：缺少重试和恢复机制
5. **无连接监控**：无法及时发现连接异常

## 优化方案

### 1. WebSocket检测机制

```go
func (m *Manager) isWebSocketUpgrade(r *http.Request) bool {
    return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
        strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}
```

- 检测`Connection: Upgrade`和`Upgrade: websocket`头部
- 自动路由WebSocket请求到优化的处理器

### 2. 带缓冲的数据传输

- **缓冲通道**：使用带缓冲的channel进行数据传输，默认缓冲100个消息
- **异步处理**：读取和写入操作分离，避免阻塞
- **数据复制**：避免竞态条件，确保数据完整性

### 3. 连接状态管理

- **原子操作**：使用`sync/atomic`管理连接状态
- **优雅关闭**：给缓冲数据时间完成传输
- **资源清理**：确保所有goroutine和连接正确关闭

### 4. 超时和错误处理

- **读取超时**：可配置的读取超时，默认30秒
- **写入超时**：可配置的写入超时，默认10秒
- **连接超时**：建立连接时的超时控制
- **错误恢复**：网络超时时继续尝试，而不是立即断开

### 5. 连接监控

- **定期检查**：每10秒检查连接状态
- **心跳机制**：预留心跳检测接口
- **状态报告**：详细的连接状态日志

## 配置选项

在`ProxyRule`中添加了以下WebSocket优化配置：

```json
{
  "websocket_optimized": true,        // 是否启用WebSocket优化
  "websocket_buffer_size": 100,       // 缓冲区大小
  "websocket_read_timeout": 30,       // 读取超时（秒）
  "websocket_write_timeout": 10,      // 写入超时（秒）
  "websocket_ping_interval": 30       // 心跳间隔（秒）
}
```

## 使用方法

### 1. 启用WebSocket优化

在代理规则配置中设置：

```json
{
  "domain": "ws.example.com",
  "target": "192.168.1.100",
  "port": 8080,
  "enabled": true,
  "websocket_optimized": true,
  "websocket_buffer_size": 200,
  "websocket_read_timeout": 60,
  "websocket_write_timeout": 15
}
```

### 2. 禁用优化（使用原有方式）

```json
{
  "domain": "ws.example.com",
  "target": "192.168.1.100", 
  "port": 8080,
  "enabled": true,
  "websocket_optimized": false
}
```

## 优化效果

### 数据丢失防护

1. **缓冲保护**：网络波动时，数据暂存在缓冲区中
2. **异步传输**：读写分离，避免一端阻塞影响另一端
3. **优雅关闭**：连接关闭时给予缓冲数据传输时间

### 连接稳定性

1. **超时重试**：网络超时时继续尝试而不是立即断开
2. **状态监控**：实时监控连接状态，及时发现问题
3. **错误隔离**：一端出错不会立即影响另一端

### 性能提升

1. **并发处理**：多个goroutine并行处理数据传输
2. **内存优化**：合理的缓冲区大小配置
3. **资源管理**：及时清理资源，避免内存泄漏

## 测试建议

### 1. 基本功能测试

```bash
# 测试WebSocket连接建立
wscat -c ws://your-domain.com/websocket

# 测试数据传输
echo "test message" | wscat -c ws://your-domain.com/websocket
```

### 2. 网络异常测试

- 模拟网络延迟
- 模拟连接中断
- 模拟高并发连接

### 3. 性能测试

- 大量并发WebSocket连接
- 高频率消息传输
- 长时间连接稳定性

## 监控和日志

优化后的WebSocket代理会产生以下日志：

```
INFO: Detected WebSocket upgrade request for example.com
INFO: WebSocket handshake successful for example.com  
DEBUG: WebSocket read error (client): connection closed
INFO: WebSocket proxy connection closed for 192.168.1.100
```

## 故障排除

### 常见问题

1. **握手失败**：检查上游服务器WebSocket支持
2. **连接超时**：调整超时配置参数
3. **数据丢失**：增加缓冲区大小
4. **内存占用高**：减少缓冲区大小或连接数

### 调试建议

1. 启用DEBUG日志级别
2. 监控goroutine数量
3. 检查网络连接状态
4. 分析错误日志模式

## 总结

通过以上优化，WebSocket代理能够：

1. **自动检测**WebSocket升级请求
2. **缓冲数据**避免网络波动时的丢失
3. **监控连接**状态并及时处理异常
4. **优雅处理**连接关闭和错误恢复
5. **提供配置**选项满足不同场景需求

这些改进大大提高了WebSocket代理的稳定性和可靠性，有效解决了连接断开时的数据丢失问题。
