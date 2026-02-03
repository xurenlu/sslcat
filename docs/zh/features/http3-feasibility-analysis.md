# HTTP/3 支持可行性分析

## 📋 概述

本文档分析在 sslcat 项目中支持 HTTP/3 协议的技术可行性、实现方案和潜在挑战。

## 🔍 当前状态

### 已支持的协议
- ✅ **HTTP/1.1**: 完全支持
- ✅ **HTTP/2**: 已实现，使用 `golang.org/x/net/http2`
- ❌ **HTTP/3**: 尚未支持

### 当前架构
- 使用标准 Go `net/http` 包作为 HTTP 服务器基础
- HTTP/2 通过 `http2.ConfigureServer()` 配置在 TLS 连接上
- 支持多域名 SSL 证书管理
- 支持代理、静态站点、PHP 站点等多种后端

## 🌐 HTTP/3 简介

### 什么是 HTTP/3？
HTTP/3 是基于 **QUIC**（Quick UDP Internet Connections）协议的下一代 HTTP 协议，由 IETF 标准化（RFC 9114）。

### HTTP/3 的关键特性
1. **基于 UDP 而非 TCP**: 使用 QUIC 协议，底层是 UDP
2. **内置加密**: QUIC 在传输层就包含 TLS 1.3
3. **连接迁移**: 网络切换时保持连接（如 WiFi 切换到移动网络）
4. **多路复用**: 类似 HTTP/2，但解决了队头阻塞问题
5. **0-RTT 连接恢复**: 快速重连，减少延迟

### HTTP/3 vs HTTP/2 vs HTTP/1.1

| 特性 | HTTP/1.1 | HTTP/2 | HTTP/3 |
|------|----------|--------|--------|
| **传输协议** | TCP | TCP | UDP (QUIC) |
| **加密** | TLS (可选) | TLS (必需) | 内置 TLS 1.3 |
| **多路复用** | ❌ | ✅ | ✅ |
| **队头阻塞** | 有 | 有（TCP层） | ❌ |
| **连接迁移** | ❌ | ❌ | ✅ |
| **0-RTT** | ❌ | ❌ | ✅ |
| **端口** | 80/443 | 443 | 443 |

## 💡 实现方案

### 方案 1: 使用 quic-go 库（推荐）

**quic-go** 是 Go 语言中最成熟和广泛使用的 QUIC/HTTP/3 实现库。

#### 优势
- ✅ 纯 Go 实现，无 CGO 依赖
- ✅ 活跃维护，社区支持良好
- ✅ 完整的 HTTP/3 支持（RFC 9114）
- ✅ 支持 0-RTT、连接迁移等高级特性
- ✅ 提供 Prometheus 指标支持
- ✅ 文档完善

#### 依赖
```bash
go get github.com/quic-go/quic-go
go get github.com/quic-go/webtransport-go  # 可选，用于 WebTransport
```

#### 实现架构

```
┌─────────────────────────────────────────┐
│         sslcat 服务器                    │
├─────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐  │
│  │  HTTP/1.1    │    │   HTTP/2     │  │
│  │  (TCP:443)   │    │  (TLS:443)   │  │
│  └──────────────┘    └──────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │      HTTP/3 Server (QUIC:443)     │  │
│  │  github.com/quic-go/quic-go       │  │
│  └────────────────────────────────────┘  │
│           │                                │
│           ▼                                │
│  ┌────────────────────────────────────┐  │
│  │     统一的 Handler 接口            │  │
│  │  (webServer http.Handler)         │  │
│  └────────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

#### 代码实现示例

**1. 添加配置支持**

```go
// internal/config/config.go
type ServerConfig struct {
    // ... 现有字段 ...
    
    // HTTP/3 配置
    HTTP3Enabled bool `json:"http3_enabled"` // 是否启用 HTTP/3（默认 false）
    
    HTTP3Config *HTTP3Config `json:"http3_config,omitempty"`
}

type HTTP3Config struct {
    Enabled              bool   `json:"enabled"`
    MaxIdleTimeout       string `json:"max_idle_timeout"`       // 默认 "120s"
    MaxIncomingStreams   int64  `json:"max_incoming_streams"`    // 默认 1000
    MaxIncomingUniStreams int64 `json:"max_incoming_uni_streams"` // 默认 1000
    MaxStreamReceiveWindow int64 `json:"max_stream_receive_window"` // 默认 6MB
    MaxConnectionReceiveWindow int64 `json:"max_connection_receive_window"` // 默认 15MB
}
```

**2. 创建 HTTP/3 服务器**

```go
// internal/web/http3_server.go
package web

import (
    "crypto/tls"
    "net/http"
    
    "github.com/quic-go/quic-go/http3"
    "github.com/sirupsen/logrus"
)

type HTTP3Server struct {
    server *http3.Server
    config *config.Config
    handler http.Handler
}

func NewHTTP3Server(cfg *config.Config, handler http.Handler) *HTTP3Server {
    return &HTTP3Server{
        config: cfg,
        handler: handler,
    }
}

func (s *HTTP3Server) Start() error {
    if !s.config.Server.HTTP3Enabled {
        return nil // HTTP/3 未启用
    }
    
    tlsConfig := sslManager.GetTLSConfig()
    
    // HTTP/3 需要 TLS 1.3
    tlsConfig.MinVersion = tls.VersionTLS13
    
    // 添加 HTTP/3 ALPN 标识
    tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h3")
    
    s.server = &http3.Server{
        Addr:      fmt.Sprintf("%s:443", s.config.Server.Host),
        Handler:   s.handler,
        TLSConfig: tlsConfig,
    }
    
    // 配置 QUIC 参数
    if s.config.Server.HTTP3Config != nil {
        cfg := s.config.Server.HTTP3Config
        if cfg.MaxIdleTimeout != "" {
            if timeout, err := time.ParseDuration(cfg.MaxIdleTimeout); err == nil {
                // 注意：quic-go 的配置方式可能需要调整
            }
        }
    }
    
    logrus.Infof("HTTP/3 server starting on %s:443", s.config.Server.Host)
    
    go func() {
        if err := s.server.ListenAndServe(); err != nil {
            logrus.Errorf("HTTP/3 server error: %v", err)
        }
    }()
    
    return nil
}

func (s *HTTP3Server) Stop() error {
    if s.server != nil {
        return s.server.Close()
    }
    return nil
}
```

**3. 在 main.go 中集成**

```go
// main.go
import (
    "github.com/quic-go/quic-go/http3"
)

func startStandardMode(...) {
    // ... 现有的 HTTP/1.1 和 HTTP/2 服务器代码 ...
    
    // 启动 HTTP/3 服务器
    if cfg.Server.HTTP3Enabled {
        http3Server := web.NewHTTP3Server(cfg, webServer, sslManager)
        if err := http3Server.Start(); err != nil {
            logrus.Errorf("Failed to start HTTP/3 server: %v", err)
        }
    }
}
```

**4. 更新 TLS 配置**

```go
// internal/ssl/manager.go
func (m *Manager) GetTLSConfig() *tls.Config {
    // ... 现有代码 ...
    
    // 如果启用 HTTP/3，添加 h3 ALPN
    if m.config.Server.HTTP3Enabled {
        nextProtos = append(nextProtos, "h3")
        // HTTP/3 需要 TLS 1.3
        tlsConfig.MinVersion = tls.VersionTLS13
    }
    
    return tlsConfig
}
```

### 方案 2: 使用标准库（未来）

Go 标准库计划在未来版本中支持 HTTP/3，但目前（Go 1.25）尚未包含。

**时间线**: 预计 Go 1.26+ 可能会包含 HTTP/3 支持（基于 `net/http` 的扩展）。

## ⚠️ 挑战与注意事项

### 1. 端口共享问题

**问题**: HTTP/3 使用 UDP，而 HTTP/1.1 和 HTTP/2 使用 TCP，它们可以共享同一个端口（443），但需要不同的监听器。

**解决方案**:
- HTTP/1.1/2: TCP 监听器在 443 端口
- HTTP/3: UDP 监听器在 443 端口
- 操作系统允许同一端口上的 TCP 和 UDP 监听器共存

### 2. 防火墙和 NAT 问题

**问题**: 
- 某些防火墙可能阻止 UDP 443
- NAT 设备可能不支持 UDP 连接迁移
- 企业网络可能限制 UDP 流量

**影响**: 
- HTTP/3 连接可能失败，自动降级到 HTTP/2
- 需要确保 HTTP/2 作为后备方案正常工作

### 3. 证书兼容性

**要求**: HTTP/3 需要 TLS 1.3，这意味着：
- 所有证书必须支持 TLS 1.3
- 某些旧证书可能需要更新
- ACME 证书通常都支持 TLS 1.3

### 4. 性能考虑

**优势**:
- 减少延迟（特别是高延迟网络）
- 更好的多路复用（无 TCP 队头阻塞）
- 连接迁移（移动设备场景）

**开销**:
- UDP 包处理可能比 TCP 稍慢（但总体性能更好）
- 需要额外的内存用于 QUIC 连接状态

### 5. 兼容性

**客户端支持**:
- ✅ Chrome/Edge (2020+)
- ✅ Firefox (2021+)
- ✅ Safari (2023+)
- ✅ curl (7.66+)
- ❌ 旧版浏览器和工具

**自动降级**: 现代浏览器会自动在 HTTP/3、HTTP/2、HTTP/1.1 之间选择最佳协议。

## 📊 实现工作量评估

### 开发任务

1. **配置支持** (2-4 小时)
   - 添加 HTTP/3 配置字段
   - 配置验证和默认值处理

2. **HTTP/3 服务器实现** (4-8 小时)
   - 创建 HTTP/3 服务器包装器
   - 集成到主服务器启动流程
   - TLS 配置更新

3. **测试** (4-6 小时)
   - 单元测试
   - 集成测试
   - 性能测试
   - 兼容性测试

4. **文档** (2-3 小时)
   - 配置文档
   - 使用指南
   - 故障排除指南

**总计**: 约 12-21 小时（1.5-3 个工作日）

### 依赖影响

- **新增依赖**: `github.com/quic-go/quic-go` (~2MB)
- **构建时间**: 增加约 10-20 秒（首次）
- **二进制大小**: 增加约 5-10MB

## 🎯 推荐实施策略

### 阶段 1: 基础支持（MVP）
1. 添加 HTTP/3 配置选项（默认禁用）
2. 实现基本的 HTTP/3 服务器
3. 与现有 HTTP/1.1 和 HTTP/2 服务器并行运行
4. 基本测试和文档

### 阶段 2: 优化和监控
1. 添加 HTTP/3 性能指标
2. 优化 QUIC 参数配置
3. 添加连接迁移支持
4. 监控和日志增强

### 阶段 3: 高级特性（可选）
1. WebTransport 支持
2. HTTP Datagrams 支持
3. 0-RTT 连接恢复优化

## ✅ 实施建议

### 建议实施
✅ **推荐实施 HTTP/3 支持**，原因：
1. **技术趋势**: HTTP/3 是未来标准，主流浏览器已支持
2. **性能优势**: 特别是在高延迟和移动网络场景
3. **竞争优势**: 提供最新协议支持，提升用户体验
4. **实现成本**: 相对较低，主要是集成工作
5. **向后兼容**: 不影响现有 HTTP/1.1 和 HTTP/2 功能

### 实施注意事项
1. **默认禁用**: 初始版本默认禁用 HTTP/3，让用户选择启用
2. **渐进式部署**: 先在测试环境验证，再逐步推广
3. **监控指标**: 添加 HTTP/3 连接数、错误率等指标
4. **降级机制**: 确保 HTTP/2 作为可靠的后备方案
5. **文档完善**: 提供清晰的配置指南和故障排除文档

## 📚 参考资源

- [quic-go 官方文档](https://quic-go.net/docs/)
- [HTTP/3 RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
- [Cloudflare HTTP/3 指南](https://www.cloudflare.com/learning/ddos/what-is-http3/)
- [Mozilla HTTP/3 实现](https://blog.mozilla.org/security/2020/12/08/firefox-83-introduces-https-rr-dns-over-https/)

## 🔄 后续步骤

如果决定实施 HTTP/3 支持：

1. **技术评审**: 团队评审本文档和技术方案
2. **依赖评估**: 评估 quic-go 库的稳定性和兼容性
3. **原型开发**: 创建最小可行原型进行验证
4. **测试计划**: 制定详细的测试计划
5. **实施计划**: 制定分阶段实施计划

---

**文档版本**: 1.0  
**创建日期**: 2026-02-03  
**最后更新**: 2026-02-03
