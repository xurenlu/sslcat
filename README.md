# SSLcat 🚀

[![Version](https://img.shields.io/badge/version-2.0.0--rc1-blue.svg)](https://github.com/xurenlu/sslcat/releases/tag/v2.0.0-rc1)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Enterprise-grade Web Server and API Gateway with automatic SSL certificate management, intelligent load balancing, and modern web management interface.**

> **企业级 Web 服务器和 API 网关，具备自动 SSL 证书管理、智能负载均衡和现代化 Web 管理界面。**

---

## 🌟 What is SSLcat? / SSLcat 是什么？

SSLcat is a powerful, high-performance web server and API gateway built with Go that simplifies SSL certificate management and provides intelligent proxy capabilities. Think of it as **nginx + Caddy + Web UI** all in one package.

SSLcat 是一个功能强大的高性能 Web 服务器和 API 网关，使用 Go 语言构建，简化 SSL 证书管理并提供智能代理功能。可以把它理解为 **nginx + Caddy + Web UI** 的一体化解决方案。

### 🎯 Key Features / 核心特性

- 🔒 **Auto SSL Management** - Let's Encrypt integration with automatic certificate renewal
- 🔄 **Smart Load Balancing** - 6 algorithms with health checks and session persistence
- 🎨 **Modern Web UI** - React-based management dashboard with real-time monitoring
- 🛡️ **Advanced Security** - AI-powered threat detection and IP blocking
- 📡 **Real-time Logs** - WebSocket-based live log streaming
- 🌍 **Multi-language** - English, Chinese, Japanese support
- 📊 **Built-in Monitoring** - Automatic Goroutine, memory, and performance monitoring
- ☁️ **AWS Route53 Support** - Automatic DNS verification for SSL certificates
- ⚡ **Smart Config Reload** - Intelligent configuration change detection
- 🔥 **Cache Warmup** - Eliminate cold start latency
- 🎛️ **Advanced Rate Limiting** - 4 algorithms for precise traffic control

- 🔒 **自动 SSL 管理** - Let's Encrypt 集成，自动证书续期
- 🔄 **智能负载均衡** - 6种算法，健康检查和会话保持
- 🎨 **现代化 Web UI** - 基于 React 的管理面板，实时监控
- 🛡️ **高级安全** - AI 驱动的威胁检测和 IP 封禁
- 📡 **实时日志** - 基于 WebSocket 的实时日志流
- 🌍 **多语言支持** - 英语、中文、日语
- 📊 **内置监控** - 自动 Goroutine、内存和性能监控
- ☁️ **AWS Route53 支持** - SSL 证书自动 DNS 验证
- ⚡ **智能配置重载** - 智能配置变更检测
- 🔥 **缓存预热** - 消除冷启动延迟
- 🎛️ **高级限流** - 4种算法精确流量控制

---

## 🏆 Why Choose SSLcat? / 为什么选择 SSLcat？

### vs Nginx / 与 Nginx 对比

| Feature / 功能 | SSLcat | Nginx | Advantage / 优势 |
|----------------|--------|-------|------------------|
| **🎨 Web Management UI** | ✅ | ❌ | No more config file editing / 无需编辑配置文件 |
| **🔒 Auto SSL** | ✅ | ❌ | No manual certificate management / 无需手动管理证书 |
| **📊 Real-time Monitoring** | ✅ | ❌ | Built-in dashboard / 内置监控面板 |
| **🤖 AI Security** | ✅ | ❌ | Intelligent threat detection / 智能威胁检测 |

### vs Caddy / 与 Caddy 对比

| Feature / 功能 | SSLcat | Caddy | Advantage / 优势 |
|----------------|--------|-------|------------------|
| **🔄 Advanced Load Balancing** | ✅ 6 algorithms | ✅ Basic | More algorithms / 更多算法 |
| **👥 Multi-user Management** | ✅ | ❌ | Team collaboration / 团队协作 |
| **🔑 API Token System** | ✅ | ❌ | Granular permissions / 细粒度权限控制 |
| **📡 Real-time Logs** | ✅ | ❌ | WebSocket streaming / WebSocket 日志流 |

---

## ⚡ Quick Start / 快速开始

### One-liner Installation (macOS/Linux)

```bash
# Download and install / 下载并安装
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh | bash

# Start with default config / 使用默认配置启动
sslcat --port 8080

# Open web UI / 打开 Web 界面: http://localhost:8080/sslcat-panel/
# Default login / 默认登录: admin / admin*9527
```

> **📝 Configuration Format / 配置格式**: SSLcat uses **JSON** configuration files (not YAML). All examples below use JSON syntax. / SSLcat 使用 **JSON** 配置文件（不是 YAML）。以下所有示例都使用 JSON 语法。

### Docker Compose

```yaml
version: '3.8'
services:
  sslcat:
    image: sslcat/sslcat:latest
    ports:
      - "80:80"
      - "443:443"
      - "8080:8080"
    volumes:
      - ./data:/app/data
      - ./sslcat.conf:/app/sslcat.conf
```

```bash
docker compose up -d
```

---

## 🛠️ Core Capabilities / 核心功能

### 🔒 SSL Certificate Management / SSL 证书管理

```json
{
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true,
    "domains": ["example.com", "api.example.com"]
  }
}
```

### 🔄 Load Balancing & Proxy / 负载均衡与代理

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "localhost",
        "port": 3000,
        "load_balancer_enabled": true,
        "load_balancer_algorithm": "round_robin",
        "health_check_enabled": true,
        "load_balancer_backends": [
          {"host": "10.0.1.10", "port": 3000},
          {"host": "10.0.1.11", "port": 3000}
        ]
      }
    ]
  }
}
```

### 🌍 Static Site Hosting / 静态站点托管

```json
{
  "static_sites": [
    {
      "domain": "www.example.com",
      "root": "/var/www/example",
      "index": "index.html",
      "try_files": true
    }
  ]
}
```

### 🐘 PHP Site Hosting / PHP 站点托管

```json
{
  "php_sites": [
    {
      "domain": "blog.example.com",
      "root": "/var/www/blog",
      "fcgi_host": "localhost",
      "fcgi_port": 9000
    }
  ]
}
```

---

## 🌍 Use Cases / 使用场景

- **Microservices Gateway** - Route traffic to multiple services / **微服务网关** - 将流量路由到多个服务
- **Automated SSL Management** - Centralized certificate management / **自动化SSL管理** - 集中式证书管理
- **API Gateway** - Load balancing and security for APIs / **API 网关** - API 的负载均衡和安全
- **Static Site Hosting** - High-performance static file serving / **静态站点托管** - 高性能静态文件服务
- **Reverse Proxy** - Intelligent request routing / **反向代理** - 智能请求路由

---

## 🚀 Enterprise Features / 企业级功能

- 👥 **Multi-user Management** - Role-based access control / **多用户管理** - 基于角色的访问控制
- 🔑 **API Token System** - Secure API access with granular permissions / **API Token 系统** - 具有细粒度权限的安全 API 访问
- 🔔 **Smart Notifications** - Email, Webhook, and AI-powered alerts / **智能通知** - 邮件、Webhook 和 AI 驱动的告警
- 🌍 **GeoIP Analysis** - Attack source visualization / **GeoIP 分析** - 攻击来源可视化
- 📊 **Advanced Analytics** - Real-time metrics and reporting / **高级分析** - 实时指标和报告
- 🛡️ **AI Security** - GPT-4 powered threat detection / **AI 安全** - GPT-4 驱动的威胁检测
- 🌐 **CDN Caching** - Built-in CDN with upstream cache and image optimization / **CDN 缓存** - 内置 CDN，支持上游缓存和图片优化
- 🔒 **WAF Protection** - Web Application Firewall with custom rules / **WAF 防护** - 支持自定义规则的 Web 应用防火墙
- 🚫 **DDoS Protection** - Advanced rate limiting and IP blocking / **DDoS 防护** - 高级限流和 IP 封禁
- 🌍 **Cluster Deployment** - Master-slave synchronization / **集群部署** - 主从同步

---

## 📈 Roadmap / 路线图

- [ ] WebSocket proxy support / WebSocket 代理支持
- [ ] gRPC proxy support / gRPC 代理支持
- [ ] Advanced caching strategies / 高级缓存策略
- [ ] GraphQL API / GraphQL API

---

## ❓ FAQ / 常见问题

### Q: 忘记登录密码了怎么办？ / How to reset forgotten password?

如果你忘记了 Web 管理界面的登录密码，可以使用命令行工具重置：

If you forget your web management interface login password, you can reset it using the command-line tool:

```bash
# 进入 sslcat 目录 / Go to sslcat directory
cd /opt/sslcat  # 或你的 sslcat 安装目录 / or your sslcat installation directory

# 重置密码 / Reset password
# 用法: go run tools/cmd/reset_password/main.go <用户名> <新密码>
# Usage: go run tools/cmd/reset_password/main.go <username> <new_password>
go run tools/cmd/reset_password/main.go admin "your_new_password"

# 示例 / Example:
go run tools/cmd/reset_password/main.go admin "MyNewPass123!"
```

**注意 / Note**:
- 密码必须包含字母和数字 / Password must contain letters and numbers
- 重置后无需重启服务 / No need to restart service after reset
- 默认管理员账号 / Default admin account: `admin` / `admin*9527`

---

## 📖 Documentation / 文档

For complete documentation, please visit / 完整文档请访问：

- [📚 **Complete Documentation** / **完整文档**](docs/)
- [🚀 **Getting Started Guide** / **入门指南**](docs/zh/getting-started/introduction.md)
- [🏗️ **Architecture Overview** / **架构概览**](docs/en/getting-started/architecture.md)
- [🔧 **Configuration Reference** / **配置参考**](docs/zh/configuration/)
- [🔒 **Security Features** / **安全功能**](docs/zh/security/)
- [📝 **Changelog** / **更新日志**](CHANGELOG.md) - 查看所有版本变更记录

---

## 🤝 Contributing / 贡献

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

我们欢迎贡献！详情请参见我们的[贡献指南](CONTRIBUTING.md)。

## 📄 License / 许可证

MIT License - see [LICENSE](LICENSE) file for details.

MIT 许可证 - 详情请参见 [LICENSE](LICENSE) 文件。

## 🔗 Links / 链接

- [GitHub Repository](https://github.com/xurenlu/sslcat)
- [Documentation](https://sslcat.com/docs)
- [Issue Tracker](https://github.com/xurenlu/sslcat/issues)
- [Releases](https://github.com/xurenlu/sslcat/releases)

---

<div align="center">

**Built with ❤️ using Go**

[⭐ Star us on GitHub](https://github.com/xurenlu/sslcat) • [📖 Read the docs](docs/) • [🐛 Report bugs](https://github.com/xurenlu/sslcat/issues)

</div>
