# SSLcat 🚀

[![Version](https://img.shields.io/badge/version-2.3.0--rc9-blue.svg)](https://github.com/xurenlu/sslcat/releases/tag/v2.3.0-rc9)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CPU Optimized](https://img.shields.io/badge/CPU%20optimized-97%25%20reduction-brightgreen.svg)](#performance)

> **Enterprise-grade SSL proxy server with automatic certificate management, intelligent domain forwarding, and modern web management interface.**

> **企业级 SSL 代理服务器，具备自动证书管理、智能域名转发和现代化 Web 管理界面。**

---

## 🌟 What is SSLcat? / SSLcat 是什么？

SSLcat is a powerful, high-performance SSL proxy server built with Go that simplifies SSL certificate management and provides intelligent domain forwarding capabilities. Think of it as **nginx + Caddy + Web UI + GitOps** all in one package.

SSLcat 是一个功能强大的高性能 SSL 代理服务器，使用 Go 语言构建，简化 SSL 证书管理并提供智能域名转发功能。可以把它理解为 **nginx + Caddy + Web UI + GitOps** 的一体化解决方案。

### 🎯 Key Features / 核心特性

- 🔒 **Auto SSL Management** - Let's Encrypt integration with automatic certificate renewal
- 🔄 **Smart Load Balancing** - 6 algorithms with health checks and session persistence  
- 🎨 **Modern Web UI** - React-based management dashboard with real-time monitoring
- 🚀 **GitOps Deployment** - Git push to deploy (like Dokku/Heroku)
- 🐳 **Docker Integration** - Built-in container management and deployment
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
- 🚀 **GitOps 部署** - Git 推送即部署（类似 Dokku/Heroku）
- 🐳 **Docker 集成** - 内置容器管理和部署
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
| **🚀 GitOps** | ✅ | ❌ | Deploy with `git push` / 使用 `git push` 部署 |
| **📊 Real-time Monitoring** | ✅ | ❌ | Built-in dashboard / 内置监控面板 |
| **🤖 AI Security** | ✅ | ❌ | Intelligent threat detection / 智能威胁检测 |

### vs Caddy / 与 Caddy 对比

| Feature / 功能 | SSLcat | Caddy | Advantage / 优势 |
|----------------|--------|-------|------------------|
| **🔄 Advanced Load Balancing** | ✅ 6 algorithms | ✅ Basic | More algorithms / 更多算法 |
| **👥 Multi-user Management** | ✅ | ❌ | Team collaboration / 团队协作 |
| **🐳 Container Support** | ✅ | ❌ | Docker registry and deployment / Docker 镜像管理和部署 |
| **🔑 API Token System** | ✅ | ❌ | Granular permissions / 细粒度权限控制 |
| **📡 Real-time Logs** | ✅ | ❌ | WebSocket streaming / WebSocket 日志流 |

---

## ⚡ Quick Start / 快速开始

### One-liner Installation (macOS/Linux)

```bash
# Download and install / 下载并安装
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh | bash

# Start with default config / 使用默认配置启动
sslcat --port 18080

# Open web UI / 打开 Web 界面: http://localhost:18080/sslcat-panel/
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
      - "18080:18080"
    volumes:
      - ./data:/app/data
      - ./sslcat.conf:/app/sslcat.conf
```

```bash
docker compose up -d
```

---

## 📊 Performance / 性能表现

Recent optimizations achieved **97% CPU reduction** / 最近的优化实现了 **97% CPU 降低**:
- 8 Runner apps: 400% CPU → 11% CPU
- 1 Runner app: 55% CPU → 4% CPU  
- Idle state: 50-100% CPU → <1% CPU

最近的优化实现了 **97% CPU 降低**：
- 8 个 Runner 应用：400% CPU → 11% CPU
- 1 个 Runner 应用：55% CPU → 4% CPU
- 空闲状态：50-100% CPU → < 1% CPU

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

### 🚀 GitOps Deployment / GitOps 部署

```bash
# Add SSLcat as remote / 添加 SSLcat 作为远程仓库
git remote add sslcat git@your-server:your-app.git

# Deploy with git push / 使用 git push 部署
git push sslcat main
```

---

## 🌍 Use Cases / 使用场景

- **Microservices Gateway** - Route traffic to multiple services / **微服务网关** - 将流量路由到多个服务
- **Automated SSL Management** - Centralized certificate management / **自动化SSL管理** - 集中式证书管理
- **Development Platform** - GitOps deployment for teams / **开发平台** - 团队的 GitOps 部署
- **Container Orchestration** - Docker-based application hosting / **容器编排** - 基于 Docker 的应用托管
- **API Gateway** - Load balancing and security for APIs / **API 网关** - API 的负载均衡和安全

---

## 🚀 Enterprise Features / 企业级功能

- 👥 **Multi-user Management** - Role-based access control / **多用户管理** - 基于角色的访问控制
- 🔑 **API Token System** - Secure API access with granular permissions / **API Token 系统** - 具有细粒度权限的安全 API 访问
- 🔔 **Smart Notifications** - Email, Webhook, and AI-powered alerts / **智能通知** - 邮件、Webhook 和 AI 驱动的告警
- 🌍 **GeoIP Analysis** - Attack source visualization / **GeoIP 分析** - 攻击来源可视化
- 📊 **Advanced Analytics** - Real-time metrics and reporting / **高级分析** - 实时指标和报告
- 🛡️ **AI Security** - GPT-4 powered threat detection / **AI 安全** - GPT-4 驱动的威胁检测

---

## 📈 Roadmap / 路线图

- [ ] Kubernetes integration / Kubernetes 集成
- [ ] Multi-cluster support / 多集群支持  
- [ ] Advanced caching strategies / 高级缓存策略
- [ ] Plugin system / 插件系统
- [ ] GraphQL API / GraphQL API

---

## ❓ FAQ / 常见问题

### Q: 忘记登录密码了怎么办？ / How to reset forgotten password?

如果你忘记了 Web 管理界面的登录密码，可以使用命令行工具重置：

If you forget your web management interface login password, you can reset it using the command-line tool:

```bash
# 进入 sslcat 目录 / Go to sslcat directory
cd /opt/sslcat  # 或你的 sslcat 安装目录 / or your sslcat installation directory

# 重置密码 / Reset password（仅 root / sudo 可执行）
# Reset password (root / sudo only)
sudo sslcat reset-password
```

**注意 / Note**:
- 密码必须至少 10 位，并包含至少三类字符（大写、小写、数字、符号） / Password must be at least 10 characters and include at least three character classes
- 重置命令会交互式要求输入两次密码；不会从命令行参数读取密码 / The command asks for the password twice interactively and never accepts it as an argument
- 重置后无需重启服务 / No need to restart service after reset

---

## 📖 Documentation / 文档

For complete documentation, please visit / 完整文档请访问：

- [📚 **Complete Documentation** / **完整文档**](docs/)
- [🚀 **Getting Started Guide** / **入门指南**](docs/zh/getting-started/introduction.md)
- [🏗️ **Architecture Overview** / **架构概览**](docs/en/getting-started/architecture.md)
- [🔧 **Configuration Reference** / **配置参考**](docs/zh/configuration/)
- [🔒 **Security Features** / **安全功能**](docs/zh/security/)
- [📊 **Performance Optimization** / **性能优化**](CPU_OPTIMIZATION_COMPLETE.md)
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
