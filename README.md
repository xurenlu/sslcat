# SSLcat 🚀

[![Version](https://img.shields.io/badge/version-1.3.16--rc11-blue.svg)](https://github.com/xurenlu/sslcat/releases/tag/v1.3.16-rc11)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CPU Optimized](https://img.shields.io/badge/CPU%20optimized-97%25%20reduction-brightgreen.svg)](#performance)

> **Enterprise-grade SSL proxy server with automatic certificate management, intelligent domain forwarding, and modern web management interface.**

## 🌟 What is SSLcat?

SSLcat is a powerful, high-performance SSL proxy server built with Go that simplifies SSL certificate management and provides intelligent domain forwarding capabilities. Think of it as **nginx + Caddy + Web UI + GitOps** all in one package.

### 🎯 Key Features

- 🔒 **Auto SSL Management** - Let's Encrypt integration with automatic certificate renewal
- 🔄 **Smart Load Balancing** - 6 algorithms with health checks and session persistence  
- 🎨 **Modern Web UI** - React-based management dashboard with real-time monitoring
- 🚀 **GitOps Deployment** - Git push to deploy (like Dokku/Heroku)
- 🐳 **Docker Integration** - Built-in container management and deployment
- 🛡️ **Advanced Security** - AI-powered threat detection and IP blocking
- 📡 **Real-time Logs** - WebSocket-based live log streaming
- 🌍 **Multi-language** - English, Chinese, Japanese support

## ⚡ Quick Start

### One-liner Installation (macOS/Linux)

```bash
# Download and install
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh | bash

# Start with default config
sslcat --port 8080

# Open web UI: http://localhost:8080/sslcat-panel/
# Default login: admin / admin*9527
```

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

## 🏆 Why Choose SSLcat?

### vs Nginx
- ✅ **Web Management UI** - No more config file editing
- ✅ **Auto SSL** - No manual certificate management
- ✅ **GitOps** - Deploy with `git push`
- ✅ **Real-time Monitoring** - Built-in dashboard

### vs Caddy  
- ✅ **Advanced Load Balancing** - 6 algorithms vs basic
- ✅ **Enterprise Features** - Multi-user, API tokens, notifications
- ✅ **Container Support** - Docker registry and deployment
- ✅ **AI Security** - Intelligent threat detection

## 📊 Performance

Recent optimizations achieved **97% CPU reduction**:
- 8 Runner apps: 400% CPU → 11% CPU
- Idle state: 50-100% CPU → <1% CPU
- Optimized goroutines and eliminated busy-waiting

## 🛠️ Core Capabilities

### 🔒 SSL Certificate Management
```yaml
ssl:
  enabled: true
  auto_cert: true
  staging: false
  domains:
    - example.com
    - api.example.com
```

### 🔄 Load Balancing & Proxy
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "localhost:3000"
      load_balancer:
        algorithm: "round_robin"
        health_check: true
        backends:
          - "10.0.1.10:3000"
          - "10.0.1.11:3000"
```

### 🚀 GitOps Deployment
```bash
# Add SSLcat as remote
git remote add sslcat git@your-server:your-app.git

# Deploy with git push
git push sslcat main
```

## 📖 Documentation

- [📚 Complete Documentation](docs/)
- [🚀 Getting Started Guide](docs/zh/getting-started/introduction.md)
- [🏗️ Architecture Overview](docs/en/getting-started/architecture.md)
- [🔧 Configuration Reference](docs/zh/configuration/)
- [🔒 Security Features](docs/zh/security/)

## 🌍 Use Cases

- **Microservices Gateway** - Route traffic to multiple services
- **SSL Termination** - Centralized certificate management
- **Development Platform** - GitOps deployment for teams
- **Container Orchestration** - Docker-based application hosting
- **API Gateway** - Load balancing and security for APIs

## 🚀 Enterprise Features

- 👥 **Multi-user Management** - Role-based access control
- 🔑 **API Token System** - Secure API access with granular permissions
- 🔔 **Smart Notifications** - Email, Webhook, and AI-powered alerts
- 🌍 **GeoIP Analysis** - Attack source visualization
- 📊 **Advanced Analytics** - Real-time metrics and reporting
- 🛡️ **AI Security** - GPT-4 powered threat detection

## 📈 Roadmap

- [ ] Kubernetes integration
- [ ] Multi-cluster support  
- [ ] Advanced caching strategies
- [ ] Plugin system
- [ ] GraphQL API

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- [GitHub Repository](https://github.com/xurenlu/sslcat)
- [Documentation](https://sslcat.com/docs)
- [Issue Tracker](https://github.com/xurenlu/sslcat/issues)
- [Releases](https://github.com/xurenlu/sslcat/releases)

---

<div align="center">

**Built with ❤️ using Go**

[⭐ Star us on GitHub](https://github.com/xurenlu/sslcat) • [📖 Read the docs](docs/) • [🐛 Report bugs](https://github.com/xurenlu/sslcat/issues)

</div>
