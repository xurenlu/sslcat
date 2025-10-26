# SSLcat Documentation

Welcome to the comprehensive documentation for SSLcat - the enterprise-grade SSL proxy server with automatic certificate management, intelligent domain forwarding, and modern web management interface.

## 📚 Table of Contents

### Part I: Getting Started
- [Introduction](getting-started/introduction.md) - What is SSLcat and why use it?
- [Quick Start](getting-started/quick-start.md) - Get up and running in 5 minutes
- [Architecture](getting-started/architecture.md) - System overview and components
- [Git Deployment Quick Start](getting-started/git-deploy-quickstart.md) - Git deployment quick start guide
- [Installation](installation/) - Installation methods and requirements

### Part II: Configuration
- [Basic Configuration](configuration/basic.md) - Essential settings
- [Advanced Configuration](configuration/advanced.md) - Advanced features
- [Port Configuration Guide](configuration/port-configuration-guide.md) - Port configuration system
- [Ports](configuration/ports.md) - Port configuration options

### Part III: Features
- [v1.3.17 New Features](FEATURES_v1.3.17.md) - v1.3.17 Release Overview ⭐ NEW
- [Monitoring System](features/monitoring.md) - Built-in Monitoring (Goroutine, Memory, Performance) ⭐ NEW
- [SSL Termination](features/ssl-termination.md) - SSL/TLS handling
- [Reverse Proxy](features/reverse-proxy.md) - Proxy functionality
- [Load Balancing](features/load-balancing.md) - Traffic distribution
- [Caching](features/caching.md) - Content caching
- [Compression](features/compression.md) - Response compression
- [WebSocket](features/websocket.md) - WebSocket support
- [HTTP/2](features/http2.md) - HTTP/2 support
- [Distributed Tracing](features/tracing.md) - Tracing support

### Part IV: Development
- [Builder Architecture](development/builder-architecture.md) - Builder architecture documentation
- [Architecture](development/architecture.md) - Development architecture

### Part V: Integration
- [Spring Boot](integration/spring-boot.md) - Java integration

### Part VI: Deployment
- [Docker](deployment/docker.md) - Container deployment
- [Docker Compose](deployment/docker-compose-deploy.md) - Docker Compose deployment

### Part VII: Examples
- [Basic Proxy](examples/basic-proxy.md) - Simple proxy setup

### Part VIII: Troubleshooting
- [Common Issues](troubleshooting/common-issues.md) - Frequent problems
- [CPU Troubleshooting Guide](troubleshooting/CPU_TROUBLESHOOTING_GUIDE.md) - CPU usage troubleshooting
- [Logging and Performance Optimization](troubleshooting/logging.md) - Logging optimization

### Part IX: Development
- [Builder Architecture](development/builder-architecture.md) - Builder architecture documentation
- [Contributing](development/contributing.md) - How to contribute

### Part X: Reference
- [Configuration Reference](reference/configuration-reference.md) - Complete config options
- [API Reference](reference/api-reference.md) - REST API

## 🚀 Quick Navigation

### For New Users
1. Start with [Introduction](getting-started/introduction.md)
2. Follow the [Quick Start](getting-started/quick-start.md) guide
3. Learn about [Basic Configuration](configuration/basic.md)

### For Administrators
1. Review [Administration](administration/) section
2. Check [Deployment](deployment/) guides
3. Learn about [Monitoring](features/monitoring.md)

### For Developers
1. Explore [Integration](integration/) guides
2. Review [API Reference](reference/api-reference.md)
3. Check [Development](development/) section

### For Troubleshooting
1. Check [Common Issues](troubleshooting/common-issues.md)
2. Check [Troubleshooting](troubleshooting/) section

## 📖 Documentation Philosophy

This documentation is designed to be:
- **Comprehensive** - Covering every aspect of SSLcat
- **Progressive** - From beginner to expert level
- **Practical** - Real-world examples and use cases
- **Up-to-date** - Always current with latest features
- **Easy to navigate** - Clear structure and cross-references

## 🔄 Version Information

- **Current Version**: v1.3.17-rc24
- **Documentation Version**: 1.0
- **Last Updated**: 2025

## 🎉 v1.3.17 New Features Highlights

v1.3.17 introduces 5 major new features:

1. **📊 Monitoring System** - Built-in Goroutine, memory, and performance monitoring with 16 Prometheus metrics
2. **☁️ AWS Route53 Support** - Automatic DNS verification for zero-manual SSL certificate issuance
3. **⚡ Smart Config Reload** - 3-level change detection to reduce unnecessary reloads
4. **🔥 Cache Warmup** - Eliminate cold start latency with 35x performance improvement
5. **🎛️ Smart Rate Limiting** - 4 advanced algorithms for precise traffic control

[View Full New Features Documentation](FEATURES_v1.3.17.md)

## 🤝 Contributing to Documentation

We welcome contributions to improve this documentation. Please see our [Contributing Guide](development/contributing.md) for details.

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/xurenlu/sslcat/issues)
- **Discussions**: [Community discussions](https://github.com/xurenlu/sslcat/discussions)
- **Documentation**: This comprehensive guide

---

*This documentation is continuously updated to reflect the latest features and best practices of SSLcat.*