# SSLcat 文档

欢迎来到 SSLcat 的完整文档 - 企业级 SSL 代理服务器，具有自动证书管理、智能域名转发和现代 Web 管理界面。

## 📚 目录

### 第一部分：快速开始
- [介绍](getting-started/introduction.md) - 什么是 SSLcat 以及为什么使用它？
- [快速开始](getting-started/quick-start.md) - 5分钟内启动运行
- [架构](getting-started/architecture.md) - 系统概览和组件
- [Git部署快速开始](getting-started/git-deploy-quickstart.md) - Git部署快速开始指南
- [压缩缓存快速开始](getting-started/QUICK_START_COMPRESSION_CACHE.md) - 压缩缓存快速开始
- [安装](installation/) - 安装方法和要求

### 第二部分：配置
- [基础配置](configuration/basic.md) - 基本设置
- [端口配置指南](configuration/port-configuration-guide.md) - 端口配置系统
- [端口配置设计](configuration/port-configuration-design.md) - 端口配置设计文档

### 第三部分：功能特性
- [v1.3.17 新特性](FEATURES_v1.3.17.md) - v1.3.17 版本新特性总览 ⭐ NEW
- [监控系统](features/monitoring.md) - 内置监控系统（Goroutine、内存、性能）⭐ NEW
- [压缩缓存指南](features/COMPRESSION_CACHE_GUIDE.md) - 压缩和缓存功能
- [HTTP/2实现](features/HTTP2_IMPLEMENTATION.md) - HTTP/2支持实现
- [HTTP/2支持分析](features/HTTP2_SUPPORT_ANALYSIS.md) - HTTP/2支持分析
- [Git部署WebUI功能](features/git-deploy-webui-features.md) - Git部署Web界面功能
- [实时日志功能](features/realtime-logs-feature.md) - 实时日志功能
- [WebSocket重连去重](features/websocket-reconnection-deduplication.md) - WebSocket重连去重
- [分布式追踪](features/tracing.md) - 追踪支持

### 第四部分：开发
- [Builder架构](development/builder-architecture.md) - Builder架构文档
- [Git部署SSH实现](development/git-deploy-ssh-implementation.md) - Git部署SSH实现
- [Git部署SSH计划](development/git-deploy-ssh-plan.md) - Git部署SSH计划
- [静态构建器Nginx](development/static-builder-nginx.md) - 静态构建器Nginx
- [贡献指南](development/contributing.md) - 开发贡献指南

### 第五部分：集成
- [Spring Boot](integration/spring-boot.md) - Java 集成

### 第六部分：部署
- [Docker](deployment/docker.md) - 容器部署
- [Docker Compose](deployment/docker-compose-deploy.md) - Docker Compose 部署

### 第七部分：示例
- [基础代理](examples/basic-proxy.md) - 简单代理设置

### 第八部分：故障排除
- [常见问题](troubleshooting/common-issues.md) - 常见问题
- [内存峰值修复](troubleshooting/memory-spike-fix.md) - 内存问题修复
- [pprof 使用指南](troubleshooting/pprof-usage.md) - 性能分析工具
- [内存泄漏调试](troubleshooting/debug-memory-leak-with-pprof.md) - 内存泄漏排查
- [journalctl 日志策略](troubleshooting/journalctl-logging-strategy.md) - 日志记录策略
- [CPU故障排查指南](troubleshooting/CPU_TROUBLESHOOTING_GUIDE.md) - CPU占用问题排查
- [日志和性能优化](troubleshooting/LOGGING_AND_PERFORMANCE_OPTIMIZATION.md) - 日志和性能优化

### 第九部分：开发
- [Builder架构](development/builder-architecture.md) - Builder架构文档
- [Git部署SSH实现](development/git-deploy-ssh-implementation.md) - Git部署SSH实现
- [静态构建器Nginx](development/static-builder-nginx.md) - 静态构建器Nginx
- [贡献指南](development/contributing.md) - 开发贡献指南

### 第十部分：参考
- [配置参考](reference/configuration-reference.md) - 完整配置选项

## 🚀 快速导航

### 新用户
1. 从[介绍](getting-started/introduction.md)开始
2. 按照[快速开始](getting-started/quick-start.md)指南
3. 学习[基础配置](configuration/basic.md)

### 管理员
1. 查看[管理](administration/)部分
2. 检查[部署](deployment/)指南
3. 了解[监控](features/monitoring.md)

### 开发者
1. 探索[集成](integration/)指南
2. 查看[配置参考](reference/configuration-reference.md)
3. 检查[开发](development/)部分

### 故障排除
1. 查看[常见问题](troubleshooting/common-issues.md)
2. 参考故障排除指南
3. 查看[故障排除](troubleshooting/)部分

## 📖 文档理念

本文档设计为：
- **全面** - 涵盖 SSLcat 的每个方面
- **渐进式** - 从初学者到专家级别
- **实用** - 真实世界的示例和用例
- **最新** - 始终与最新功能保持同步
- **易于导航** - 清晰的结构和交叉引用

## 🔄 版本信息

- **当前版本**: v1.3.17-rc24
- **文档版本**: 1.0
- **最后更新**: 2025

## 🎉 v1.3.17 新特性亮点

v1.3.17 版本引入了5个重大新特性：

1. **📊 监控系统** - 内置 Goroutine、内存、性能监控，16个 Prometheus 指标
2. **☁️ AWS Route53 支持** - 自动 DNS 验证，零手动操作 SSL 证书申请
3. **⚡ 智能配置重载** - 3级变更检测，减少不必要的重载
4. **🔥 缓存预热** - 消除冷启动延迟，性能提升 35倍
5. **🎛️ 智能限流** - 4种先进算法，精确流量控制

[查看完整新特性文档](FEATURES_v1.3.17.md)

## 🤝 贡献文档

我们欢迎对改进本文档的贡献。请查看我们的[贡献指南](development/contributing.md)了解详情。

## 📞 支持

- **GitHub Issues**: [报告错误或请求功能](https://github.com/xurenlu/sslcat/issues)
- **讨论**: [社区讨论](https://github.com/xurenlu/sslcat/discussions)
- **文档**: 这份综合指南

---

*本文档持续更新，以反映 SSLcat 的最新功能和最佳实践。*