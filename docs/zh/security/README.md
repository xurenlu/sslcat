# SSLcat 安全功能

欢迎来到 SSLcat 安全功能文档。SSLcat 提供了全面的安全防护功能，包括 Web 应用防火墙（WAF）、多维度封禁、威胁检测等。

## 📚 文档导航

### 核心功能

- **[WAF 概述](waf-overview.md)** - Web 应用防火墙功能总览
- **[WAF 多维度封禁](waf-multi-dim-blocking.md)** - IP、TLS 指纹、IP 段多维度封禁策略
- **[WAF 频率限制](waf-rate-limiting.md)** - 基于触发频率的自动封禁功能

### 管理功能

- **[封禁管理](blocking-management.md)** - IP 和 User-Agent 封禁管理（CLI、Web 界面、API）
- **[威胁检测](threat-detection.md)** - 威胁情报和机器人检测
- **[扫描器检测](scanner-detection.md)** - 漏洞扫描器自动检测和封禁

## 🚀 快速开始

### 1. 启用 WAF

在配置文件中启用 WAF：

```json
{
  "security": {
    "enable_waf": true
  }
}
```

### 2. 配置频率限制

启用自动封禁功能：

```json
{
  "security": {
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 60,
    "waf_rate_limit_max_hits": 10,
    "waf_rate_limit_block_sec": 3600
  }
}
```

### 3. 手动封禁 IP

使用 CLI 命令：

```bash
sslcat block ip 192.168.1.100 -duration 24h -reason "恶意扫描"
```

## 🛡️ 安全功能列表

### Web 应用防火墙 (WAF)

- ✅ SQL 注入检测
- ✅ XSS 攻击检测
- ✅ 敏感文件访问检测
- ✅ 恶意 User-Agent 检测
- ✅ 路径遍历检测
- ✅ 命令注入检测
- ✅ 扫描器检测（Nmap、Masscan、Shodan、Censys、LeakIX 等）

### 封禁管理

- ✅ IP 地址封禁（手动/自动）
- ✅ User-Agent 封禁
- ✅ TLS 指纹封禁
- ✅ IP 段封禁
- ✅ 临时封禁和永久封禁
- ✅ 封禁列表查看和管理

### 威胁检测

- ✅ 威胁情报集成
- ✅ 机器人检测
- ✅ 可疑行为检测
- ✅ 自动化攻击识别

## 📖 功能详解

### WAF 多维度封禁

WAF 多维度封禁策略可以从多个维度自动检测和封禁恶意攻击者：

- **IP 地址封禁**：封禁单个恶意 IP
- **TLS 指纹封禁**：封禁使用相同工具/脚本的所有连接
- **IP 段封禁**：当同一网段内多个 IP 被封禁时，自动封禁整个网段

[查看详细文档](waf-multi-dim-blocking.md)

### WAF 频率限制

WAF 频率限制功能可以自动检测和封禁频繁触发 WAF 规则的 IP 地址：

- 自动记录触发事件
- 统计时间窗口内的触发次数
- 达到阈值时自动封禁
- 临时封禁，到期自动解除

[查看详细文档](waf-rate-limiting.md)

### 封禁管理

封禁管理功能提供了多种方式来管理 IP 和 User-Agent 的封禁：

- **CLI 命令**：`block`、`unblock`、`blocked`
- **Web 界面**：管理面板中的安全设置
- **API 接口**：RESTful API 支持

[查看详细文档](blocking-management.md)

### 扫描器检测

SSLcat 可以自动检测和封禁常见的漏洞扫描器：

- Nmap
- Masscan
- Shodan
- Censys
- LeakIX
- 以及其他常见扫描工具

[查看详细文档](scanner-detection.md)

## 🔧 配置指南

### 生产环境推荐配置

```json
{
  "security": {
    "enable_waf": true,
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 60,
    "waf_rate_limit_max_hits": 10,
    "waf_rate_limit_block_sec": 3600,
    "waf_tls_block_enabled": true,
    "waf_tls_block_window": 60,
    "waf_tls_block_max_hits": 10,
    "waf_tls_block_duration_sec": 3600,
    "waf_subnet_block_enabled": true,
    "waf_subnet_mask": 24,
    "waf_subnet_threshold": 3,
    "waf_subnet_block_duration_sec": 7200
  }
}
```

### 测试环境推荐配置

```json
{
  "security": {
    "enable_waf": true,
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 120,
    "waf_rate_limit_max_hits": 20,
    "waf_rate_limit_block_sec": 1800
  }
}
```

## 📊 监控和日志

### 查看封禁列表

使用 CLI 命令：

```bash
sslcat blocked
```

### 查看 WAF 统计

访问管理面板的安全设置页面，查看：
- 总拦截数
- 事件总数
- 规则总数
- 检测率

### 日志分析

WAF 事件会记录在日志中：

```bash
# 查看 WAF 日志
sudo journalctl -u sslcat | grep "WAF检测"
```

## 🔗 相关文档

- [CLI 命令参考](../administration/cli-commands.md) - 包含封禁管理命令
- [配置参考](../reference/configuration-reference.md) - 完整配置选项
- [故障排查](../troubleshooting/common-issues.md) - 常见问题解决

## 📝 版本信息

- **当前版本**: v1.3.31-rc18+
- **文档版本**: 1.0
- **最后更新**: 2025-01-29

---

*本文档持续更新，以反映 SSLcat 的最新安全功能和最佳实践。*

