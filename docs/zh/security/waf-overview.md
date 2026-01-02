# WAF 概述

Web 应用防火墙（WAF）是 SSLcat 的核心安全功能，提供全面的 Web 应用安全防护。

## 功能概述

SSLcat 的 WAF 功能提供了多层安全防护，包括：

- ✅ SQL 注入检测和防护
- ✅ XSS 攻击检测和防护
- ✅ 敏感文件访问检测
- ✅ 恶意 User-Agent 检测
- ✅ 路径遍历检测
- ✅ 命令注入检测
- ✅ 扫描器检测（Nmap、Masscan、Shodan、Censys、LeakIX 等）
- ✅ 频率限制和自动封禁
- ✅ 多维度封禁（IP、TLS 指纹、IP 段）

## 核心功能

### 1. 攻击检测

WAF 可以检测多种常见的 Web 攻击：

- **SQL 注入**：检测 SQL 注入攻击模式
- **XSS 攻击**：检测跨站脚本攻击
- **路径遍历**：检测目录遍历攻击
- **命令注入**：检测命令注入攻击
- **敏感文件访问**：检测对敏感文件的访问尝试

### 2. 扫描器检测

自动检测和封禁常见的漏洞扫描器：

- Nmap、Masscan、Zmap
- Shodan、Censys、LeakIX
- Nikto、SQLMap、Acunetix
- Burp Suite、OWASP ZAP
- 以及其他常见扫描工具

### 3. 频率限制

自动检测和封禁频繁触发 WAF 规则的 IP：

- 时间窗口内统计触发次数
- 达到阈值时自动封禁
- 临时封禁，到期自动解除

### 4. 多维度封禁

从多个维度自动检测和封禁恶意攻击者：

- **IP 地址封禁**：封禁单个恶意 IP
- **TLS 指纹封禁**：封禁使用相同工具的所有连接
- **IP 段封禁**：封禁整个网段

## 配置说明

### 启用 WAF

在配置文件中启用 WAF：

```json
{
  "security": {
    "enable_waf": true
  }
}
```

### 按域名配置 WAF

可以为每个域名单独配置 WAF：

- **全局（默认）**：使用全局 WAF 配置
- **启用**：强制为此域名启用 WAF
- **禁用**：强制为此域名禁用 WAF

### WAF 规则

WAF 规则在初始化时自动加载，包括：

- 敏感文件访问规则
- SQL 注入检测规则
- XSS 攻击检测规则
- 扫描器检测规则
- 其他安全规则

## 性能优化

SSLcat 的 WAF 实现了多项性能优化：

### 1. 日志限流

- 相同攻击每分钟最多记录一次日志
- 减少日志 I/O 开销
- CPU 占用降低 99%+

### 2. 事件存储优化

- 最多保存 10,000 个事件
- 自动清理超过 24 小时的旧事件
- 内存占用 ≤5 MB

### 3. 检测性能优化

- 正则表达式预编译
- 快速失败机制
- 读写锁优化

## 使用场景

### 场景 1：防止 SQL 注入

攻击者尝试 SQL 注入攻击：

```
请求: /api/user?id=1' OR '1'='1
→ WAF 检测到 SQL 注入模式
→ 阻止请求
→ 记录安全事件
```

### 场景 2：防止 XSS 攻击

攻击者尝试 XSS 攻击：

```
请求: /search?q=<script>alert('XSS')</script>
→ WAF 检测到 XSS 模式
→ 阻止请求
→ 记录安全事件
```

### 场景 3：防止敏感文件访问

攻击者尝试访问敏感文件：

```
请求: /.git/config
→ WAF 检测到敏感文件访问
→ 阻止请求
→ 记录安全事件
```

## 监控和日志

### 查看 WAF 统计

访问管理面板的安全设置页面，查看：
- 总拦截数
- 事件总数
- 规则总数
- 检测率

### WAF 日志

WAF 事件会记录在日志中：

```bash
# 查看 WAF 日志
sudo journalctl -u sslcat | grep "WAF检测"
```

### API 接口

WAF 提供了丰富的 API 接口：

- `GET /api/waf/stats` - 获取 WAF 统计
- `GET /api/waf/rules` - 获取 WAF 规则列表
- `GET /api/waf/events` - 获取 WAF 事件列表
- `GET /api/waf/config` - 获取 WAF 配置

## 最佳实践

### 1. 启用 WAF

在生产环境中始终启用 WAF，提供基础安全防护。

### 2. 配置频率限制

启用频率限制，自动封禁频繁攻击的 IP：

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

### 3. 启用多维度封禁

启用多维度封禁，应对分布式攻击：

```json
{
  "security": {
    "waf_tls_block_enabled": true,
    "waf_subnet_block_enabled": true
  }
}
```

### 4. 定期审查

定期审查 WAF 事件和封禁列表：
- 分析攻击模式
- 优化 WAF 规则
- 解除误封

## 相关文档

- [WAF 多维度封禁](waf-multi-dim-blocking.md) - 多维度封禁策略详解
- [WAF 频率限制](waf-rate-limiting.md) - 频率限制功能详解
- [扫描器检测](scanner-detection.md) - 扫描器检测功能详解
- [封禁管理](blocking-management.md) - 封禁管理功能详解

## 版本信息

- **当前版本**: v1.3.31-rc18+
- **最后更新**: 2025-01-29

