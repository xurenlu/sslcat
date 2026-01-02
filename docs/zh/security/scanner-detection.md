# 扫描器检测

SSLcat 可以自动检测和封禁常见的漏洞扫描器和安全工具，有效防止恶意扫描和攻击。

## 功能概述

扫描器检测功能通过分析请求的 User-Agent 和其他特征，自动识别常见的漏洞扫描工具和安全扫描器，并可以自动封禁这些工具。

## 支持的扫描器

SSLcat 支持检测以下常见的漏洞扫描器和安全工具：

### 网络扫描工具

- **Nmap** - 网络映射和端口扫描工具
- **Masscan** - 大规模端口扫描工具
- **Zmap** - 快速互联网扫描工具

### 安全扫描平台

- **Shodan** - 互联网连接设备搜索引擎
- **Censys** - 互联网设备搜索引擎
- **LeakIX** - 漏洞搜索和网络分析平台

### Web 应用扫描工具

- **Nikto** - Web 服务器扫描器
- **SQLMap** - SQL 注入检测工具
- **Acunetix** - Web 漏洞扫描器
- **AppScan** - IBM 应用安全扫描器
- **Nessus** - 漏洞扫描器
- **OpenVAS** - 开源漏洞评估系统
- **Qualys** - 云安全扫描平台
- **Burp Suite** - Web 应用安全测试工具
- **OWASP ZAP** - OWASP 安全测试工具
- **Assetnote** - 资产发现和漏洞扫描平台

## 检测机制

### User-Agent 检测

扫描器检测主要通过分析 HTTP 请求的 User-Agent 头来识别扫描工具：

```go
// 扫描器检测规则
scannerRules := []struct {
    name    string
    pattern string
}{
    {"Assetnote Scanner", `(?i)Assetnote`},
    {"Nmap Scanner", `(?i)nmap|Nmap`},
    {"Nikto Scanner", `(?i)nikto|Nikto`},
    {"SQLMap Scanner", `(?i)sqlmap`},
    {"Acunetix Scanner", `(?i)Acunetix|WVS`},
    {"AppScan Scanner", `(?i)AppScan|Rational`},
    {"Nessus Scanner", `(?i)Nessus`},
    {"OpenVAS Scanner", `(?i)OpenVAS`},
    {"Qualys Scanner", `(?i)Qualys`},
    {"Burp Scanner", `(?i)Burp`},
    {"OWASP Scanner", `(?i)OWASP|ZAP`},
    {"Masscan Scanner", `(?i)masscan`},
    {"Zmap Scanner", `(?i)zmap`},
    {"Shodan Scanner", `(?i)Shodan`},
    {"Censys Scanner", `(?i)Censys`},
    {"LeakIX Scanner", `(?i)leakix`},
}
```

### 检测流程

1. **请求分析**：提取请求的 User-Agent 头
2. **模式匹配**：使用正则表达式匹配已知扫描器模式
3. **规则触发**：如果匹配成功，触发 WAF 规则
4. **自动封禁**：根据 WAF 配置，可以自动封禁或记录事件

## 配置说明

### 启用扫描器检测

扫描器检测是 WAF 功能的一部分，需要先启用 WAF：

```json
{
  "security": {
    "enable_waf": true
  }
}
```

### 扫描器检测规则

扫描器检测规则默认启用，会自动检测和阻止扫描工具。规则配置在 WAF 引擎初始化时自动加载。

### 自定义扫描器规则

如果需要添加自定义扫描器检测规则，可以修改 `internal/waf/engine.go` 中的 `scannerRules` 数组：

```go
scannerRules := []struct {
    name    string
    pattern string
}{
    // 添加自定义规则
    {"Custom Scanner", `(?i)custom-scanner`},
}
```

## 使用场景

### 场景 1：防止恶意扫描

攻击者使用 Nmap 扫描服务器端口：

```
请求 User-Agent: Nmap/7.80
→ 检测到 Nmap Scanner
→ 触发 WAF 规则
→ 根据配置自动封禁或记录事件
```

### 场景 2：防止自动化攻击

攻击者使用 SQLMap 进行 SQL 注入测试：

```
请求 User-Agent: sqlmap/1.5.2
→ 检测到 SQLMap Scanner
→ 立即阻止请求
→ 记录安全事件
```

### 场景 3：防止大规模扫描

Shodan、Censys 等平台进行互联网扫描：

```
请求 User-Agent: Shodan
→ 检测到 Shodan Scanner
→ 阻止扫描请求
→ 保护服务器信息泄露
```

## 与其他安全功能的配合

### WAF 频率限制

扫描器检测与 WAF 频率限制配合使用：

1. 扫描器检测识别扫描工具
2. 如果扫描器频繁触发规则，频率限制会自动封禁 IP
3. 形成多层防护

### 多维度封禁

扫描器检测与多维度封禁配合使用：

1. 扫描器检测识别扫描工具
2. 如果使用相同 TLS 指纹，TLS 指纹封禁会阻止所有连接
3. 如果来自同一网段，IP 段封禁会阻止整个网段

### 威胁情报

扫描器检测与威胁情报配合使用：

1. 扫描器检测识别扫描工具
2. 威胁情报验证 IP 是否为已知恶意 IP
3. 综合判断后决定是否封禁

## 日志和监控

### 扫描器检测日志

当检测到扫描器时，会记录日志：

```
WAF检测到扫描器: Nmap Scanner from 192.168.1.100, User-Agent: Nmap/7.80, 动作: block
```

### 查看扫描器事件

可以通过管理面板的安全设置页面查看扫描器检测事件：
- 扫描器类型
- 来源 IP
- 检测时间
- 处理动作

## 最佳实践

### 1. 启用 WAF

确保 WAF 功能已启用，扫描器检测才能正常工作。

### 2. 配置自动封禁

启用 WAF 频率限制，自动封禁频繁扫描的 IP：

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

### 3. 监控扫描活动

定期查看扫描器检测事件，分析攻击模式：
- 哪些扫描器最常用
- 扫描频率如何
- 是否需要调整规则

### 4. 白名单配置

如果某些扫描器是合法的（如内部安全扫描），可以：
- 将 IP 加入白名单
- 为特定域名禁用 WAF
- 调整扫描器检测规则

## 故障排查

### 问题 1：扫描器未被检测

**可能原因：**
- WAF 未启用
- User-Agent 被修改或隐藏
- 扫描器不在支持列表中

**解决方案：**
1. 检查 WAF 是否启用
2. 查看请求日志，确认 User-Agent
3. 添加自定义扫描器规则

### 问题 2：合法扫描被误封

**解决方案：**
1. 将合法扫描 IP 加入白名单
2. 为特定域名禁用 WAF
3. 调整扫描器检测规则，排除合法扫描器

### 问题 3：扫描器绕过检测

**可能原因：**
- 扫描器修改了 User-Agent
- 使用代理隐藏真实 User-Agent

**解决方案：**
1. 启用 TLS 指纹检测
2. 启用 IP 段封禁
3. 结合其他安全功能（威胁情报、频率限制）

## 相关文档

- [WAF 概述](waf-overview.md) - WAF 功能总览
- [WAF 频率限制](waf-rate-limiting.md) - 自动封禁功能
- [WAF 多维度封禁](waf-multi-dim-blocking.md) - 多维度封禁策略
- [封禁管理](blocking-management.md) - 手动封禁管理

## 版本信息

- **引入版本**: v1.3.31-rc18
- **最后更新**: 2025-01-29

