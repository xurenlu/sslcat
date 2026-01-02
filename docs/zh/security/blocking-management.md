# 封禁管理

SSLcat 提供了全面的封禁管理功能，支持通过 CLI 命令、Web 界面和 API 接口来管理 IP 地址、User-Agent 和 TLS 指纹的封禁。

## 功能概述

封禁管理功能支持以下封禁维度：

1. **IP 地址封禁** - 封禁单个 IP 地址
2. **User-Agent 封禁** - 封禁特定的 User-Agent
3. **TLS 指纹封禁** - 封禁使用相同 TLS 指纹的所有连接（通过 WAF 多维度封禁）

## 封禁类型

### 临时封禁

临时封禁会在指定时间后自动解除，支持的时间格式：
- `1h` - 1 小时
- `24h` - 24 小时
- `7d` - 7 天
- `30d` - 30 天

### 永久封禁

设置封禁时长为 `0` 或使用 `-duration 0` 表示永久封禁，直到手动解除。

## CLI 命令

### 封禁 IP 或 User-Agent

```bash
# 封禁 IP（默认 24 小时）
sslcat block ip 192.168.1.100

# 封禁 IP，指定时长
sslcat block ip 192.168.1.100 -duration 1h
sslcat block ip 192.168.1.100 -duration 7d
sslcat block ip 192.168.1.100 -duration 0  # 永久封禁

# 封禁 IP，指定原因
sslcat block ip 192.168.1.100 -reason "恶意扫描"

# 封禁 User-Agent
sslcat block user-agent "bad-bot/1.0" -duration 24h -reason "恶意爬虫"

# 也可以使用 ua 作为 user-agent 的简写
sslcat block ua "bad-bot/1.0" -duration 24h
```

**参数说明：**
- `ip <ip>` - 要封禁的 IP 地址
- `user-agent <ua>` 或 `ua <ua>` - 要封禁的 User-Agent
- `-duration <duration>` - 封禁时长：`1h`、`24h`、`7d`、`0`（永久）
- `-reason <reason>` - 封禁原因（可选）

### 解封 IP 或 User-Agent

```bash
# 解封 IP
sslcat unblock ip 192.168.1.100

# 解封 User-Agent
sslcat unblock user-agent "bad-bot/1.0"

# 也可以使用 ua 作为 user-agent 的简写
sslcat unblock ua "bad-bot/1.0"
```

### 查看封禁列表

```bash
# 查看所有被封禁的 IP 和 User-Agent
sslcat blocked
```

**输出示例：**
```
Blocked IPs:
============
  IP: 192.168.1.100
    Reason: 恶意扫描
    Blocked at: 2025-01-29 10:30:00
    Expires at: 2025-01-30 10:30:00

  IP: 10.0.0.50
    Reason: Manual block via CLI
    Blocked at: 2025-01-29 09:15:00
    Expires at: 2025-01-30 09:15:00

Blocked User-Agents:
====================
  User-Agent: bad-bot/1.0
    Reason: 恶意爬虫
    Blocked at: 2025-01-29 09:15:00
    Expires at: 2025-01-30 09:15:00
```

## Web 界面

### 访问封禁管理

1. 登录 SSLcat 管理面板
2. 导航到 **安全设置** → **封禁管理**
3. 查看当前封禁列表

### 手动封禁

1. 在封禁管理页面，点击 **添加封禁**
2. 选择封禁类型：
   - **IP 地址**
   - **User-Agent**
   - **TLS 指纹**（需要 WAF 多维度封禁功能）
3. 输入要封禁的值
4. 设置封禁时长（或选择永久封禁）
5. 输入封禁原因（可选）
6. 点击 **确认封禁**

### 解除封禁

1. 在封禁列表中，找到要解除的封禁项
2. 点击 **解除封禁** 按钮
3. 确认操作

## API 接口

### 1. 获取封禁列表

**请求**：
```http
GET /sslcat-panel/api/security/blocked-list
```

**响应示例**：
```json
{
  "success": true,
  "data": {
    "ips": [
      {
        "ip": "192.168.1.100",
        "reason": "恶意扫描",
        "block_time": "2025-01-29T10:30:00Z",
        "expire_time": "2025-01-30T10:30:00Z"
      }
    ],
    "user_agents": [
      {
        "user_agent": "bad-bot/1.0",
        "reason": "恶意爬虫",
        "block_time": "2025-01-29T09:15:00Z",
        "expire_time": "2025-01-30T09:15:00Z"
      }
    ]
  }
}
```

### 2. 封禁 IP 或 User-Agent

**请求**：
```http
POST /sslcat-panel/api/security/block
Content-Type: application/json

{
  "type": "ip",
  "value": "192.168.1.100",
  "duration": 86400,
  "reason": "恶意扫描"
}
```

**参数说明：**
- `type` - 封禁类型：`ip`、`user_agent`、`tls_fingerprint`
- `value` - 要封禁的值（IP 地址、User-Agent 或 TLS 指纹）
- `duration` - 封禁时长（秒），`0` 表示永久封禁
- `reason` - 封禁原因（可选）

**响应示例**：
```json
{
  "success": true,
  "message": "IP 192.168.1.100 blocked successfully",
  "data": {
    "type": "ip",
    "value": "192.168.1.100",
    "duration": 86400,
    "reason": "恶意扫描",
    "blocked_at": "2025-01-29 10:30:00"
  }
}
```

### 3. 解除封禁

**请求**：
```http
POST /sslcat-panel/api/security/unblock
Content-Type: application/json

{
  "type": "ip",
  "value": "192.168.1.100"
}
```

**参数说明：**
- `type` - 封禁类型：`ip`、`user_agent`、`tls_fingerprint`
- `value` - 要解除封禁的值

**响应示例**：
```json
{
  "success": true,
  "message": "Successfully unblocked ip: 192.168.1.100"
}
```

## 封禁维度说明

### IP 地址封禁

IP 地址封禁会阻止来自指定 IP 的所有请求。封禁会同时应用到：
- Security Manager（基础安全模块）
- WAF 多维度封禁（如果启用）

**使用场景：**
- 已知恶意 IP
- 频繁攻击的 IP
- 需要临时阻止的 IP

### User-Agent 封禁

User-Agent 封禁会阻止使用指定 User-Agent 的所有请求。

**使用场景：**
- 恶意爬虫
- 扫描工具
- 自动化攻击工具

### TLS 指纹封禁

TLS 指纹封禁会阻止使用相同 TLS 指纹的所有连接，无论来自哪个 IP。这需要启用 WAF 多维度封禁功能。

**使用场景：**
- 分布式攻击（使用相同工具）
- 自动化攻击脚本
- 绕过 IP 封禁的攻击者

## 最佳实践

### 1. 合理设置封禁时长

- **临时封禁**：用于可疑行为，建议 1-24 小时
- **长期封禁**：用于确认的恶意行为，建议 7-30 天
- **永久封禁**：仅用于确认的恶意 IP 或工具

### 2. 记录封禁原因

始终记录封禁原因，便于后续分析和审计：
- 恶意扫描
- SQL 注入尝试
- 暴力破解
- 恶意爬虫

### 3. 定期审查封禁列表

定期检查封禁列表：
- 确认封禁是否仍然有效
- 解除误封的 IP
- 分析攻击模式

### 4. 配合自动封禁使用

手动封禁应与自动封禁（WAF 频率限制、多维度封禁）配合使用：
- 自动封禁处理常见攻击
- 手动封禁处理特殊情况
- 两者结合提供全面防护

## 故障排查

### 问题 1：封禁未生效

**可能原因：**
- 配置未保存
- 服务未重启
- IP 地址格式错误

**解决方案：**
1. 检查配置是否正确保存
2. 重启 SSLcat 服务
3. 验证 IP 地址格式（IPv4 或 IPv6）

### 问题 2：正常用户被误封

**解决方案：**
1. 立即解除封禁：`sslcat unblock ip <ip>`
2. 检查封禁原因
3. 将 IP 加入白名单（如果支持）
4. 调整自动封禁阈值

### 问题 3：封禁列表过长

**解决方案：**
1. 定期清理过期封禁
2. 合并相同类型的封禁
3. 使用 IP 段封禁代替单个 IP 封禁（如果适用）

## 相关文档

- [CLI 命令参考](../administration/cli-commands.md) - 完整的 CLI 命令文档
- [WAF 多维度封禁](waf-multi-dim-blocking.md) - TLS 指纹和 IP 段封禁
- [WAF 频率限制](waf-rate-limiting.md) - 自动封禁功能
- [扫描器检测](scanner-detection.md) - 自动检测和封禁扫描器

## 版本信息

- **引入版本**: v1.3.31-rc18
- **最后更新**: 2025-01-29

