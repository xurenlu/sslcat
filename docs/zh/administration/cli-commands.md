# CLI 命令参考

SSLcat 提供了完整的命令行界面（CLI），用于在服务器上直接管理和配置 SSLcat。即使 Web 界面无法访问，管理员也可以通过 CLI 命令完成所有配置管理任务，无需手动编辑配置文件。

## 重要说明

⚠️ **所有 CLI 命令都需要在服务器上以 root 权限运行**（SSLcat 需要 root 权限绑定特权端口）。

## 基本用法

### 命令格式

```bash
sslcat <command> [subcommand] [options]
```

### 配置文件

所有 CLI 命令默认使用 `sslcat.conf` 作为配置文件。如果需要指定不同的配置文件，使用 `-config` 参数：

```bash
sslcat -config /path/to/sslcat.conf <command>
```

## 可用命令

### 1. 配置管理 (`config`)

配置管理命令用于查看、获取和设置配置项。

#### 显示完整配置

```bash
# 显示完整的 JSON 格式配置
sslcat config show

# 使用自定义配置文件
sslcat -config /etc/sslcat/sslcat.conf config show
```

**示例输出：**
```json
{
  "server": {
    "port": 443,
    "host": "0.0.0.0",
    ...
  },
  "ssl": {
    "email": "admin@example.com",
    ...
  },
  ...
}
```

#### 获取配置项

```bash
# 获取服务器端口
sslcat config get server.port

# 获取 SSL 邮箱
sslcat config get ssl.email

# 获取代理规则数量（需要先查看结构）
sslcat config get proxy.rules
```

**使用点号（.）分隔的路径访问嵌套配置项**，例如：
- `server.port` - 服务器端口
- `ssl.email` - SSL 证书邮箱
- `ssl.staging` - 是否使用 Let's Encrypt 测试环境
- `proxy.cache.enabled` - 是否启用代理缓存

#### 设置配置项

```bash
# 设置服务器端口
sslcat config set server.port 8080

# 设置 SSL 邮箱
sslcat config set ssl.email admin@example.com

# 启用 SSL 测试环境
sslcat config set ssl.staging true

# 禁用 SSL 测试环境
sslcat config set ssl.staging false
```

**注意事项：**
- 配置修改会立即保存到配置文件
- 修改配置后需要重启 SSLcat 服务才能生效
- 使用点号（.）分隔的路径访问嵌套配置项
- 支持的类型：字符串、整数、布尔值、浮点数

---

### 2. 代理管理 (`proxy`)

代理管理命令用于管理反向代理规则。

#### 列出所有代理规则

```bash
sslcat proxy list
```

**示例输出：**
```
Proxy Rules:
============
1. Domain: api.example.com
   Target: localhost:8080
   Enabled: true
   SSL Only: false

2. Domain: app.example.com
   Target: localhost:3000
   Enabled: true
   SSL Only: true
```

#### 添加代理规则

```bash
# 基本用法：添加一个代理规则
sslcat proxy add -domain example.com -target localhost -port 8080

# 启用 SSL 强制
sslcat proxy add -domain example.com -target localhost -port 8080 -ssl

# 添加时禁用规则
sslcat proxy add -domain example.com -target localhost -port 8080 -disabled

# 完整示例
sslcat proxy add -domain api.example.com -target localhost -port 3000 -ssl -enabled
```

**参数说明：**
- `-domain <domain>` - **必需**，域名（例如：`example.com`）
- `-target <target>` - **必需**，目标服务器地址（例如：`localhost` 或 `192.168.1.100`）
- `-port <port>` - **可选**，目标端口（默认：`80`）
- `-ssl` - **可选**，强制 HTTPS（SSL Only）
- `-enabled` - **可选**，启用规则（默认：启用）
- `-disabled` - **可选**，禁用规则

**注意事项：**
- 域名不能重复，如果已存在会报错
- 规则添加后会自动保存到配置文件
- 添加规则后需要重启 SSLcat 服务才能生效

#### 更新代理规则

```bash
# 更新目标地址
sslcat proxy update -domain example.com -target localhost -port 3000

# 更新端口
sslcat proxy update -domain example.com -port 8080

# 启用 SSL 强制
sslcat proxy update -domain example.com -ssl

# 禁用 SSL 强制
sslcat proxy update -domain example.com -no-ssl

# 禁用规则
sslcat proxy update -domain example.com -disabled

# 启用规则
sslcat proxy update -domain example.com -enabled
```

**参数说明：**
- `-domain <domain>` - **必需**，要更新的域名
- `-target <target>` - **可选**，新的目标地址
- `-port <port>` - **可选**，新的目标端口
- `-ssl` - **可选**，启用 SSL 强制
- `-no-ssl` - **可选**，禁用 SSL 强制
- `-enabled` - **可选**，启用规则
- `-disabled` - **可选**，禁用规则

**注意事项：**
- 只更新指定的字段，未指定的字段保持不变
- 更新后会自动保存到配置文件
- 更新规则后需要重启 SSLcat 服务才能生效

#### 删除代理规则

```bash
# 删除指定域名的代理规则
sslcat proxy delete -domain example.com
```

**注意事项：**
- 删除操作不可恢复，请谨慎操作
- 删除后会自动保存到配置文件
- 删除规则后需要重启 SSLcat 服务才能生效

---

### 3. SSL 证书管理 (`ssl`)

SSL 证书管理命令用于管理 SSL 证书。**注意：当前版本的部分 SSL 命令功能为占位符实现，完整功能正在开发中。**

#### 列出证书

```bash
sslcat ssl list
```

**当前实现：** 显示配置中启用的代理规则域名列表。

#### 显示证书详情

```bash
sslcat ssl show -domain example.com
```

**当前实现：** 占位符，显示提示信息。

#### 申请证书

```bash
# 使用配置文件中的邮箱
sslcat ssl request -domain example.com

# 指定邮箱
sslcat ssl request -domain example.com -email admin@example.com
```

**参数说明：**
- `-domain <domain>` - **必需**，要申请证书的域名
- `-email <email>` - **可选**，Let's Encrypt 邮箱（如果未指定，使用配置文件中的 `ssl.email`）

**当前实现：** 占位符，显示提示信息。

#### 续期证书

```bash
sslcat ssl renew -domain example.com
```

**当前实现：** 占位符，显示提示信息。

#### 删除证书

```bash
sslcat ssl delete -domain example.com
```

**当前实现：** 占位符，显示提示信息。

---

### 4. 封禁管理 (`block`)

封禁管理命令用于手动封禁和解封 IP 地址或 User-Agent。

#### 封禁 IP 或 User-Agent

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
- `-duration <duration>` - 封禁时长：`1h`（1小时）、`24h`（24小时）、`7d`（7天）、`0`（永久）
- `-reason <reason>` - 封禁原因（可选）

**注意事项：**
- 封禁操作会立即生效
- IP 封禁会同时应用到 Security Manager 和 WAF
- User-Agent 封禁会应用到 Security Manager

#### 解封 IP 或 User-Agent

```bash
# 解封 IP
sslcat unblock ip 192.168.1.100

# 解封 User-Agent
sslcat unblock user-agent "bad-bot/1.0"

# 也可以使用 ua 作为 user-agent 的简写
sslcat unblock ua "bad-bot/1.0"
```

**注意事项：**
- 解封操作会立即生效
- 解封 IP 会同时解除 Security Manager 和 WAF 的封禁
- 解封 User-Agent 会解除 Security Manager 的封禁

#### 查看封禁列表

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

Blocked User-Agents:
====================
  User-Agent: bad-bot/1.0
    Reason: 恶意爬虫
    Blocked at: 2025-01-29 09:15:00
    Expires at: 2025-01-30 09:15:00
```

**相关文档：**
- [封禁管理](../security/blocking-management.md) - 完整的封禁管理文档
- [WAF 多维度封禁](../security/waf-multi-dim-blocking.md) - WAF 多维度封禁功能

---

### 5. 帮助命令 (`help`)

显示所有可用命令的帮助信息。

```bash
sslcat help
```

**输出示例：**
```
SSLcat CLI Commands:

  config          Configuration management
  proxy           Proxy management
  ssl             SSL certificate management
  help            Show help information

Use 'sslcat <command> --help' for detailed help
```

---

## 启动参数

除了 CLI 子命令，SSLcat 还支持以下启动参数：

### 基本参数

```bash
# 指定配置文件
sslcat -config /path/to/sslcat.conf

# 指定管理面板路径前缀
sslcat -admin-prefix /sslcat-panel

# 指定监听地址和端口
sslcat -host 0.0.0.0 -port 443

# 指定 SSL 邮箱
sslcat -email admin@example.com

# 使用 Let's Encrypt 测试环境
sslcat -staging

# 指定日志级别
sslcat -log-level debug
```

### 配置验证

```bash
# 测试配置文件语法
sslcat -config sslcat.conf -test

# 检查配置文件完整性
sslcat -config sslcat.conf -check

# 显示版本信息
sslcat -version
```

**完整参数列表：**
- `-config` - 配置文件路径（默认：`/etc/sslcat/sslcat.conf`）
- `-admin-prefix` - 管理面板路径前缀（默认：`/sslcat-panel`）
- `-host` - 监听地址（默认：`0.0.0.0`）
- `-port` - 监听端口（默认：`443`）
- `-email` - SSL 证书邮箱
- `-staging` - 使用 Let's Encrypt 测试环境
- `-log-level` - 日志级别：`debug`, `info`, `warn`, `error`（默认：`info`）
- `-test` - 测试配置文件语法
- `-check` - 检查配置文件完整性
- `-version` - 显示版本信息

---

## 使用示例

### 完整工作流程示例

```bash
# 1. 查看当前配置
sslcat config show

# 2. 添加代理规则
sslcat proxy add -domain api.example.com -target localhost -port 3000 -ssl

# 3. 查看代理规则列表
sslcat proxy list

# 4. 设置 SSL 邮箱
sslcat config set ssl.email admin@example.com

# 5. 申请 SSL 证书（占位符）
sslcat ssl request -domain api.example.com

# 6. 查看配置项
sslcat config get ssl.email

# 7. 更新代理规则
sslcat proxy update -domain api.example.com -port 8080

# 8. 删除代理规则
sslcat proxy delete -domain api.example.com
```

### 批量操作示例

```bash
# 批量添加多个代理规则
for domain in api.example.com app.example.com www.example.com; do
    sslcat proxy add -domain $domain -target localhost -port 8080 -ssl
done

# 批量更新代理规则端口
for domain in api.example.com app.example.com; do
    sslcat proxy update -domain $domain -port 3000
done
```

### 配置管理示例

```bash
# 查看服务器配置
sslcat config get server.port
sslcat config get server.host

# 修改服务器端口
sslcat config set server.port 8443

# 查看 SSL 配置
sslcat config get ssl.email
sslcat config get ssl.staging

# 修改 SSL 配置
sslcat config set ssl.email newadmin@example.com
sslcat config set ssl.staging false
```

---

## 配置文件格式

CLI 命令操作的是 JSON 格式的配置文件。配置文件的基本结构：

```json
{
  "server": {
    "port": 443,
    "host": "0.0.0.0"
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "localhost",
        "port": 8080,
        "enabled": true,
        "ssl_only": false
      }
    ]
  }
}
```

使用 `config get` 和 `config set` 命令时，使用点号（.）分隔的路径访问嵌套字段。

---

## 最佳实践

### 1. 备份配置文件

在修改配置之前，建议先备份配置文件：

```bash
cp /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.backup
```

### 2. 测试配置

修改配置后，使用 `-test` 参数验证配置：

```bash
sslcat -config /etc/sslcat/sslcat.conf -test
```

### 3. 重启服务

配置修改后，需要重启 SSLcat 服务才能生效：

```bash
# 如果使用 systemd
sudo systemctl restart sslcat

# 如果使用其他方式
# 停止当前进程，然后重新启动
```

### 4. 查看日志

修改配置后，查看日志确认配置是否正确加载：

```bash
# 如果使用 systemd
sudo journalctl -u sslcat -f

# 或查看日志文件
tail -f /var/log/sslcat/sslcat.log
```

---

## 故障排查

### 命令无法执行

**问题：** 运行 `sslcat` 命令提示找不到命令或权限不足

**解决方案：**
1. 确保 SSLcat 已正确安装
2. 确保命令路径在 PATH 中，或使用完整路径
3. 确保以 root 权限运行（SSLcat 需要 root 权限）

### 配置文件无法读取

**问题：** 提示配置文件不存在或无法读取

**解决方案：**
1. 检查配置文件路径是否正确
2. 使用 `-config` 参数指定完整路径
3. 确保配置文件有读取权限

### 配置无法保存

**问题：** 修改配置后提示保存失败

**解决方案：**
1. 确保配置文件有写入权限
2. 确保配置文件路径正确
3. 检查磁盘空间是否充足

### 配置格式错误

**问题：** 使用 `config set` 后配置文件格式错误

**解决方案：**
1. 检查配置路径是否正确（使用点号分隔）
2. 检查值类型是否正确（字符串、数字、布尔值）
3. 从备份恢复配置文件

---

## 相关文档

- [用户管理](user-management.md)
- [Web 界面](web-interface.md)
- [封禁管理](../security/blocking-management.md) - 封禁管理功能详解
- [配置参考](../reference/configuration-reference.md)
- [故障排查](../troubleshooting/common-issues.md)
- [快速开始](../getting-started/quick-start.md)

---

## 版本信息

本文档适用于 SSLcat v1.3.21-rc5 及更高版本。

**最后更新：** 2025-01-29
