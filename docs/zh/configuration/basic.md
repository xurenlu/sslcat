# 基础配置

本指南涵盖了 SSLcat 的基本配置选项，包括服务器设置、SSL 证书管理、代理规则和安全设置。

## 📋 配置文件结构

SSLcat 使用位于 `/etc/sslcat/sslcat.conf` 的 JSON 配置文件。配置分为几个部分：

```json
{
  "server": { ... },
  "ssl": { ... },
  "admin": { ... },
  "proxy": { ... },
  "security": { ... },
  "logging": { ... }
}
```

## 🖥️ 服务器配置

### 基本服务器设置

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false,
    "max_connections": 1000,
    "read_timeout_sec": 30,
    "write_timeout_sec": 30,
    "idle_timeout_sec": 120
  }
}
```

**配置选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `host` | string | "0.0.0.0" | 服务器绑定地址 |
| `port` | integer | 443 | HTTPS 端口号 |
| `debug` | boolean | false | 启用调试日志 |
| `max_connections` | integer | 1000 | 最大并发连接数 |
| `read_timeout_sec` | integer | 30 | 请求读取超时 |
| `write_timeout_sec` | integer | 30 | 响应写入超时 |
| `idle_timeout_sec` | integer | 120 | 连接空闲超时 |

### 高级服务器设置

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false,
    "max_connections": 1000,
    "read_timeout_sec": 30,
    "write_timeout_sec": 30,
    "idle_timeout_sec": 120,
    "keep_alive": true,
    "keep_alive_timeout": "60s",
    "max_header_bytes": 1048576,
    "max_upload_bytes": 1073741824
  }
}
```

**其他选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `keep_alive` | boolean | true | 启用 HTTP keep-alive |
| `keep_alive_timeout` | string | "60s" | Keep-alive 超时 |
| `max_header_bytes` | integer | 1048576 | 最大头部大小 (1MB) |
| `max_upload_bytes` | integer | 1073741824 | 最大上传大小 (1GB) |

## 🔒 SSL 证书配置

### 基本 SSL 设置

```json
{
  "ssl": {
    "email": "your-email@example.com",
    "staging": false,
    "auto_renew": true,
    "certificate_dir": "/opt/sslcat/certs",
    "key_dir": "/opt/sslcat/keys"
  }
}
```

**SSL 配置选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `email` | string | 必需 | Let's Encrypt 通知邮箱 |
| `staging` | boolean | false | 使用 Let's Encrypt 测试环境 |
| `auto_renew` | boolean | true | 启用自动证书续期 |
| `certificate_dir` | string | "/opt/sslcat/certs" | 证书存储目录 |
| `key_dir` | string | "/opt/sslcat/keys" | 私钥存储目录 |

### 高级 SSL 设置

```json
{
  "ssl": {
    "email": "your-email@example.com",
    "staging": false,
    "auto_renew": true,
    "certificate_dir": "/opt/sslcat/certs",
    "key_dir": "/opt/sslcat/keys",
    "min_tls_version": "1.2",
    "cipher_suites": [
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ],
    "hsts": {
      "enabled": true,
      "max_age": 31536000,
      "include_subdomains": true
    },
    "renewal_threshold": 30,
    "renewal_check_interval": "24h"
  }
}
```

**高级 SSL 选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `min_tls_version` | string | "1.2" | 最小 TLS 版本 |
| `cipher_suites` | array | [] | 允许的密码套件 |
| `hsts` | object | {} | HTTP 严格传输安全 |
| `renewal_threshold` | integer | 30 | 过期前续期的天数 |
| `renewal_check_interval` | string | "24h" | 证书检查间隔 |

## 👤 管理员配置

### 基本管理员设置

```json
{
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": false,
    "session_timeout": "24h"
  }
}
```

**管理员配置选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `username` | string | "admin" | 管理员用户名 |
| `password_file` | string | "/opt/sslcat/data/admin.pass" | 密码文件路径 |
| `first_run` | boolean | true | 首次运行标志 |
| `session_timeout` | string | "24h" | 会话超时持续时间 |

### 高级管理员设置

```json
{
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": false,
    "session_timeout": "24h",
    "max_login_attempts": 3,
    "lockout_duration": "15m",
    "password_policy": {
      "min_length": 8,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_symbols": true
    }
  }
}
```

**高级管理员选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `max_login_attempts` | integer | 3 | 最大失败登录尝试次数 |
| `lockout_duration` | string | "15m" | 账户锁定持续时间 |
| `password_policy` | object | {} | 密码复杂性要求 |

## 🌐 代理配置

### 基本代理规则

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "ssl_only": true
      }
    ]
  }
}
```

**基本代理规则选项：**

| 选项 | 类型 | 必需 | 描述 |
|------|------|------|------|
| `domain` | string | 是 | 要代理的域名 |
| `target` | string | 是 | 后端服务器 IP 或主机名 |
| `port` | integer | 是 | 后端服务器端口 |
| `enabled` | boolean | 否 | 启用/禁用规则 |
| `ssl_only` | boolean | 否 | 要求 HTTPS 连接 |

### 高级代理规则

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "ssl_only": true,
        "path_prefix": "/api",
        "websocket": false,
        "health_check": {
          "enabled": true,
          "path": "/health",
          "interval": "30s",
          "timeout": "5s"
        },
        "load_balancing": {
          "method": "round_robin",
          "targets": [
            {"host": "127.0.0.1", "port": 8080, "weight": 1},
            {"host": "127.0.0.1", "port": 8081, "weight": 1}
          ]
        }
      }
    ]
  }
}
```

**高级代理选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `path_prefix` | string | "" | URL 路径前缀 |
| `websocket` | boolean | false | 启用 WebSocket 支持 |
| `health_check` | object | {} | 后端健康监控 |
| `load_balancing` | object | {} | 负载均衡配置 |

## 🛡️ 安全配置

### 基本安全设置

```json
{
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "max_attempts_5min": 10,
    "ip_whitelist": [],
    "ip_blacklist": []
  }
}
```

**基本安全选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `max_attempts` | integer | 3 | 阻止前的失败登录尝试次数 |
| `block_duration` | string | "5m" | IP 阻止持续时间 |
| `max_attempts_5min` | integer | 10 | 5 分钟内的最大尝试次数 |
| `ip_whitelist` | array | [] | 受信任 IP 地址列表 |
| `ip_blacklist` | array | [] | 被阻止 IP 地址列表 |

### 高级安全设置

```json
{
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "max_attempts_5min": 10,
    "ip_whitelist": [],
    "ip_blacklist": [],
    "user_agent_validation": true,
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 60,
      "burst_size": 10
    },
    "ddos_protection": {
      "enabled": true,
      "max_requests_per_second": 100,
      "block_duration": "1h"
    }
  }
}
```

**高级安全选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `user_agent_validation` | boolean | true | 验证用户代理 |
| `rate_limiting` | object | {} | 速率限制配置 |
| `ddos_protection` | object | {} | DDoS 保护设置 |

## 📊 日志配置

### 基本日志设置

```json
{
  "logging": {
    "level": "info",
    "access_log": "/opt/sslcat/logs/access.log",
    "error_log": "/opt/sslcat/logs/error.log"
  }
}
```

**基本日志选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `level` | string | "info" | 日志级别 (debug, info, warn, error) |
| `access_log` | string | "/opt/sslcat/logs/access.log" | 访问日志文件路径 |
| `error_log` | string | "/opt/sslcat/logs/error.log" | 错误日志文件路径 |

### 高级日志设置

```json
{
  "logging": {
    "level": "info",
    "access_log": "/opt/sslcat/logs/access.log",
    "error_log": "/opt/sslcat/logs/error.log",
    "security_log": "/opt/sslcat/logs/security.log",
    "log_rotation": {
      "enabled": true,
      "max_size": "100MB",
      "max_files": 10,
      "compress": true
    },
    "log_format": "json",
    "include_headers": true,
    "include_body": false
  }
}
```

**高级日志选项：**

| 选项 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `security_log` | string | "" | 安全日志文件路径 |
| `log_rotation` | object | {} | 日志轮转设置 |
| `log_format` | string | "text" | 日志格式 (text, json) |
| `include_headers` | boolean | false | 包含请求头 |
| `include_body` | boolean | false | 包含请求体 |

## 🔧 配置示例

### 开发环境

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "debug": true
  },
  "ssl": {
    "email": "dev@example.com",
    "staging": true,
    "auto_renew": false
  },
  "admin": {
    "username": "admin",
    "password_file": "./data/admin.pass",
    "first_run": true
  },
  "proxy": {
    "rules": [
      {
        "domain": "localhost",
        "target": "127.0.0.1",
        "port": 3000,
        "enabled": true,
        "ssl_only": false
      }
    ]
  }
}
```

### 生产环境

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false,
    "max_connections": 1000
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true
  },
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": false
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "ssl_only": true
      }
    ]
  },
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 60
    }
  }
}
```

## 🔄 配置管理

### 重新加载配置

```bash
# 重新加载配置而不重启
sudo systemctl reload sslcat

# 或发送 SIGHUP 信号
sudo kill -HUP $(pgrep sslcat)
```

### 验证配置

```bash
# 验证配置文件
sslcat --config /etc/sslcat/sslcat.conf --validate

# 测试配置而不启动
sslcat --config /etc/sslcat/sslcat.conf --dry-run
```

### 备份配置

```bash
# 备份当前配置
sudo cp /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.backup

# 从备份恢复
sudo cp /etc/sslcat/sslcat.conf.backup /etc/sslcat/sslcat.conf
sudo systemctl reload sslcat
```

## 🚨 故障排除

### 常见配置问题

**无效的 JSON 语法：**
```bash
# 检查 JSON 语法
python -m json.tool /etc/sslcat/sslcat.conf
```

**端口已被使用：**
```bash
# 检查端口使用情况
sudo netstat -tlnp | grep :443
sudo lsof -i :443
```

**权限问题：**
```bash
# 检查文件权限
ls -la /etc/sslcat/sslcat.conf
sudo chown sslcat:sslcat /etc/sslcat/sslcat.conf
```

### 配置验证

```bash
# 使用调试日志启动
sslcat --config /etc/sslcat/sslcat.conf --log-level debug

# 检查配置错误
sudo journalctl -u sslcat -f | grep -i error
```

---

*基础配置完成？查看我们的[高级配置指南](advanced.md)了解更多详细设置。*
