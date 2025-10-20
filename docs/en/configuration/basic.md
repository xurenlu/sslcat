# Basic Configuration

This guide covers the essential configuration options for SSLcat, including server settings, SSL certificate management, proxy rules, and security settings.

## 📋 Configuration File Structure

SSLcat uses a JSON configuration file located at `/etc/sslcat/sslcat.conf`. The configuration is organized into several sections:

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

## 🖥️ Server Configuration

### Basic Server Settings

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

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `host` | string | "0.0.0.0" | Server binding address |
| `port` | integer | 443 | HTTPS port number |
| `debug` | boolean | false | Enable debug logging |
| `max_connections` | integer | 1000 | Maximum concurrent connections |
| `read_timeout_sec` | integer | 30 | Request read timeout |
| `write_timeout_sec` | integer | 30 | Response write timeout |
| `idle_timeout_sec` | integer | 120 | Connection idle timeout |

### Advanced Server Settings

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

**Additional Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keep_alive` | boolean | true | Enable HTTP keep-alive |
| `keep_alive_timeout` | string | "60s" | Keep-alive timeout |
| `max_header_bytes` | integer | 1048576 | Maximum header size (1MB) |
| `max_upload_bytes` | integer | 1073741824 | Maximum upload size (1GB) |

## 🔒 SSL Certificate Configuration

### Basic SSL Settings

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

**SSL Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `email` | string | Required | Email for Let's Encrypt notifications |
| `staging` | boolean | false | Use Let's Encrypt staging environment |
| `auto_renew` | boolean | true | Enable automatic certificate renewal |
| `certificate_dir` | string | "/opt/sslcat/certs" | Certificate storage directory |
| `key_dir` | string | "/opt/sslcat/keys" | Private key storage directory |

### Advanced SSL Settings

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

**Advanced SSL Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `min_tls_version` | string | "1.2" | Minimum TLS version |
| `cipher_suites` | array | [] | Allowed cipher suites |
| `hsts` | object | {} | HTTP Strict Transport Security |
| `renewal_threshold` | integer | 30 | Days before expiration to renew |
| `renewal_check_interval` | string | "24h" | Certificate check interval |

## 👤 Admin Configuration

### Basic Admin Settings

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

**Admin Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `username` | string | "admin" | Admin username |
| `password_file` | string | "/opt/sslcat/data/admin.pass" | Password file path |
| `first_run` | boolean | true | First run flag |
| `session_timeout` | string | "24h" | Session timeout duration |

### Advanced Admin Settings

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

**Advanced Admin Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_login_attempts` | integer | 3 | Maximum failed login attempts |
| `lockout_duration` | string | "15m" | Account lockout duration |
| `password_policy` | object | {} | Password complexity requirements |

## 🌐 Proxy Configuration

### Basic Proxy Rules

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

**Basic Proxy Rule Options:**

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `domain` | string | Yes | Domain name to proxy |
| `target` | string | Yes | Backend server IP or hostname |
| `port` | integer | Yes | Backend server port |
| `enabled` | boolean | No | Enable/disable the rule |
| `ssl_only` | boolean | No | Require HTTPS connections |

### Advanced Proxy Rules

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

**Advanced Proxy Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `path_prefix` | string | "" | URL path prefix |
| `websocket` | boolean | false | Enable WebSocket support |
| `health_check` | object | {} | Backend health monitoring |
| `load_balancing` | object | {} | Load balancing configuration |

## 🛡️ Security Configuration

### Basic Security Settings

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

**Basic Security Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_attempts` | integer | 3 | Failed login attempts before blocking |
| `block_duration` | string | "5m" | IP block duration |
| `max_attempts_5min` | integer | 10 | Maximum attempts in 5 minutes |
| `ip_whitelist` | array | [] | List of trusted IP addresses |
| `ip_blacklist` | array | [] | List of blocked IP addresses |

### Advanced Security Settings

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

**Advanced Security Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `user_agent_validation` | boolean | true | Validate user agents |
| `rate_limiting` | object | {} | Rate limiting configuration |
| `ddos_protection` | object | {} | DDoS protection settings |

## 📊 Logging Configuration

### Basic Logging Settings

```json
{
  "logging": {
    "level": "info",
    "access_log": "/opt/sslcat/logs/access.log",
    "error_log": "/opt/sslcat/logs/error.log"
  }
}
```

**Basic Logging Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | string | "info" | Log level (debug, info, warn, error) |
| `access_log` | string | "/opt/sslcat/logs/access.log" | Access log file path |
| `error_log` | string | "/opt/sslcat/logs/error.log" | Error log file path |

### Advanced Logging Settings

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

**Advanced Logging Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `security_log` | string | "" | Security log file path |
| `log_rotation` | object | {} | Log rotation settings |
| `log_format` | string | "text" | Log format (text, json) |
| `include_headers` | boolean | false | Include request headers |
| `include_body` | boolean | false | Include request body |

## 🔧 Configuration Examples

### Development Environment

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

### Production Environment

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

## 🔄 Configuration Management

### Reload Configuration

```bash
# Reload configuration without restart
sudo systemctl reload sslcat

# Or send SIGHUP signal
sudo kill -HUP $(pgrep sslcat)
```

### Validate Configuration

```bash
# Validate configuration file
sslcat --config /etc/sslcat/sslcat.conf --validate

# Test configuration without starting
sslcat --config /etc/sslcat/sslcat.conf --dry-run
```

### Backup Configuration

```bash
# Backup current configuration
sudo cp /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.backup

# Restore from backup
sudo cp /etc/sslcat/sslcat.conf.backup /etc/sslcat/sslcat.conf
sudo systemctl reload sslcat
```

## 🚨 Troubleshooting

### Common Configuration Issues

**Invalid JSON syntax:**
```bash
# Check JSON syntax
python -m json.tool /etc/sslcat/sslcat.conf
```

**Port already in use:**
```bash
# Check port usage
sudo netstat -tlnp | grep :443
sudo lsof -i :443
```

**Permission issues:**
```bash
# Check file permissions
ls -la /etc/sslcat/sslcat.conf
sudo chown sslcat:sslcat /etc/sslcat/sslcat.conf
```

### Configuration Validation

```bash
# Start with debug logging
sslcat --config /etc/sslcat/sslcat.conf --log-level debug

# Check configuration errors
sudo journalctl -u sslcat -f | grep -i error
```

---

*Basic configuration complete? Check out our [Advanced Configuration Guide](advanced.md) for more detailed settings.*
