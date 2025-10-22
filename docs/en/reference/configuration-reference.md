# Configuration Reference

This guide provides a complete reference for SSLcat configuration files, including all available configuration options and examples.

## Configuration File Format

SSLcat uses JSON format configuration files, with the default filename being `sslcat.conf`.

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "http://localhost:8080",
        "ssl": true
      }
    ]
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true
  }
}
```

## Server Configuration

### Basic Settings
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443,
    "debug": false,
    "workers": 4,
    "max_connections": 1000
  }
}
```

### Advanced Settings
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443,
    "debug": false,
    "workers": 4,
    "max_connections": 1000,
    "read_timeout": "30s",
    "write_timeout": "30s",
    "idle_timeout": "120s",
    "keep_alive": true,
    "keep_alive_timeout": "30s"
  }
}
```

## SSL Configuration

### Basic SSL Settings
```json
{
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true,
    "certificate_dir": "/opt/sslcat/certs",
    "key_dir": "/opt/sslcat/keys"
  }
}
```

### Advanced SSL Settings
```json
{
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true,
    "certificate_dir": "/opt/sslcat/certs",
    "key_dir": "/opt/sslcat/keys",
    "min_version": "TLS12",
    "max_version": "TLS13",
    "cipher_suites": [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256"
    ],
    "session_resumption": true,
    "session_cache_size": 1000
  }
}
```

## Proxy Configuration

### Basic Proxy Rules
```json
{
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "http://localhost:8080",
        "ssl": true
      }
    ]
  }
}
```

### Advanced Proxy Rules
```json
{
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "http://localhost:8080",
        "ssl": true,
        "path_prefix": "/api",
        "headers": {
          "X-Forwarded-For": "$remote_addr",
          "X-Real-IP": "$remote_addr"
        },
        "timeout": "30s",
        "retry": 3
      }
    ],
    "default_target": "http://localhost:3000",
    "health_check": {
      "enabled": true,
      "path": "/health",
      "interval": "30s",
      "timeout": "5s"
    }
  }
}
```

## Admin Configuration

### Basic Admin Settings
```json
{
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": true,
    "session_timeout": "24h"
  }
}
```

### Advanced Admin Settings
```json
{
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": true,
    "session_timeout": "24h",
    "api_enabled": true,
    "api_key_file": "/opt/sslcat/data/api.key",
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 100
    }
  }
}
```

## Security Configuration

### Basic Security Settings
```json
{
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "max_attempts_5min": 10
  }
}
```

### Advanced Security Settings
```json
{
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "max_attempts_5min": 10,
    "ip_whitelist": [
      "192.168.1.0/24",
      "10.0.0.0/8"
    ],
    "ip_blacklist": [
      "192.168.1.100"
    ],
    "rate_limiting": {
      "enabled": true,
      "requests_per_second": 10,
      "burst_size": 20
    },
    "headers": {
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "X-XSS-Protection": "1; mode=block"
    }
  }
}
```

## Compression Configuration

### Basic Compression Settings
```json
{
  "compression": {
    "enabled": true,
    "algorithms": ["gzip", "brotli"],
    "min_size": 1024,
    "max_size": "10MB"
  }
}
```

### Advanced Compression Settings
```json
{
  "compression": {
    "enabled": true,
    "algorithms": ["gzip", "brotli"],
    "min_size": 512,
    "max_size": "50MB",
    "cache_size": "100MB",
    "cache_ttl": "24h",
    "compression_level": 6,
    "brotli_quality": 4
  }
}
```

## Caching Configuration

### Basic Cache Settings
```json
{
  "cache": {
    "enabled": true,
    "type": "memory",
    "size": "100MB",
    "ttl": "1h"
  }
}
```

### Advanced Cache Settings
```json
{
  "cache": {
    "enabled": true,
    "type": "redis",
    "redis_url": "redis://localhost:6379",
    "size": "500MB",
    "ttl": "24h",
    "eviction_policy": "lru",
    "compression": true,
    "persistence": true
  }
}
```

## Logging Configuration

### Basic Logging Settings
```json
{
  "logging": {
    "level": "info",
    "format": "json",
    "output": "stdout"
  }
}
```

### Advanced Logging Settings
```json
{
  "logging": {
    "level": "info",
    "format": "json",
    "output": "file",
    "file_path": "/var/log/sslcat/sslcat.log",
    "max_size": "100MB",
    "max_age": "30d",
    "max_backups": 10,
    "compress": true,
    "access_log": {
      "enabled": true,
      "file_path": "/var/log/sslcat/access.log",
      "format": "combined"
    },
    "error_log": {
      "enabled": true,
      "file_path": "/var/log/sslcat/error.log"
    }
  }
}
```

## Monitoring Configuration

### Basic Monitoring Settings
```json
{
  "monitoring": {
    "enabled": true,
    "metrics_path": "/metrics",
    "health_check_path": "/health"
  }
}
```

### Advanced Monitoring Settings
```json
{
  "monitoring": {
    "enabled": true,
    "metrics_path": "/metrics",
    "health_check_path": "/health",
    "prometheus": {
      "enabled": true,
      "path": "/metrics"
    },
    "health_check": {
      "enabled": true,
      "path": "/health",
      "timeout": "5s",
      "interval": "30s"
    },
    "profiling": {
      "enabled": true,
      "path": "/debug/pprof"
    }
  }
}
```

## Complete Configuration Example

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443,
    "debug": false,
    "workers": 4,
    "max_connections": 1000,
    "read_timeout": "30s",
    "write_timeout": "30s",
    "idle_timeout": "120s"
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true,
    "certificate_dir": "/opt/sslcat/certs",
    "key_dir": "/opt/sslcat/keys"
  },
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": true,
    "session_timeout": "24h"
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "http://localhost:8080",
        "ssl": true
      }
    ]
  },
  "security": {
    "max_attempts": 3,
    "block_duration": "5m",
    "max_attempts_5min": 10
  },
  "compression": {
    "enabled": true,
    "algorithms": ["gzip", "brotli"],
    "min_size": 1024,
    "max_size": "10MB"
  },
  "cache": {
    "enabled": true,
    "type": "memory",
    "size": "100MB",
    "ttl": "1h"
  },
  "logging": {
    "level": "info",
    "format": "json",
    "output": "stdout"
  },
  "monitoring": {
    "enabled": true,
    "metrics_path": "/metrics",
    "health_check_path": "/health"
  }
}
```

## Configuration Validation

### Validate Configuration
```bash
# Validate configuration file
sslcat -config sslcat.conf -validate

# Test configuration
sslcat -config sslcat.conf -test

# Check JSON syntax
python -c "import json; json.load(open('sslcat.conf'))"
```

### Common Configuration Errors

1. **Invalid JSON Syntax**
   - Missing commas
   - Unclosed brackets
   - Invalid string quotes

2. **Invalid Values**
   - Invalid port numbers
   - Invalid timeouts
   - Invalid file paths

3. **Missing Required Fields**
   - Missing server configuration
   - Missing SSL email
   - Missing admin credentials

## Related Documentation

- [Basic Configuration](../configuration/basic.md)
- [Advanced Configuration](../configuration/advanced.md)
- [Port Configuration Guide](../configuration/port-configuration-guide.md)
- [Troubleshooting](../troubleshooting/common-issues.md)
