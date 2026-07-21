# 高级配置

本指南涵盖 SSLcat 的高级配置选项，包括性能调优、安全设置和企业功能。

## 服务器配置

### 基本服务器设置
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443,
    "debug": false,
    "workers": 4,
    "max_connections": 1000,
    "keep_alive_timeout": "30s",
    "read_timeout": "30s",
    "write_timeout": "30s"
  }
}
```

### 性能调优
```json
{
  "server": {
    "max_connections": 2000,
    "max_connections_per_ip": 100,
    "keep_alive_timeout": "60s",
    "read_timeout": "60s",
    "write_timeout": "60s",
    "idle_timeout": "120s",
    "tcp_keepalive": true,
    "tcp_keepalive_interval": "30s"
  }
}
```

## SSL 配置

### 高级 SSL 设置
```json
{
  "ssl": {
    "min_version": "TLS12",
    "max_version": "TLS13",
    "cipher_suites": [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256"
    ],
    "session_resumption": true,
    "session_cache_size": 1000,
    "session_timeout": "24h",
    "ocsp_stapling": true,
    "hsts": {
      "enabled": true,
      "max_age": "31536000",
      "include_subdomains": true
    }
  }
}
```

### 证书管理
```json
{
  "ssl": {
    "certificate_authority": "letsencrypt",
    "staging": false,
    "auto_renew": true,
    "renewal_threshold": "30d",
    "certificate_dir": "/opt/sslcat/certs",
    "key_dir": "/opt/sslcat/keys",
    "backup_certificates": true,
    "certificate_rotation": true
  }
}
```

## 代理配置

### 高级代理设置
```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "http://localhost:8080",
        "ssl": true,
        "path_prefix": "/api",
        "headers": {
          "X-Forwarded-For": "$remote_addr",
          "X-Real-IP": "$remote_addr",
          "X-Forwarded-Proto": "$scheme"
        },
        "timeout": "30s",
        "retry": 3,
        "health_check": {
          "enabled": true,
          "path": "/health",
          "interval": "30s",
          "timeout": "5s"
        }
      }
    ],
    "default_target": "http://localhost:3000",
    "load_balancing": {
      "algorithm": "round_robin",
      "health_check": true,
      "sticky_sessions": false
    }
  }
}
```

### 负载均衡
```json
{
  "proxy": {
    "load_balancing": {
      "algorithm": "least_connections",
      "servers": [
        "http://backend1:8080",
        "http://backend2:8080",
        "http://backend3:8080"
      ],
      "health_check": {
        "enabled": true,
        "path": "/health",
        "interval": "10s",
        "timeout": "3s",
        "unhealthy_threshold": 3,
        "healthy_threshold": 2
      },
      "sticky_sessions": {
        "enabled": true,
        "cookie_name": "SSLCAT_SESSION",
        "ttl": "24h"
      }
    }
  }
}
```

## 缓存配置

### 内存缓存
```json
{
  "cache": {
    "enabled": true,
    "type": "memory",
    "size": "500MB",
    "ttl": "1h",
    "eviction_policy": "lru",
    "compression": true,
    "persistence": false
  }
}
```

### Redis 缓存
```json
{
  "cache": {
    "enabled": true,
    "type": "redis",
    "redis_url": "redis://localhost:6379",
    "redis_password": "your_password",
    "redis_db": 0,
    "size": "1GB",
    "ttl": "24h",
    "eviction_policy": "lru",
    "compression": true,
    "persistence": true,
    "cluster": {
      "enabled": false,
      "nodes": [
        "redis://node1:6379",
        "redis://node2:6379",
        "redis://node3:6379"
      ]
    }
  }
}
```

## 压缩配置

### 高级压缩设置
```json
{
  "compression": {
    "enabled": true,
    "algorithms": ["gzip", "brotli"],
    "min_size": 512,
    "max_size": "50MB",
    "cache_size": "200MB",
    "cache_ttl": "24h",
    "compression_level": 6,
    "brotli_quality": 4,
    "vary_header": true,
    "content_types": [
      "text/html",
      "text/css",
      "text/javascript",
      "application/javascript",
      "application/json"
    ]
  }
}
```

## 安全配置

### 访问控制
```json
{
  "security": {
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
      "burst_size": 20,
      "per_ip": true
    },
    "headers": {
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "X-XSS-Protection": "1; mode=block",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
    }
  }
}
```

### 认证和授权
```json
{
  "security": {
    "authentication": {
      "enabled": true,
      "type": "basic",
      "realm": "SSLcat Admin",
      "users": [
        {
          "username": "admin",
          "password": "hashed_password",
          "roles": ["admin"]
        }
      ]
    },
    "authorization": {
      "enabled": true,
      "roles": {
        "admin": ["*"],
        "operator": ["read", "write"],
        "viewer": ["read"]
      }
    }
  }
}
```

## 监控配置

### 性能监控
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
    }
  },
  "server": {
    "enable_pprof": true,
    "pprof_addr": "127.0.0.1:6060"
  }
}
```

### 日志配置
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

## 企业功能

### 集群配置
```json
{
  "cluster": {
    "enabled": true,
    "nodes": [
      "sslcat-node1:8080",
      "sslcat-node2:8080",
      "sslcat-node3:8080"
    ],
    "leader_election": true,
    "consensus": "raft",
    "data_replication": true
  }
}
```

### 高可用配置
```json
{
  "ha": {
    "enabled": true,
    "vip": "192.168.1.100",
    "vip_interface": "eth0",
    "health_check": {
      "enabled": true,
      "interval": "5s",
      "timeout": "3s",
      "unhealthy_threshold": 3
    },
    "failover": {
      "enabled": true,
      "timeout": "10s"
    }
  }
}
```

## 性能优化

### 系统调优
```json
{
  "performance": {
    "worker_processes": 4,
    "worker_connections": 1024,
    "multi_accept": true,
    "use_epoll": true,
    "sendfile": true,
    "tcp_nopush": true,
    "tcp_nodelay": true,
    "keepalive_timeout": 65,
    "client_max_body_size": "10m"
  }
}
```

### 内存优化
```json
{
  "performance": {
    "memory": {
      "max_memory": "2GB",
      "gc_threshold": "1GB",
      "cache_size": "500MB",
      "buffer_size": "64KB"
    }
  }
}
```

## 相关文档

- [基础配置](basic.md)
- [端口配置指南](port-configuration-guide.md)
- [配置参考](../reference/configuration-reference.md)
- [性能优化](../troubleshooting/performance.md)
