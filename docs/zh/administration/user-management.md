# 用户管理

本指南介绍如何在 SSLcat 中管理用户账户、权限和访问控制。

## 用户类型

### 管理员 (Admin)
- **权限**: 完全访问所有功能
- **功能**: 配置管理、用户管理、系统监控
- **限制**: 无限制

### 操作员 (Operator)
- **权限**: 监控和基本配置
- **功能**: 查看指标、管理代理规则、查看日志
- **限制**: 不能修改系统配置

### 查看者 (Viewer)
- **权限**: 只读访问
- **功能**: 查看配置、监控指标、查看日志
- **限制**: 不能修改任何配置

## 用户管理

### 创建用户
```bash
# 使用 CLI 创建用户
sslcat users create -username admin -email admin@example.com -role admin

# 或使用 API
curl -X POST http://localhost:18080/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "securepassword",
    "role": "admin"
  }'
```

### 列出用户
```bash
# 使用 CLI 列出用户
sslcat users list

# 或使用 API
curl -H "Authorization: Bearer your-token" \
     http://localhost:18080/api/v1/users
```

### 更新用户
```bash
# 使用 CLI 更新用户
sslcat users update -username admin -role super-admin

# 或使用 API
curl -X PUT http://localhost:18080/api/v1/users/user-1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "email": "newemail@example.com",
    "role": "admin"
  }'
```

### 删除用户
```bash
# 使用 CLI 删除用户
sslcat users delete -username admin

# 或使用 API
curl -X DELETE http://localhost:18080/api/v1/users/user-1 \
  -H "Authorization: Bearer your-token"
```

## 权限管理

### 角色权限
```json
{
  "security": {
    "authentication": {
      "enabled": true,
      "roles": {
        "admin": {
          "permissions": [
            "config:read",
            "config:write",
            "users:read",
            "users:write",
            "monitoring:read",
            "system:read"
          ]
        },
        "operator": {
          "permissions": [
            "config:read",
            "monitoring:read",
            "logs:read"
          ]
        },
        "viewer": {
          "permissions": [
            "config:read",
            "monitoring:read"
          ]
        }
      }
    }
  }
}
```

### 资源权限
```json
{
  "security": {
    "access_control": {
      "enabled": true,
      "resources": {
        "config": {
          "admin": ["read", "write"],
          "operator": ["read"],
          "viewer": ["read"]
        },
        "users": {
          "admin": ["read", "write"],
          "operator": [],
          "viewer": []
        },
        "monitoring": {
          "admin": ["read", "write"],
          "operator": ["read"],
          "viewer": ["read"]
        }
      }
    }
  }
}
```

## 认证配置

### 基本认证
```json
{
  "security": {
    "authentication": {
      "enabled": true,
      "method": "basic",
      "users": [
        {
          "username": "admin",
          "password": "$2a$10$...",
          "role": "admin"
        },
        {
          "username": "operator",
          "password": "$2a$10$...",
          "role": "operator"
        }
      ]
    }
  }
}
```

### JWT 认证
```json
{
  "security": {
    "authentication": {
      "enabled": true,
      "method": "jwt",
      "jwt": {
        "secret": "your-jwt-secret",
        "issuer": "sslcat",
        "audience": "sslcat-users",
        "expiration": "3600s"
      }
    }
  }
}
```

### OAuth2 认证
```json
{
  "security": {
    "authentication": {
      "enabled": true,
      "method": "oauth2",
      "oauth2": {
        "provider": "google",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret",
        "redirect_url": "https://sslcat.example.com/auth/callback"
      }
    }
  }
}
```

## 访问控制

### IP 白名单
```json
{
  "security": {
    "access_control": {
      "enabled": true,
      "ip_whitelist": [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12"
      ]
    }
  }
}
```

### 时间限制
```json
{
  "security": {
    "access_control": {
      "enabled": true,
      "time_restrictions": {
        "enabled": true,
        "allowed_hours": "09:00-17:00",
        "allowed_days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
        "timezone": "UTC"
      }
    }
  }
}
```

### 地理位置限制
```json
{
  "security": {
    "access_control": {
      "enabled": true,
      "geo_restrictions": {
        "enabled": true,
        "allowed_countries": ["US", "CA", "GB"],
        "blocked_countries": ["CN", "RU"]
      }
    }
  }
}
```

## 会话管理

### 会话配置
```json
{
  "security": {
    "session": {
      "enabled": true,
      "timeout": "3600s",
      "max_sessions": 10,
      "secure_cookies": true,
      "http_only": true
    }
  }
}
```

### 会话监控
```bash
# 查看活跃会话
sslcat sessions list

# 终止特定会话
sslcat sessions terminate -session-id session-123

# 清除所有会话
sslcat sessions clear
```

## 审计日志

### 启用审计
```json
{
  "security": {
    "audit": {
      "enabled": true,
      "log_level": "info",
      "events": [
        "user_login",
        "user_logout",
        "config_change",
        "user_creation",
        "user_deletion",
        "permission_change"
      ]
    }
  }
}
```

### 审计日志格式
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "event": "user_login",
  "user": "admin",
  "ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "success": true,
  "details": {
    "method": "password",
    "session_id": "session-123"
  }
}
```

## 密码策略

### 密码要求
```json
{
  "security": {
    "password_policy": {
      "enabled": true,
      "min_length": 8,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_special_chars": true,
      "max_age": 90,
      "history_count": 5
    }
  }
}
```

### 密码重置
```bash
# 重置用户密码
sslcat users password -username admin

# 或使用 API
curl -X POST http://localhost:18080/api/v1/users/user-1/password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "new_password": "newsecurepassword"
  }'
```

## 多因素认证

### 启用 2FA
```json
{
  "security": {
    "mfa": {
      "enabled": true,
      "methods": ["totp", "sms"],
      "backup_codes": true,
      "grace_period": 7
    }
  }
}
```

### TOTP 配置
```bash
# 为用户启用 TOTP
sslcat users mfa enable -username admin -method totp

# 验证 TOTP 代码
sslcat users mfa verify -username admin -code 123456
```

## API 密钥管理

### 创建 API 密钥
```bash
# 创建 API 密钥
sslcat api key generate -user admin -name "automation"

# 或使用 API
curl -X POST http://localhost:18080/api/v1/api-keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{
    "name": "automation",
    "user_id": "user-1",
    "permissions": ["config:read", "monitoring:read"]
  }'
```

### 管理 API 密钥
```bash
# 列出 API 密钥
sslcat api keys list

# 撤销 API 密钥
sslcat api key revoke -key abc123

# 更新 API 密钥权限
sslcat api key update -key abc123 -permissions "config:read,monitoring:read"
```

## 安全最佳实践

### 1. 强密码策略
- 使用复杂的密码
- 定期更换密码
- 启用密码历史记录
- 实施密码过期策略

### 2. 访问控制
- 实施最小权限原则
- 使用 IP 白名单
- 启用时间限制
- 监控异常访问

### 3. 会话管理
- 设置合理的会话超时
- 启用安全 Cookie
- 监控并发会话
- 及时清理过期会话

### 4. 审计和监控
- 启用完整的审计日志
- 监控登录活动
- 设置异常告警
- 定期审查访问日志

### 5. 多因素认证
- 为管理员启用 2FA
- 使用 TOTP 或 SMS
- 提供备用代码
- 定期更新认证方法

## 故障排除

### 常见问题

1. **用户无法登录**
   - 检查用户名和密码
   - 验证用户状态
   - 检查 IP 白名单
   - 查看审计日志

2. **权限不足**
   - 检查用户角色
   - 验证资源权限
   - 查看访问控制配置
   - 检查会话状态

3. **会话问题**
   - 检查会话超时设置
   - 验证 Cookie 配置
   - 查看会话存储
   - 检查网络连接

### 调试命令
```bash
# 检查用户状态
sslcat users status -username admin

# 查看权限
sslcat users permissions -username admin

# 检查会话
sslcat sessions info -session-id session-123

# 查看审计日志
sslcat audit logs -user admin -since "2024-01-01"
```

## 相关文档

- [Web 界面](web-interface.md)
- [CLI 命令](cli-commands.md)
- [安全配置](../configuration/security.md)
- [监控指南](../features/monitoring.md)

---

*用户管理是 SSLcat 安全性的重要组成部分，正确配置可以确保系统的安全性和可访问性。*
