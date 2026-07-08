# User Management

This guide explains how to manage user accounts, permissions, and access control in SSLcat.

## User Types

### Administrator (Admin)
- **Permissions**: Full access to all features
- **Functions**: Configuration management, user management, system monitoring
- **Limitations**: None

### Operator
- **Permissions**: Monitoring and basic configuration
- **Functions**: View metrics, manage proxy rules, view logs
- **Limitations**: Cannot modify system configuration

### Viewer
- **Permissions**: Read-only access
- **Functions**: View configuration, monitor metrics, view logs
- **Limitations**: Cannot modify any configuration

## User Management

### Creating Users
```bash
# Create user using CLI
sslcat users create -username admin -email admin@example.com -role admin

# Or using API
curl -X POST http://localhost:18080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin",
    "password": "secure_password"
  }'
```

### User Roles and Permissions

| Role | Configuration | Users | Monitoring | Logs | System |
|------|---------------|-------|-------------|------|--------|
| Admin | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| Operator | ✅ Read/Write | ❌ None | ✅ Full | ✅ Full | ❌ None |
| Viewer | ✅ Read | ❌ None | ✅ Read | ✅ Read | ❌ None |

### Managing User Permissions

```json
{
  "users": {
    "admin": {
      "role": "admin",
      "permissions": {
        "configuration": "full",
        "users": "full",
        "monitoring": "full",
        "logs": "full",
        "system": "full"
      }
    },
    "operator": {
      "role": "operator",
      "permissions": {
        "configuration": "read_write",
        "users": "none",
        "monitoring": "full",
        "logs": "full",
        "system": "none"
      }
    }
  }
}
```

## Authentication

### Password Management

```bash
# Change user password
sslcat users password -username admin -new-password new_secure_password

# Reset user password
sslcat users reset-password -username admin
```

### API Authentication

```bash
# Get API token
curl -X POST http://localhost:18080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password"
  }'

# Use API token
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:18080/api/v1/config
```

## Access Control

### IP Restrictions

```json
{
  "security": {
    "ip_whitelist": [
      "192.168.1.0/24",
      "10.0.0.0/8"
    ],
    "ip_blacklist": [
      "192.168.1.100"
    ]
  }
}
```

### Session Management

```json
{
  "admin": {
    "session_timeout": "24h",
    "max_sessions": 5,
    "inactive_timeout": "2h"
  }
}
```

## User Operations

### List Users

```bash
# List all users
sslcat users list

# List users with details
sslcat users list -verbose
```

### Update User

```bash
# Update user role
sslcat users update -username admin -role operator

# Update user email
sslcat users update -username admin -email new@example.com
```

### Delete User

```bash
# Delete user
sslcat users delete -username old_user

# Delete user with confirmation
sslcat users delete -username old_user -confirm
```

## Security Best Practices

### 1. Strong Passwords
- Minimum 12 characters
- Mix of letters, numbers, and symbols
- No common passwords

### 2. Regular Password Rotation
- Change passwords every 90 days
- Use password managers
- Enable two-factor authentication

### 3. Access Monitoring
- Monitor login attempts
- Log all user actions
- Set up alerts for suspicious activity

### 4. Role-Based Access
- Assign minimal required permissions
- Regular permission reviews
- Remove unused accounts

## Troubleshooting

### Common Issues

1. **User Cannot Login**
   ```bash
   # Check user status
   sslcat users status -username admin
   
   # Reset password
   sslcat users reset-password -username admin
   ```

2. **Permission Denied**
   ```bash
   # Check user permissions
   sslcat users permissions -username admin
   
   # Update user role
   sslcat users update -username admin -role admin
   ```

3. **Session Expired**
   - Check session timeout settings
   - Verify system time synchronization
   - Clear browser cache

## Related Documentation

- [Web Interface](web-interface.md)
- [CLI Commands](cli-commands.md)
- [Security Configuration](../configuration/security.md)
- [Troubleshooting](../troubleshooting/common-issues.md)
