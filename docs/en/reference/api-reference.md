# API Reference

SSLcat provides a comprehensive REST API for configuration management, monitoring, and administration.

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

All API endpoints require authentication. Use one of these methods:

### API Key Authentication
```bash
curl -H "Authorization: Bearer your-api-key" \
     http://localhost:8080/api/v1/config
```

### Basic Authentication
```bash
curl -u username:password \
     http://localhost:8080/api/v1/config
```

## Configuration Management

### Get Current Configuration
```http
GET /api/v1/config
```

**Response:**
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
  }
}
```

### Update Configuration
```http
PUT /api/v1/config
Content-Type: application/json
```

**Request Body:**
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
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration updated successfully"
}
```

## Proxy Rules Management

### List Proxy Rules
```http
GET /api/v1/proxy/rules
```

**Response:**
```json
{
  "rules": [
    {
      "id": "rule-1",
      "domain": "example.com",
      "target": "http://localhost:8080",
      "ssl": true,
      "enabled": true
    }
  ]
}
```

### Create Proxy Rule
```http
POST /api/v1/proxy/rules
Content-Type: application/json
```

**Request Body:**
```json
{
  "domain": "api.example.com",
  "target": "http://localhost:3000",
  "ssl": true,
  "load_balancing": {
    "enabled": true,
    "algorithm": "round_robin",
    "backends": [
      "http://localhost:3000",
      "http://localhost:3001"
    ]
  }
}
```

**Response:**
```json
{
  "id": "rule-2",
  "status": "created",
  "message": "Proxy rule created successfully"
}
```

### Update Proxy Rule
```http
PUT /api/v1/proxy/rules/{rule_id}
Content-Type: application/json
```

**Request Body:**
```json
{
  "domain": "api.example.com",
  "target": "http://localhost:3000",
  "ssl": true,
  "load_balancing": {
    "enabled": true,
    "algorithm": "least_connections",
    "backends": [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:3002"
    ]
  }
}
```

### Delete Proxy Rule
```http
DELETE /api/v1/proxy/rules/{rule_id}
```

**Response:**
```json
{
  "status": "success",
  "message": "Proxy rule deleted successfully"
}
```

## SSL Certificate Management

### List Certificates
```http
GET /api/v1/ssl/certificates
```

**Response:**
```json
{
  "certificates": [
    {
      "domain": "example.com",
      "provider": "letsencrypt",
      "status": "valid",
      "expires_at": "2024-12-31T23:59:59Z",
      "auto_renew": true
    }
  ]
}
```

### Create Certificate
```http
POST /api/v1/ssl/certificates
Content-Type: application/json
```

**Request Body:**
```json
{
  "domain": "api.example.com",
  "provider": "letsencrypt",
  "email": "admin@example.com",
  "auto_renew": true
}
```

### Renew Certificate
```http
POST /api/v1/ssl/certificates/{domain}/renew
```

**Response:**
```json
{
  "status": "success",
  "message": "Certificate renewal initiated"
}
```

## Load Balancing Management

### List Backends
```http
GET /api/v1/load-balancer/backends
```

**Response:**
```json
{
  "backends": [
    {
      "id": "backend-1",
      "url": "http://localhost:8080",
      "status": "healthy",
      "response_time": "50ms",
      "last_check": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### Add Backend
```http
POST /api/v1/load-balancer/backends
Content-Type: application/json
```

**Request Body:**
```json
{
  "url": "http://localhost:8081",
  "weight": 1,
  "health_check": {
    "enabled": true,
    "path": "/health",
    "interval": 30
  }
}
```

### Update Backend Status
```http
PUT /api/v1/load-balancer/backends/{backend_id}/status
Content-Type: application/json
```

**Request Body:**
```json
{
  "status": "disabled",
  "reason": "Maintenance"
}
```

## Monitoring and Metrics

### Get Metrics
```http
GET /api/v1/metrics
```

**Response:**
```json
{
  "requests_total": 1000,
  "requests_per_second": 10.5,
  "response_time_avg": "50ms",
  "response_time_p95": "100ms",
  "response_time_p99": "200ms",
  "error_rate": 0.01,
  "active_connections": 50,
  "ssl_handshakes": 500,
  "cache_hits": 800,
  "cache_misses": 200
}
```

### Get Health Status
```http
GET /api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "components": {
    "proxy": "healthy",
    "ssl": "healthy",
    "load_balancer": "healthy",
    "cache": "healthy"
  }
}
```

### Get System Information
```http
GET /api/v1/system/info
```

**Response:**
```json
{
  "version": "1.3.16-rc18",
  "uptime": "24h30m15s",
  "memory_usage": "128MB",
  "cpu_usage": "15%",
  "disk_usage": "2.1GB",
  "network_interfaces": [
    {
      "name": "eth0",
      "ip": "192.168.1.100",
      "status": "up"
    }
  ]
}
```

## Cache Management

### Get Cache Statistics
```http
GET /api/v1/cache/stats
```

**Response:**
```json
{
  "hits": 800,
  "misses": 200,
  "hit_rate": 0.8,
  "size": "50MB",
  "max_size": "100MB",
  "entries": 1000
}
```

### Clear Cache
```http
POST /api/v1/cache/clear
```

**Response:**
```json
{
  "status": "success",
  "message": "Cache cleared successfully"
}
```

### Clear Cache by Pattern
```http
POST /api/v1/cache/clear
Content-Type: application/json
```

**Request Body:**
```json
{
  "pattern": "*.css",
  "domain": "example.com"
}
```

## Logging Management

### Get Logs
```http
GET /api/v1/logs
```

**Query Parameters:**
- `level`: Log level (debug, info, warn, error)
- `limit`: Number of log entries (default: 100)
- `since`: Start time (ISO 8601 format)

**Response:**
```json
{
  "logs": [
    {
      "timestamp": "2024-01-01T12:00:00Z",
      "level": "info",
      "message": "Request processed successfully",
      "fields": {
        "method": "GET",
        "url": "/api/users",
        "status": 200,
        "duration": "50ms"
      }
    }
  ]
}
```

### Set Log Level
```http
PUT /api/v1/logs/level
Content-Type: application/json
```

**Request Body:**
```json
{
  "level": "debug"
}
```

## User Management

### List Users
```http
GET /api/v1/users
```

**Response:**
```json
{
  "users": [
    {
      "id": "user-1",
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "created_at": "2024-01-01T00:00:00Z",
      "last_login": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### Create User
```http
POST /api/v1/users
Content-Type: application/json
```

**Request Body:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "securepassword",
  "role": "user"
}
```

### Update User
```http
PUT /api/v1/users/{user_id}
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "newemail@example.com",
  "role": "admin"
}
```

### Delete User
```http
DELETE /api/v1/users/{user_id}
```

## Backup and Restore

### Create Backup
```http
POST /api/v1/backup
```

**Response:**
```json
{
  "backup_id": "backup-20240101-120000",
  "status": "created",
  "size": "1.2MB",
  "created_at": "2024-01-01T12:00:00Z"
}
```

### List Backups
```http
GET /api/v1/backup
```

**Response:**
```json
{
  "backups": [
    {
      "id": "backup-20240101-120000",
      "size": "1.2MB",
      "created_at": "2024-01-01T12:00:00Z"
    }
  ]
}
```

### Restore Backup
```http
POST /api/v1/backup/{backup_id}/restore
```

**Response:**
```json
{
  "status": "success",
  "message": "Backup restored successfully"
}
```

## Error Responses

All API endpoints return appropriate HTTP status codes and error messages:

### 400 Bad Request
```json
{
  "error": "bad_request",
  "message": "Invalid request parameters",
  "details": {
    "field": "domain",
    "issue": "Domain is required"
  }
}
```

### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "message": "Authentication required"
}
```

### 403 Forbidden
```json
{
  "error": "forbidden",
  "message": "Insufficient permissions"
}
```

### 404 Not Found
```json
{
  "error": "not_found",
  "message": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "internal_error",
  "message": "Internal server error",
  "request_id": "req-123456"
}
```

## Rate Limiting

API endpoints are rate limited to prevent abuse:

- **Authentication endpoints**: 5 requests per minute
- **Configuration endpoints**: 10 requests per minute
- **Monitoring endpoints**: 60 requests per minute
- **Other endpoints**: 30 requests per minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1640995200
```

## SDK Examples

### Python SDK
```python
import sslcat

client = sslcat.Client(
    base_url="http://localhost:8080/api/v1",
    api_key="your-api-key"
)

# Get configuration
config = client.get_config()

# Create proxy rule
rule = client.create_proxy_rule({
    "domain": "api.example.com",
    "target": "http://localhost:3000",
    "ssl": True
})

# Get metrics
metrics = client.get_metrics()
```

### Node.js SDK
```javascript
const SSLcat = require('sslcat-sdk');

const client = new SSLcat({
  baseUrl: 'http://localhost:8080/api/v1',
  apiKey: 'your-api-key'
});

// Get configuration
const config = await client.getConfig();

// Create proxy rule
const rule = await client.createProxyRule({
  domain: 'api.example.com',
  target: 'http://localhost:3000',
  ssl: true
});

// Get metrics
const metrics = await client.getMetrics();
```

### Go SDK
```go
package main

import (
    "github.com/xurenlu/sslcat-sdk-go"
)

func main() {
    client := sslcat.NewClient(
        "http://localhost:8080/api/v1",
        "your-api-key",
    )
    
    // Get configuration
    config, err := client.GetConfig()
    
    // Create proxy rule
    rule, err := client.CreateProxyRule(sslcat.ProxyRule{
        Domain: "api.example.com",
        Target: "http://localhost:3000",
        SSL: true,
    })
    
    // Get metrics
    metrics, err := client.GetMetrics()
}
```

## Webhook Integration

### Configure Webhook
```http
POST /api/v1/webhooks
Content-Type: application/json
```

**Request Body:**
```json
{
  "url": "https://your-app.com/webhook",
  "events": ["config_changed", "certificate_expired"],
  "secret": "webhook-secret"
}
```

### Webhook Payload Example
```json
{
  "event": "config_changed",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "change_type": "proxy_rule_added",
    "rule_id": "rule-1",
    "domain": "example.com"
  }
}
```

## Related Documentation

- [Web Interface](../administration/web-interface.md)
- [Configuration Guide](../configuration/basic.md)
- [Monitoring](../features/monitoring.md)
- [Troubleshooting](../troubleshooting/common-issues.md)

---

*This API reference provides comprehensive documentation for all SSLcat API endpoints. For additional examples and use cases, see the integration guides.*