# SSLcat Port Configuration

## 📋 Overview

SSLcat v1.3.10-rc1 introduces a new port configuration system that supports two modes: **Standard Mode** and **Custom Mode**. This design allows users to choose the appropriate port configuration for different use cases.

## 🎯 Port Mode Description

### Standard Mode (Recommended)

**Use Cases**: Production environments, HTTPS support required

**Features**:
- Listen on ports 80 and 443
- Automatic SSL certificate application and management
- HTTP to HTTPS automatic redirection
- Full HTTPS functionality support

**Configuration Example**:
```json
{
  "server": {
    "port_mode": "standard",
    "enable_https": true
  }
}
```

### Custom Mode

**Use Cases**: Development environments, internal network deployment, reverse proxy backend

**Features**:
- Listen on a single custom port
- HTTP protocol only
- No automatic SSL certificate application
- Suitable for development and testing

**Configuration Example**:
```json
{
  "server": {
    "port_mode": "custom",
    "custom_port": 18080,
    "enable_https": false
  }
}
```

## 🚀 Usage

### 1. Standard Mode Configuration

For production environments, use standard mode:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "standard",
    "enable_https": true,
    "ssl": {
      "email": "admin@example.com",
      "staging": false,
      "auto_renew": true
    }
  }
}
```

**Features**:
- Automatic SSL certificate application via Let's Encrypt
- HTTP to HTTPS redirection
- Full SSL/TLS support
- Production-ready configuration

### 2. Custom Mode Configuration

For development or internal use:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "custom",
    "custom_port": 18080,
    "enable_https": false
  }
}
```

**Features**:
- Single port configuration
- HTTP only
- Suitable for development
- No SSL certificate management

## 🔧 Configuration Options

### Server Configuration

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `port_mode` | string | Port mode: "standard" or "custom" | "standard" |
| `enable_https` | boolean | Enable HTTPS support | true |
| `custom_port` | integer | Custom port number (custom mode only) | 18080 |

### SSL Configuration (Standard Mode)

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `email` | string | Email for SSL certificate | Required |
| `staging` | boolean | Use Let's Encrypt staging | false |
| `auto_renew` | boolean | Auto-renew certificates | true |

## 📝 Examples

### Production Configuration

```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "standard",
    "enable_https": true
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "http://localhost:3000",
        "ssl": true
      }
    ]
  }
}
```

### Development Configuration

```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "custom",
    "custom_port": 18080,
    "enable_https": false
  },
  "proxy": {
    "rules": [
      {
        "domain": "localhost",
        "target": "http://localhost:3000",
        "ssl": false
      }
    ]
  }
}
```

### Reverse Proxy Backend

```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "custom",
    "custom_port": 18080,
    "enable_https": false
  },
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "http://backend:3000",
        "ssl": false
      }
    ]
  }
}
```

## ⚠️ Important Notes

### Standard Mode
- Requires root privileges to bind to ports 80 and 443
- Automatic SSL certificate management
- HTTP traffic automatically redirected to HTTPS
- Suitable for production environments

### Custom Mode
- No root privileges required
- HTTP protocol only
- No SSL certificate management
- Suitable for development and internal use

## 🔍 Troubleshooting

### Port Binding Issues

**Error**: `bind: address already in use`

**Solution**:
1. Check if another service is using the port:
   ```bash
   sudo netstat -tlnp | grep :80
   sudo netstat -tlnp | grep :443
   ```

2. Stop conflicting services or change ports

### SSL Certificate Issues

**Error**: `failed to obtain certificate`

**Solutions**:
1. Check domain DNS resolution
2. Ensure port 80 is accessible
3. Verify email address is valid
4. Check Let's Encrypt rate limits

### Configuration Validation

```bash
# Validate configuration
sslcat -config sslcat.conf -validate

# Test configuration
sslcat -config sslcat.conf -test
```

## 📚 Related Documentation

- [Basic Configuration](basic.md) - Basic SSLcat configuration
- [Advanced Configuration](advanced.md) - Advanced configuration options
- [Port Configuration Design](port-configuration-design.md) - Port configuration design
- [SSL Certificates](ssl-certificates.md) - SSL certificate management
- [Troubleshooting](../troubleshooting/common-issues.md) - Common issues and solutions
