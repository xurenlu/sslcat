# Post-Installation Configuration

This guide covers the essential steps to configure SSLcat after installation, including initial setup, security configuration, and basic proxy rules.

## 🔧 Initial Configuration

### 1. Access Web Interface

After installation, access the web management interface:

```bash
# Access the web interface
http://your-server-ip/sslcat-panel
```

**Default Credentials:**
- Username: `admin`
- Password: `admin*9527`

### 2. First Login Process

1. **Login with Default Credentials**
   - Use the default username and password
   - The system will force you to change the password

2. **Change Admin Password**
   - Enter a strong new password
   - Confirm the password
   - The system will update the password file

3. **Customize Panel Path**
   - Choose a custom path for the admin panel
   - This enhances security by hiding the default path
   - Remember the new path for future access

## ⚙️ Basic Configuration

### 1. SSL Certificate Setup

Configure SSL certificate management:

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

**Configuration Options:**
- `email`: Your email for Let's Encrypt notifications
- `staging`: Set to `true` for testing (uses staging certificates)
- `auto_renew`: Enable automatic certificate renewal
- `certificate_dir`: Directory for certificate files
- `key_dir`: Directory for private key files

### 2. Server Configuration

Configure the server settings:

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
- `host`: Server binding address (0.0.0.0 for all interfaces)
- `port`: HTTPS port (443 for standard HTTPS)
- `debug`: Enable debug logging
- `max_connections`: Maximum concurrent connections
- `read_timeout_sec`: Request read timeout
- `write_timeout_sec`: Response write timeout
- `idle_timeout_sec`: Connection idle timeout

### 3. Admin Configuration

Configure admin settings:

```json
{
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": false,
    "session_timeout": "24h",
    "max_login_attempts": 3,
    "lockout_duration": "15m"
  }
}
```

**Configuration Options:**
- `username`: Admin username
- `password_file`: Path to password file
- `first_run`: Set to false after initial setup
- `session_timeout`: Admin session timeout
- `max_login_attempts`: Maximum failed login attempts
- `lockout_duration`: Account lockout duration

## 🔒 Security Configuration

### 1. Basic Security Settings

Configure basic security options:

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
    }
  }
}
```

**Security Options:**
- `max_attempts`: Failed login attempts before blocking
- `block_duration`: IP block duration
- `max_attempts_5min`: Maximum attempts in 5 minutes
- `ip_whitelist`: List of trusted IP addresses
- `ip_blacklist`: List of blocked IP addresses
- `user_agent_validation`: Validate user agents
- `rate_limiting`: Configure rate limiting

### 2. Firewall Configuration

Configure firewall rules:

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8080/tcp  # Admin interface (optional)

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

### 3. SSL/TLS Configuration

Configure SSL/TLS settings:

```json
{
  "ssl": {
    "min_tls_version": "1.2",
    "cipher_suites": [
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ],
    "hsts": {
      "enabled": true,
      "max_age": 31536000,
      "include_subdomains": true
    }
  }
}
```

## 🌐 Proxy Configuration

### 1. Basic Proxy Rule

Create your first proxy rule:

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "ssl_only": true,
        "path_prefix": "",
        "health_check": {
          "enabled": true,
          "path": "/health",
          "interval": "30s",
          "timeout": "5s"
        }
      }
    ]
  }
}
```

**Proxy Rule Options:**
- `domain`: Domain name to proxy
- `target`: Backend server IP or hostname
- `port`: Backend server port
- `enabled`: Enable/disable the rule
- `ssl_only`: Require HTTPS connections
- `path_prefix`: URL path prefix
- `health_check`: Backend health monitoring

### 2. Load Balancing

Configure load balancing for multiple backends:

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "targets": [
          {"host": "127.0.0.1", "port": 3001, "weight": 1},
          {"host": "127.0.0.1", "port": 3002, "weight": 1},
          {"host": "127.0.0.1", "port": 3003, "weight": 2}
        ],
        "enabled": true,
        "ssl_only": true,
        "load_balancing": {
          "method": "weighted_round_robin",
          "health_check": {
            "enabled": true,
            "path": "/health",
            "interval": "30s"
          }
        }
      }
    ]
  }
}
```

### 3. WebSocket Support

Configure WebSocket proxying:

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "ws.example.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "websocket": true,
        "websocket_timeout": "300s"
      }
    ]
  }
}
```

## 📊 Monitoring Configuration

### 1. Logging Configuration

Configure logging settings:

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
      "max_files": 10
    }
  }
}
```

### 2. Statistics Configuration

Configure statistics collection:

```json
{
  "statistics": {
    "enabled": true,
    "retention_days": 30,
    "metrics": {
      "requests": true,
      "response_times": true,
      "errors": true,
      "certificates": true
    }
  }
}
```

## 🔄 Service Management

### 1. Start SSLcat Service

```bash
# Start the service
sudo systemctl start sslcat

# Enable auto-start on boot
sudo systemctl enable sslcat

# Check service status
sudo systemctl status sslcat
```

### 2. Configuration Reload

```bash
# Reload configuration without restart
sudo systemctl reload sslcat

# Or send SIGHUP signal
sudo kill -HUP $(pgrep sslcat)
```

### 3. Service Monitoring

```bash
# View real-time logs
sudo journalctl -u sslcat -f

# View error logs
sudo journalctl -u sslcat -p err

# Check service health
sudo systemctl is-active sslcat
sudo systemctl is-enabled sslcat
```

## 🧪 Testing Configuration

### 1. Test SSL Certificate

```bash
# Test SSL certificate
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Check certificate details
openssl x509 -in /opt/sslcat/certs/your-domain.com.crt -text -noout
```

### 2. Test Proxy Functionality

```bash
# Test HTTP proxy
curl -H "Host: your-domain.com" http://your-server-ip/

# Test HTTPS proxy
curl -H "Host: your-domain.com" https://your-domain.com/
```

### 3. Test Web Interface

```bash
# Test admin interface
curl -I http://your-server-ip/sslcat-panel

# Test API endpoints
curl -X GET http://your-server-ip/sslcat-panel/api/status
```

## 🔧 Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check configuration syntax
sslcat --config /etc/sslcat/sslcat.conf --log-level debug

# Check port availability
sudo netstat -tlnp | grep :443
```

**SSL certificate issues:**
```bash
# Check certificate status
sudo journalctl -u sslcat | grep -i certificate

# Test Let's Encrypt connectivity
curl -I https://acme-v02.api.letsencrypt.org/directory
```

**Proxy not working:**
```bash
# Check proxy rules
curl -X GET http://localhost:18080/sslcat-panel/api/proxy/rules

# Test backend connectivity
curl -I http://127.0.0.1:8080/health
```

### Configuration Validation

```bash
# Validate configuration file
sslcat --config /etc/sslcat/sslcat.conf --validate

# Test configuration without starting
sslcat --config /etc/sslcat/sslcat.conf --dry-run
```

## 📋 Post-Installation Checklist

### Basic Setup
- [ ] SSLcat service is running
- [ ] Web interface is accessible
- [ ] Admin password has been changed
- [ ] SSL email is configured
- [ ] Basic proxy rule is created

### Security
- [ ] Firewall rules are configured
- [ ] Security settings are enabled
- [ ] IP whitelist/blacklist is configured
- [ ] Rate limiting is enabled

### Monitoring
- [ ] Logging is configured
- [ ] Statistics collection is enabled
- [ ] Health checks are working
- [ ] Monitoring alerts are set up

### Testing
- [ ] SSL certificates are working
- [ ] Proxy rules are functional
- [ ] Web interface is responsive
- [ ] API endpoints are accessible

## 🚀 Next Steps

After completing the post-installation configuration:

1. **[Advanced Configuration](configuration/advanced.md)** - Configure advanced features
2. **[Security Hardening](configuration/security.md)** - Enhance security settings
3. **[Monitoring Setup](administration/monitoring.md)** - Set up comprehensive monitoring
4. **[Backup Configuration](administration/backup.md)** - Configure backup and recovery

---

*Configuration complete? Check out our [Advanced Configuration Guide](configuration/advanced.md) for more detailed settings.*
