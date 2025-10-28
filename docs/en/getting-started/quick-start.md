# Quick Start Guide

Get SSLcat running in 5 minutes with this quick start guide.

## Prerequisites

- Linux server with root access
- Domain name pointing to your server
- Ports 80 and 443 available

## Installation

### Step 1: Download and Install

```bash
# Download installation package
curl -L https://github.com/xurenlu/sslcat/releases/download/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -o sslcat.tar.gz

# CDN mirror download (faster for Chinese users)
curl -L https://cdn.wxside.com/xurenlu/sslcat/releases/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -o sslcat.tar.gz

# Extract and install
tar -xzf sslcat.tar.gz
sudo ./install-sslcat.sh
```

### Step 2: Basic Configuration

```bash
# Edit configuration file
sudo nano /etc/sslcat/sslcat.conf
```

Add your basic configuration:

```yaml
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false

proxy:
  rules:
    - domain: "your-domain.com"
      target: "http://localhost:8080"
      ssl: true

ssl:
  certificates:
    - domain: "your-domain.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true

monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
```

### Step 3: Start SSLcat

```bash
# Start service
sudo systemctl start sslcat

# Enable auto-start
sudo systemctl enable sslcat

# Check status
sudo systemctl status sslcat
```

### Step 4: Access Web Interface

1. Open browser and navigate to: `http://your-server-ip:8080/sslcat-panel`
2. Login with default credentials:
   - Username: `admin`
   - Password: `admin*9527`
3. Change admin password and configure settings
4. Configure your first proxy rule

## Initial Configuration

### 1. SSL Certificate Setup

After starting SSLcat, configure SSL certificates:

1. Go to **SSL Certificates** section in the web interface
2. Add your domain
3. SSLcat will automatically request certificates from Let's Encrypt
4. Monitor certificate status

### 2. Proxy Rule Configuration

Set up your first proxy rule:

1. Navigate to **Proxy Configuration**
2. Click **Add New Rule**
3. Configure:
   - **Domain**: `your-domain.com`
   - **Target**: `127.0.0.1` (or your backend server)
   - **Port**: `8080` (or your application port)
   - **SSL Only**: `true` (recommended)
4. Save and enable the rule

### 3. Security Configuration

Configure basic security settings:

1. Go to **Security Settings**
2. Set:
   - **Max Login Attempts**: 3
   - **Block Duration**: 5 minutes
   - **IP Whitelist**: Add trusted IPs if needed
3. Save configuration

## Command Line Usage

### Basic Commands

```bash
# Start SSLcat with custom configuration
sslcat --config /path/to/config.yaml --port 443

# Start in debug mode
sslcat --config sslcat.conf --log-level debug

# Check version
sslcat --version

# Show help
sslcat --help
```

### Service Management

```bash
# Start service
sudo systemctl start sslcat

# Stop service
sudo systemctl stop sslcat

# Restart service
sudo systemctl restart sslcat

# Check status
sudo systemctl status sslcat

# View logs
sudo journalctl -u sslcat -f
```

## Web Interface Overview

### Dashboard
- **System Status**: Service health and statistics
- **Active Connections**: Current proxy connections
- **Certificate Status**: SSL certificate information
- **Security Events**: Recent security events

### Proxy Management
- **Rule Configuration**: Add, edit and delete proxy rules
- **Domain Management**: Manage domain configurations
- **Backend Health**: Monitor backend server health

### SSL Certificate Management
- **Certificate List**: View all certificates
- **Auto Renewal**: Configure auto-renewal
- **Certificate Details**: View certificate information

### Security
- **Access Control**: Configure security policies
- **Blocked IPs**: View and manage blocked IPs
- **Audit Logs**: Security event logs

## Troubleshooting

### Common Issues

**Service won't start:**
```bash
# Check configuration syntax
sslcat --config /etc/sslcat/sslcat.conf --log-level debug

# Check port availability
sudo netstat -tlnp | grep :443
```

**SSL certificate issues:**
- Ensure domain points to your server
- Check firewall settings (ports 80 and 443)
- Verify email address in configuration file

**Web interface not accessible:**
- Check if service is running: `sudo systemctl status sslcat`
- Verify firewall settings
- Check logs: `sudo journalctl -u sslcat -f`

### Getting Help

- **Logs**: `sudo journalctl -u sslcat -f`
- **Configuration**: Check `/etc/sslcat/sslcat.conf`
- **Documentation**: [Full documentation](../README.md)
- **Issues**: [GitHub Issues](https://github.com/xurenlu/sslcat/issues)

## Next Steps

Now that you have SSLcat running, explore these topics:

1. **[Basic Configuration](configuration/basic.md)** - Learn about basic configuration options
2. **[Advanced Features](configuration/advanced.md)** - Explore advanced features and capabilities
3. **[Security Configuration](configuration/security.md)** - Secure your SSLcat installation
4. **[Monitoring](administration/monitoring.md)** - Set up monitoring and alerts
5. **[Troubleshooting](troubleshooting/common-issues.md)** - Common issues and solutions

## 🎉 Congratulations!

You have successfully installed and configured SSLcat! Your SSL proxy server is now ready to handle SSL termination, certificate management, and domain forwarding.

---

*Need help? Check out our [troubleshooting guide](troubleshooting/common-issues.md) or [join the community](https://github.com/xurenlu/sslcat/discussions).*