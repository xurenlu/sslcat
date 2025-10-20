# Quick Start Guide

Get SSLcat up and running in minutes with this quick start guide. This guide will walk you through the essential steps to install, configure, and start using SSLcat.

## 🚀 One-Minute Setup

### Prerequisites
- Linux server with root access
- Domain name pointing to your server
- Ports 80 and 443 available

### Step 1: Download and Install

```bash
# Download and run the installation script
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh | sudo bash

# Or for Chinese users (faster download)
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v latest
```

### Step 2: Basic Configuration

```bash
# Edit the configuration file
sudo nano /etc/sslcat/sslcat.conf
```

Add your basic configuration:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false
  },
  "ssl": {
    "email": "your-email@example.com",
    "staging": false,
    "auto_renew": true
  },
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": true
  },
  "proxy": {
    "rules": [
      {
        "domain": "your-domain.com",
        "target": "127.0.0.1",
        "port": 8080,
        "enabled": true,
        "ssl_only": true
      }
    ]
  }
}
```

### Step 3: Start SSLcat

```bash
# Start the service
sudo systemctl start sslcat

# Enable auto-start on boot
sudo systemctl enable sslcat

# Check status
sudo systemctl status sslcat
```

### Step 4: Access Web Interface

1. Open your browser and navigate to: `http://your-server-ip/sslcat-panel`
2. Login with default credentials:
   - Username: `admin`
   - Password: `admin*9527`
3. Change the admin password and customize the panel path
4. Configure your first proxy rule

## 🐳 Docker Quick Start

If you prefer Docker:

```bash
# Clone the repository
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# Start with Docker Compose
docker-compose up -d

# Access the web interface
open http://localhost:8080/sslcat-panel
```

## 📱 macOS Development Setup

For local development on macOS:

```bash
# Download the macOS binary
curl -fsSL https://cdn.wxside.com/xurenlu/sslcat/releases/download/v1.3.3/sslcat_v1.3.3_darwin-arm64.tar.gz -o sslcat.tgz

# Extract and install
tar -xzf sslcat.tgz
sudo install -m 0755 sslcat /usr/local/bin/sslcat

# Create a basic config
cat > sslcat.conf << EOF
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "debug": true
  },
  "ssl": {
    "email": "your-email@example.com",
    "staging": true,
    "auto_renew": false
  },
  "admin": {
    "username": "admin",
    "password_file": "./data/admin.pass",
    "first_run": true
  }
}
EOF

# Start SSLcat
sslcat --config sslcat.conf --port 8080
```

Access the web interface at: `http://localhost:8080/sslcat-panel`

## ⚙️ Initial Configuration

### 1. SSL Certificate Setup

After starting SSLcat, configure SSL certificates:

1. Go to the **SSL Certificates** section in the web interface
2. Add your domain name
3. SSLcat will automatically request a certificate from Let's Encrypt
4. Monitor the certificate status

### 2. Proxy Rules Configuration

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
2. Set up:
   - **Max Login Attempts**: 3
   - **Block Duration**: 5 minutes
   - **IP Whitelist**: Add trusted IPs if needed
3. Save the configuration

## 🔧 Command Line Usage

### Basic Commands

```bash
# Start SSLcat with custom config
sslcat --config /path/to/config.json --port 443

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

## 🌐 Web Interface Overview

### Dashboard
- **System Status**: Service health and statistics
- **Active Connections**: Current proxy connections
- **Certificate Status**: SSL certificate information
- **Security Events**: Recent security events

### Proxy Management
- **Rule Configuration**: Add, edit, and delete proxy rules
- **Domain Management**: Manage domain configurations
- **Backend Health**: Monitor backend server health

### SSL Certificate Management
- **Certificate List**: View all certificates
- **Auto-renewal**: Configure automatic renewal
- **Certificate Details**: View certificate information

### Security
- **Access Control**: Configure security policies
- **Blocked IPs**: View and manage blocked IPs
- **Audit Logs**: Security event logs

## 🚨 Troubleshooting

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
- Verify email address in configuration

**Web interface not accessible:**
- Check if service is running: `sudo systemctl status sslcat`
- Verify firewall settings
- Check logs: `sudo journalctl -u sslcat -f`

### Getting Help

- **Logs**: `sudo journalctl -u sslcat -f`
- **Configuration**: Check `/etc/sslcat/sslcat.conf`
- **Documentation**: [Full Documentation](../README.md)
- **Issues**: [GitHub Issues](https://github.com/xurenlu/sslcat/issues)

## 📚 Next Steps

Now that you have SSLcat running, explore these topics:

1. **[Basic Configuration](configuration/basic.md)** - Learn about essential configuration options
2. **[Advanced Features](configuration/advanced.md)** - Explore advanced features and capabilities
3. **[Security Configuration](configuration/security.md)** - Secure your SSLcat installation
4. **[Monitoring](administration/monitoring.md)** - Set up monitoring and alerting
5. **[Troubleshooting](troubleshooting/common-issues.md)** - Common issues and solutions

## 🎉 Congratulations!

You've successfully installed and configured SSLcat! Your SSL proxy server is now ready to handle SSL termination, certificate management, and domain forwarding.

---

*Need help? Check out our [troubleshooting guide](troubleshooting/common-issues.md) or [join the community](https://github.com/xurenlu/sslcat/discussions).*
