# SSLcat - SSL Proxy Server

SSLcat is a powerful SSL proxy server that supports automatic certificate management, domain forwarding, security protection, and web management panel.

## 📚 Documentation

- 📑 [Complete Documentation Index](DOCS.md) - Index and navigation for all documents
- 📖 [Project Summary (Chinese)](项目总结.md) - Detailed feature introduction and technical documentation
- 🚀 [Deployment Guide (English)](DEPLOYMENT_EN.md) - Complete deployment and operations documentation
- 🚀 [部署指南 (中文)](DEPLOYMENT.md) - Chinese deployment guide

### 🌍 Multilingual Versions
- 🇨🇳 [中文 README](README.md) - Chinese version
- 🇯🇵 [日本語 README](README_JA.md) - Japanese version  
- 🇪🇸 [Español README](README_ES.md) - Spanish version
- 🇫🇷 [Français README](README_FR.md) - French version
- 🇷🇺 [Русский README](README_RU.md) - Russian version

## Features

### 🌏 Network Optimization for China
- **CDN Proxy Optimization**: Uses [CDNProxy](https://cdnproxy.some.im/docs) service
- **Access Acceleration**: Solves jsdelivr CDN access issues in mainland China
- **Stability**: Ensures stable resource loading through proxy service

### 🔒 Automatic SSL Certificate Management
- Automatically obtain SSL certificates from Let's Encrypt
- Support for automatic certificate renewal
- Support for staging and production environments
- Certificate caching and performance optimization

### 🔄 Smart Domain Forwarding
- Intelligent proxy forwarding based on domain names
- Support for HTTP/HTTPS protocols
- WebSocket proxy support
- Connection pooling and load balancing

### 🛡️ Security Protection
- IP blocking and access control
- Anti-brute force protection
- User-Agent validation
- Access logging

### 🎛️ Web Management Panel
- Intuitive web interface
- Real-time monitoring and statistics
- Proxy rule management
- SSL certificate management
- Security configuration

### 🔄 Graceful Restart
- Zero-downtime restart
- Connection preservation and state recovery
- Graceful shutdown mechanism

## System Requirements

- Linux system (Ubuntu/Debian/CentOS/RHEL)
- Go 1.21 or higher
- Root privileges
- Ports 80 and 443 available

## 📥 Get Source Code

### GitHub Repository

Project hosted on GitHub: **[https://github.com/xurenlu/sslcat](https://github.com/xurenlu/sslcat)**

### Latest Version Download

```bash
# Clone latest source code
git clone https://github.com/xurenlu/sslcat.git
cd withssl

# Or download specific version (recommended)
wget https://github.com/xurenlu/sslcat/archive/refs/heads/main.zip
unzip main.zip
cd withssl-main
```

## 🚀 Quick Installation

### Automatic Installation (Recommended)

```bash
# Download installation script from GitHub
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh -o install.sh

# Run installation script
sudo bash install.sh
```

### Embedded Deployment (Single File)

```bash
# Generate embedded deployment package
./deploy-embedded.sh

# Or generate Linux version
./deploy-embedded.sh linux

# Then upload deploy/ directory to server
```

### Manual Installation

1. **Install Dependencies**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y curl wget git build-essential ca-certificates certbot

# CentOS/RHEL
sudo yum update -y
sudo yum install -y curl wget git gcc gcc-c++ make ca-certificates certbot
```

2. **Install Go**
```bash
# Download and install Go 1.21
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

3. **Compile SSLcat**
```bash
git clone https://github.com/xurenlu/sslcat.git
cd withssl
go mod download
go build -o withssl main.go
```

4. **Create User and Directories**
```bash
sudo useradd -r -s /bin/false withssl
sudo mkdir -p /etc/withssl /var/lib/withssl/{certs,keys,logs}
sudo chown -R withssl:withssl /var/lib/withssl
```

5. **Configure and Start**
```bash
sudo cp withssl /opt/withssl/
sudo cp withssl.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable withssl
sudo systemctl start withssl
```

## Configuration

### Configuration File Location
- Main config file: `/etc/withssl/withssl.conf`
- Certificate directory: `/var/lib/withssl/certs`
- Key directory: `/var/lib/withssl/keys`
- Log directory: `/var/lib/withssl/logs`

### Basic Configuration

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
    "password": "admin*9527",
    "first_run": true
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
    "block_duration": "1m",
    "max_attempts_5min": 10
  },
  "admin_prefix": "/withssl-panel"
}
```

## Usage

### Start Service
```bash
sudo systemctl start withssl
```

### Stop Service
```bash
sudo systemctl stop withssl
```

### Restart Service
```bash
sudo systemctl restart withssl
```

### Graceful Restart
```bash
sudo systemctl reload withssl
# or send SIGHUP signal
sudo kill -HUP $(pgrep withssl)
```

### View Logs
```bash
# View service status
sudo systemctl status withssl

# View real-time logs
sudo journalctl -u withssl -f

# View error logs
sudo journalctl -u withssl -p err
```

## Web Management Panel

### Access Management Panel
1. Open browser and visit: `https://your-domain/withssl-panel`
2. Login with default credentials:
   - Username: `admin`
   - Password: `admin*9527`
3. Change password after first login

### Management Panel Features
- **Dashboard**: View system status and statistics
- **Proxy Configuration**: Manage domain forwarding rules
- **SSL Certificates**: View and manage SSL certificates
- **Security Settings**: Configure security policies and view blocked IPs
- **System Settings**: Modify system configuration

## Proxy Configuration

### Add Proxy Rule
1. Login to management panel
2. Go to "Proxy Configuration" page
3. Click "New Proxy Rule"
4. Fill in configuration:
   - Domain: Domain to proxy
   - Target: Backend server IP or domain
   - Port: Backend service port
   - Enabled: Whether to enable this rule
   - SSL Only: Whether to allow HTTPS access only

### Proxy Rule Example
```json
{
  "proxy": {
    "rules": [
      {
        "domain": "api.example.com",
        "target": "127.0.0.1",
        "port": 3000,
        "enabled": true,
        "ssl_only": true
      },
      {
        "domain": "app.example.com",
        "target": "192.168.1.100",
        "port": 8080,
        "enabled": true,
        "ssl_only": false
      }
    ]
  }
}
```

## SSL Certificate Management

### Automatic Certificate Acquisition
SSLcat automatically obtains SSL certificates for configured domains without manual intervention.

### Certificate Renewal
Certificates are automatically renewed 30 days before expiration, or can be manually triggered.

### Certificate Storage
- Certificate file: `/var/lib/withssl/certs/domain.crt`
- Private key file: `/var/lib/withssl/keys/domain.key`

## Security Features

### IP Blocking Mechanism
- Automatic blocking after 3 failed attempts in 1 minute
- Automatic blocking after 10 failed attempts in 5 minutes
- Configurable blocking duration
- Support for manual unblocking

### Access Control
- User-Agent validation
- Reject empty User-Agent access
- Reject uncommon browser User-Agent access

### Unblock IPs
```bash
# Delete blocking file and restart service
sudo rm /var/lib/withssl/withssl.block
sudo systemctl restart withssl
```

## Command Line Arguments

```bash
withssl --help
```

Available options:
- `--config`: Configuration file path (default: "/etc/withssl/withssl.conf")
- `--admin-prefix`: Management panel path prefix (default: "/withssl-panel")
- `--email`: SSL certificate email
- `--staging`: Use Let's Encrypt staging environment
- `--port`: Listen port (default: 443)
- `--host`: Listen address (default: "0.0.0.0")
- `--log-level`: Log level (default: "info")
- `--version`: Show version information

## Network Optimization

### China Mainland User Optimization

SSLcat has been optimized for China mainland network environment, using [CDNProxy](https://cdnproxy.some.im/docs) service to solve jsdelivr CDN access issues.

#### CDN Proxy Usage
- **Original address**: `https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`
- **Proxy address**: `https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css`

#### Resource Files Involved
- Bootstrap 5.1.3 CSS
- Bootstrap Icons 1.7.2
- Bootstrap 5.1.3 JavaScript
- Axios JavaScript library

#### Access Control
According to CDNProxy documentation, the service implements access control policies. If access is blocked, it's usually because the request's Referer domain is not in the whitelist. Contact the service administrator to add your domain to the whitelist if needed.

## Deployment Options

### 1. System Service Deployment
Use the provided `install.sh` script to automatically install as a system service.

### 2. Docker Deployment
```bash
docker build -t withssl .
docker run -d -p 80:80 -p 443:443 -v $(pwd)/config:/etc/withssl withssl
```

### 3. Docker Compose Deployment
```bash
docker-compose up -d
```

## Development Guide

### Project Structure
```
withssl/
├── main.go                 # Main program entry
├── go.mod                  # Go module file
├── internal/               # Internal packages
│   ├── config/            # Configuration management
│   ├── logger/            # Log management
│   ├── ssl/               # SSL certificate management
│   ├── proxy/             # Proxy management
│   ├── security/          # Security management
│   ├── web/               # Web server
│   └── graceful/          # Graceful restart
├── web/                   # Web resources
│   ├── templates/         # HTML templates
│   └── static/            # Static resources
├── install.sh             # Installation script
├── deploy.sh              # Deployment script
├── DEPLOYMENT.md          # Deployment guide
└── README.md              # Documentation
```

### Development Environment Setup
```bash
# Clone project
git clone https://github.com/xurenlu/sslcat.git
cd withssl

# Install dependencies
go mod download

# Run development server
go run main.go --config withssl.conf --log-level debug
```

### Cross-Platform Compilation

SSLcat supports cross-compilation for multiple platforms:

```bash
# Linux 64-bit (recommended for servers)
make build-linux

# All platforms
make build-all

# Manual compilation
GOOS=linux GOARCH=amd64 go build -o withssl-linux main.go
```

## Performance Optimization

### System Optimization
```bash
# Increase file descriptor limit
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize network parameters
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### Configuration Optimization
```json
{
  "server": {
    "debug": false
  },
  "security": {
    "max_attempts": 5,
    "block_duration": "5m"
  }
}
```

## Troubleshooting

### Common Issues

1. **Service startup failure**
   ```bash
   # Check configuration file syntax
   sudo withssl --config /etc/withssl/withssl.conf --log-level debug
   
   # Check port usage
   sudo netstat -tlnp | grep :443
   ```

2. **SSL certificate acquisition failure**
   - Ensure domain resolution is correct
   - Ensure port 80 is accessible
   - Check firewall settings
   - Use staging environment for testing

3. **Proxy forwarding failure**
   - Check if target server is reachable
   - Verify port is correct
   - Check access logs

4. **Management panel inaccessible**
   - Check firewall settings
   - Verify SSL certificate is valid
   - Check service logs

### Log Analysis
```bash
# View detailed logs
sudo journalctl -u withssl -f --no-pager

# Filter error logs
sudo journalctl -u withssl -p err --since "1 hour ago"

# View logs for specific time period
sudo journalctl -u withssl --since "2024-01-01 00:00:00" --until "2024-01-01 23:59:59"
```

## License

This project uses the MIT license. See [LICENSE](LICENSE) file for details.

## Support

If you encounter issues or have suggestions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Search [Issues](https://github.com/xurenlu/sslcat/issues)
3. Create a new Issue
4. Contact maintainers

## Changelog

### v1.0.0 (2024-01-01)
- Initial release
- Support for automatic SSL certificate management
- Support for domain proxy forwarding
- Support for web management panel
- Support for security protection mechanisms
- Support for graceful restart functionality
- Optimized for China mainland network environment
