# SSLcat - SSL Proxy Server

## ⏱️ Quick Start with SSLcat in 1 Minute

```bash
# 1) macOS local quick test (or download darwin package manually)
curl -fsSL https://sslcat.com/xurenlu/sslcat/releases/download/v1.0.11/sslcat_1.0.11_darwin_arm64.tar.gz -o sslcat.tgz
tar -xzf sslcat.tgz && sudo install -m 0755 sslcat /usr/local/bin/sslcat
sslcat --config sslcat.conf --port 8080
# Browser access: http://localhost:8080/sslcat-panel/
# First login: admin / admin*9527
# ⚠️ First login will force: 1) Password change 2) Custom admin panel path
# Please remember the new admin panel path!

# 2) Optional: Docker Compose one-click start
docker compose up -d
```

SSLcat is a powerful SSL proxy server that supports automatic certificate management, domain forwarding, security protection, and web management panel, with HTTP/3 (QUIC) and HTTP/2 protocol support (automatic negotiation, backward compatible).

## 📚 Documentation Navigation

- 📑 [Complete Documentation Index](DOCS.md) - Index and navigation for all documents
- 📖 [Project Summary](项目总结.md) - Detailed feature introduction and technical documentation
- 🚀 [Deployment Guide (Chinese)](DEPLOYMENT.md) - Complete deployment and operations documentation
- 🚀 [Deployment Guide (English)](DEPLOYMENT_EN.md) - English deployment guide

### 🌍 Multilingual Versions
- 🇨🇳 [中文 README](README.md) - Chinese version
- 🇯🇵 [日本語 README](README_JA.md) - Japanese version  
- 🇪🇸 [Español README](README_ES.md) - Spanish version
- 🇫🇷 [Français README](README_FR.md) - French version
- 🇷🇺 [Русский README](README_RU.md) - Russian version

## Features

### 🌏 Network Optimization for China
- **CDN Proxy Optimization**: Uses [CDNProxy](https://cdnproxy.some.im/docs) proxy service
- **Access Acceleration**: Solves jsdelivr CDN access issues in mainland China
- **Stability**: Ensures stable resource loading through proxy service

### 🔒 Automatic SSL Certificate Management
- Automatically obtain SSL certificates from Let's Encrypt
- Support for automatic certificate renewal
- Support for staging and production environments
- Certificate caching and performance optimization
- **Bulk Certificate Operations**: One-click download/import of all certificates (ZIP format)

### 🔄 Smart Domain Forwarding
- Intelligent proxy forwarding based on domain names
- Support for HTTP/HTTPS protocols
- WebSocket proxy support
- Connection pooling and load balancing

### 🛡️ Security Protection Mechanisms
- IP blocking and access control
- Anti-brute force protection
- User-Agent validation
- Access logging
- **TLS Client Fingerprinting**: Client identification based on ClientHello characteristics
- **Production Environment Optimization**: More lenient security thresholds for high-traffic scenarios

### 🎛️ Web Management Panel
- Intuitive web interface
- Real-time monitoring and statistics
- Proxy rule management
- SSL certificate management
- Security configuration
- **API Token Management**: Read-only/read-write API access control
- **TLS Fingerprint Statistics**: Real-time client fingerprint analysis data

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
cd sslcat

# Or download specific version (recommended)
wget https://github.com/xurenlu/sslcat/archive/refs/heads/main.zip
unzip main.zip
cd sslcat-main
```

## 🚀 Installation and Deployment

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
cd sslcat
go mod download
go build -o sslcat main.go
```

4. **Create User and Directories**
```bash
sudo useradd -r -s /bin/false sslcat
sudo mkdir -p /etc/sslcat /var/lib/sslcat/{certs,keys,logs}
sudo chown -R sslcat:sslcat /var/lib/sslcat
```

5. **Configure and Start**
```bash
sudo cp sslcat /opt/sslcat/
sudo cp sslcat.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sslcat
sudo systemctl start sslcat
```

## Configuration

### Configuration File Location
- Main config file: `/etc/sslcat/sslcat.conf`
- Certificate directory: `/var/lib/sslcat/certs`
- Key directory: `/var/lib/sslcat/keys`
- Log directory: `/var/lib/sslcat/logs`

### Basic Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 443
  debug: false

ssl:
  email: "your-email@example.com"  # SSL certificate email
  staging: false                   # Whether to use staging environment
  auto_renew: true                 # Auto renewal

admin:
  username: "admin"
  password_file: "/var/lib/sslcat/admin.pass"     # Password saved in this file, sslcat.conf doesn't persist password
  first_run: true

proxy:
  rules:
    - domain: "example.com"
      target: "127.0.0.1"
      port: 8080
      enabled: true
      ssl_only: true

security:
  max_attempts: 3                  # Max failed attempts in 1 minute
  block_duration: "1m"             # Block duration
  max_attempts_5min: 10            # Max failed attempts in 5 minutes

admin_prefix: "/sslcat-panel"     # Management panel path prefix
```

### Password Recovery (Emergency Recovery)

SSLcat uses "marker file + first-time forced password change" security strategy:

- Marker file: `admin.password_file` (default `./data/admin.pass`). File saves current admin password with 0600 permissions.
- First login: If marker file doesn't exist, or file content is still default password `admin*9527`, admin will be forced to "change password" page after successful login to set new password and write to marker file.

Password recovery steps:

1. Stop service (or keep running, recommend stopping).
2. Delete marker file (if path changed, delete according to actual config path):
   ```bash
   rm -f ./data/admin.pass
   ```
3. Restart service, login with default account (admin / admin*9527).
4. System will force enter "change password" page, set new password to restore normal operation.

Note: For security reasons, `sslcat.conf` no longer persists `admin.password` plaintext when saving; runtime actual password uses `admin.password_file` as standard.

## Usage

### Start Service
```bash
sudo systemctl start sslcat
```

### Stop Service
```bash
sudo systemctl stop sslcat
```

### Restart Service
```bash
sudo systemctl restart sslcat
```

### Graceful Restart
```bash
sudo systemctl reload sslcat
# or send SIGHUP signal
sudo kill -HUP $(pgrep sslcat)
```

### View Logs
```bash
# View service status
sudo systemctl status sslcat

# View real-time logs
sudo journalctl -u sslcat -f

# View error logs
sudo journalctl -u sslcat -p err
```

## Web Management Panel

### Access Management Panel

**⚠️ Important: Initial Access Method**

Since the system doesn't have SSL certificates when first installed, please use the following method for initial access:

1. **First Access** (using server IP address):
   ```
   http://YOUR_SERVER_IP/sslcat-panel
   ```
   Note: Use `http://` (not https) because there are no SSL certificates yet

2. **After configuring domain and obtaining certificates**:
   ```
   https://your-domain/your-custom-panel-path
   ```

**Login Process:**
1. Login with default credentials:
   - Username: `admin`
   - Password: `admin*9527`
2. First login will force:
   - Change administrator password
   - Customize admin panel access path (for security)
3. **Please remember the new admin panel path!** The system will automatically redirect to the new path

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
```yaml
proxy:
  rules:
    - domain: "api.example.com"
      target: "127.0.0.1"
      port: 3000
      enabled: true
      ssl_only: true
    - domain: "app.example.com"
      target: "192.168.1.100"
      port: 8080
      enabled: true
      ssl_only: false
```

## SSL Certificate Management

### Automatic Certificate Acquisition
SSLcat automatically obtains SSL certificates for configured domains without manual intervention.

### Certificate Renewal
Certificates are automatically renewed 30 days before expiration, or can be manually triggered.

### Certificate Storage
- Certificate file: `/var/lib/sslcat/certs/domain.crt`
- Private key file: `/var/lib/sslcat/keys/domain.key`

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
sudo rm /var/lib/sslcat/sslcat.block
sudo systemctl restart sslcat
```

## Command Line Arguments

```bash
sslcat [options]

Options:
  --config string        Configuration file path (default: "/etc/sslcat/sslcat.conf")
  --admin-prefix string  Management panel path prefix (default: "/sslcat-panel")
  --email string         SSL certificate email
  --staging             Use Let's Encrypt staging environment
  --port int            Listen port (default: 443)
  --host string         Listen address (default: "0.0.0.0")
  --log-level string    Log level (default: "info")
  --version             Show version information
```

## Troubleshooting

### Common Issues

1. **Service startup failure**
   ```bash
   # Check configuration file syntax
   sudo withssl --config /etc/sslcat/withssl.conf --log-level debug
   
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
sudo journalctl -u sslcat -f --no-pager

# Filter error logs
sudo journalctl -u sslcat -p err --since "1 hour ago"

# View logs for specific time period
sudo journalctl -u sslcat --since "2024-01-01 00:00:00" --until "2024-01-01 23:59:59"
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
```yaml
server:
  # Enable debug mode for performance analysis
  debug: false
  
proxy:
  # Configure reasonable number of proxy rules
  rules: []
  
security:
  # Adjust security parameters
  max_attempts: 5
  block_duration: "5m"
```

## Network Optimization

### China Mainland User Optimization

SSLcat has been optimized for China mainland network environment, using [CDNProxy](https://cdnproxy.some.im/docs) proxy service to solve jsdelivr CDN access issues.

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

## Development Guide

### Project Structure
```
sslcat/
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
└── README.md              # Documentation
```

### Development Environment Setup
```bash
# Clone project
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# Install dependencies
go mod download

# Run development server
go run main.go --config sslcat.conf --log-level debug
```

### Contributing Guide
1. Fork project
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## License

This project uses the MIT license. See [LICENSE](LICENSE) file for details.

## Support

If you encounter issues or have suggestions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Search [Issues](https://github.com/xurenlu/sslcat/issues)
3. Create a new Issue
4. Contact maintainers

## Changelog

For complete version update history, please refer to: **[CHANGELOG.md](CHANGELOG.md)**

### Latest Version v1.0.11 (2025-01-03)
- 🎉 Complete multilingual support (Chinese, English, Japanese, Spanish, French, Russian)
- 🔒 Enhanced security settings: First login requires admin panel path configuration
- 📚 Documentation structure optimization and user experience improvements
- 🔧 Unified version management and build optimization