# SSLcat Deployment Guide

This document provides detailed instructions for deploying SSLcat in different environments.

## 📚 Related Documentation

- 📖 [Main README](README_EN.md) - Detailed usage and configuration guide
- 📋 [Project Summary (Chinese)](项目总结.md) - Detailed feature introduction and technical documentation
- 🇨🇳 [中文部署指南](DEPLOYMENT.md) - Chinese version of this document

## 🎯 Quick Deployment

### Method 1: Using Deployment Script (Recommended)

On Mac/Linux development machine:

```bash
# 1. Build Linux version and create deployment package
./deploy.sh your-server.com root

# 2. Upload to server
scp -r deploy/ root@your-server.com:/tmp/

# 3. Install on server
ssh root@your-server.com 'cd /tmp/deploy && bash deploy-commands.sh'
```

### Method 2: Using Makefile

```bash
# Build Linux version
make build-linux

# Manual upload
scp build/withssl-linux-amd64 root@your-server.com:/opt/sslcat/withssl
scp withssl.conf.example root@your-server.com:/etc/sslcat/withssl.conf
```

## 🔧 Cross-Compilation Guide

### Supported Platforms

SSLcat supports cross-compilation for the following platforms:

| Platform | Architecture | Command | Purpose |
|----------|--------------|---------|---------|
| **Linux** | AMD64 | `make build-linux` | 🎯 **Server Deployment (Recommended)** |
| Linux | ARM64 | `GOOS=linux GOARCH=arm64 go build` | ARM servers |
| macOS | AMD64 | `GOOS=darwin GOARCH=amd64 go build` | Intel Mac |
| macOS | ARM64 | `GOOS=darwin GOARCH=arm64 go build` | M1/M2 Mac |
| Windows | AMD64 | `GOOS=windows GOARCH=amd64 go build` | Windows servers |

### Verify Compilation Results

```bash
# Compile Linux version
GOOS=linux GOARCH=amd64 go build -o withssl-linux main.go

# Verify file type
file withssl-linux
# Output: withssl-linux: ELF 64-bit LSB executable, x86-64...

# Check file size
ls -lh withssl-linux
```

## 📋 Deployment Checklist

### Required Files

```
deploy/
├── withssl                 # Linux 64-bit binary
├── withssl.conf           # Configuration file
├── withssl.service        # systemd service file
└── deploy-commands.sh     # Server-side installation script
```

### Optional Files

```
deploy/
├── install.sh            # Complete installation script
├── README.md             # Documentation
└── ssl-certs/           # Pre-installed certificates (if any)
```

## 🚀 Detailed Deployment Steps

### Step 1: Local Build

```bash
# Method A: Using deployment script
./deploy.sh

# Method B: Manual build
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o withssl main.go
```

### Step 2: Prepare Server

On target server:

```bash
# Create user and directories
sudo useradd -r -s /bin/false withssl
sudo mkdir -p /etc/sslcat /var/lib/sslcat/{certs,keys,logs}
sudo chown -R withssl:withssl /var/lib/sslcat
```

### Step 3: Upload Files

```bash
# Upload binary
scp withssl root@server:/opt/sslcat/
ssh root@server 'chmod +x /opt/sslcat/withssl'

# Upload configuration
scp withssl.conf root@server:/etc/sslcat/
ssh root@server 'chown withssl:withssl /etc/sslcat/withssl.conf'
```

### Step 4: Install System Service

```bash
# Create systemd service file
cat > /etc/systemd/system/withssl.service << 'EOF'
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=withssl
Group=withssl
WorkingDirectory=/opt/sslcat
ExecStart=/opt/sslcat/withssl --config /etc/sslcat/withssl.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable withssl
sudo systemctl start withssl
```

## 🔍 Deployment Verification

### Check Service Status

```bash
# View service status
sudo systemctl status withssl

# View logs
sudo journalctl -u withssl -f

# Check port listening
sudo netstat -tlnp | grep :443
```

### Test Functionality

```bash
# Test management panel
curl -k https://your-domain/sslcat-panel/login

# Test API
curl -k https://your-domain/sslcat-panel/api/stats
```

## 🛠️ Common Deployment Issues

### Issue 1: Binary Cannot Execute

```bash
# Check file permissions
ls -la /opt/sslcat/withssl

# Set execute permissions
sudo chmod +x /opt/sslcat/withssl

# Check file type
file /opt/sslcat/withssl
```

### Issue 2: Permission Issues

```bash
# Check directory permissions
ls -la /var/lib/sslcat
ls -la /etc/sslcat

# Fix permissions
sudo chown -R withssl:withssl /var/lib/sslcat
sudo chown withssl:withssl /etc/sslcat/withssl.conf
```

### Issue 3: Port in Use

```bash
# Check port usage
sudo netstat -tlnp | grep :443

# Modify configuration file port
sudo nano /etc/sslcat/withssl.conf
```

### Issue 4: Firewall Issues

```bash
# Ubuntu/Debian
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

## 🔄 Update Deployment

### Quick Update

```bash
# 1. Compile new version on development machine
GOOS=linux GOARCH=amd64 go build -o withssl main.go

# 2. Upload new version
scp withssl root@server:/opt/sslcat/withssl-new

# 3. Graceful restart
ssh root@server '
  sudo systemctl stop withssl
  sudo mv /opt/sslcat/withssl-new /opt/sslcat/withssl
  sudo chmod +x /opt/sslcat/withssl
  sudo systemctl start withssl
'
```

### Using Graceful Restart

```bash
# Send SIGHUP signal for graceful restart
ssh root@server 'sudo systemctl reload withssl'
```

## 📊 Production Environment Recommendations

### Performance Optimization

```bash
# 1. Increase file descriptor limit
echo "withssl soft nofile 65536" >> /etc/security/limits.conf
echo "withssl hard nofile 65536" >> /etc/security/limits.conf

# 2. Optimize network parameters
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### Monitoring Setup

```bash
# Setup log rotation
cat > /etc/logrotate.d/withssl << 'EOF'
/var/lib/sslcat/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

### Backup Strategy

```bash
# Backup configuration and certificates
tar -czf withssl-backup-$(date +%Y%m%d).tar.gz \
    /etc/sslcat/ \
    /var/lib/sslcat/certs/ \
    /var/lib/sslcat/keys/
```

## 🎯 Summary

| Deployment Method | Use Case | Pros | Cons |
|-------------------|----------|------|------|
| **deploy.sh** | Production | Fast, controllable | Manual execution required |
| **install.sh** | New environment | Fully automated | Network dependent |
| **Manual deployment** | Special requirements | Full control | Complex steps |

**Recommended Workflow:**
1. 🧪 **Test Environment**: Use `install.sh` for quick setup
2. 🚀 **Production Environment**: Use `deploy.sh` for precise control
3. 🔄 **Daily Updates**: Use `deploy.sh` or manual updates
