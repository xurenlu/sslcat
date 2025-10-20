# Installation Methods

This guide covers various methods to install SSLcat, from quick one-click installations to advanced custom builds.

## 🚀 Quick Installation (Recommended)

### One-Click Installation Script

The fastest way to get SSLcat running:

```bash
# Standard installation
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/install.sh | sudo bash

# For Chinese users (faster download)
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v latest
```

**What this script does:**
- Downloads the latest SSLcat binary
- Creates system user and directories
- Installs systemd service
- Sets up basic configuration
- Starts the service

### Installation with Specific Version

```bash
# Install specific version
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v 1.3.3
```

## 📦 Package Installation

### Ubuntu/Debian

```bash
# Add repository (if available)
# wget -qO- https://repo.sslcat.com/key.gpg | sudo apt-key add -
# echo "deb https://repo.sslcat.com/ubuntu/ focal main" | sudo tee /etc/apt/sources.list.d/sslcat.list

# Update package list
sudo apt update

# Install SSLcat
sudo apt install sslcat

# Start service
sudo systemctl start sslcat
sudo systemctl enable sslcat
```

### CentOS/RHEL

```bash
# Add repository (if available)
# sudo yum-config-manager --add-repo https://repo.sslcat.com/centos/sslcat.repo

# Install SSLcat
sudo yum install sslcat

# Start service
sudo systemctl start sslcat
sudo systemctl enable sslcat
```

## 🐳 Docker Installation

### Docker Run

```bash
# Pull the image
docker pull sslcat/sslcat:latest

# Run container
docker run -d \
  --name sslcat \
  -p 80:80 \
  -p 443:443 \
  -v /etc/sslcat:/etc/sslcat \
  -v /opt/sslcat:/opt/sslcat \
  sslcat/sslcat:latest
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  sslcat:
    image: sslcat/sslcat:latest
    container_name: sslcat
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config:/etc/sslcat
      - ./data:/opt/sslcat
    environment:
      - SSL_EMAIL=your-email@example.com
      - SSL_STAGING=false
```

Start with Docker Compose:

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f sslcat
```

## 🔨 Building from Source

### Prerequisites

```bash
# Install Go 1.21+
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install build dependencies
sudo apt install build-essential git
```

### Build Process

```bash
# Clone repository
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# Download dependencies
go mod download

# Build binary
go build -o sslcat main.go

# Install
sudo cp sslcat /usr/local/bin/
sudo chmod +x /usr/local/bin/sslcat
```

### Cross-Platform Build

```bash
# Build for different architectures
GOOS=linux GOARCH=amd64 go build -o sslcat-linux-amd64 main.go
GOOS=darwin GOARCH=arm64 go build -o sslcat-darwin-arm64 main.go
GOOS=windows GOARCH=amd64 go build -o sslcat-windows-amd64.exe main.go
```

## 🏗️ Manual Installation

### Step 1: Download Binary

```bash
# Create installation directory
sudo mkdir -p /opt/sslcat/{bin,certs,keys,logs,data}

# Download binary
wget https://github.com/xurenlu/sslcat/releases/download/v1.3.3/sslcat_v1.3.3_linux-amd64.tar.gz
tar -xzf sslcat_v1.3.3_linux-amd64.tar.gz
sudo cp sslcat /opt/sslcat/bin/
sudo chmod +x /opt/sslcat/bin/sslcat
```

### Step 2: Create System User

```bash
# Create sslcat user
sudo useradd -r -s /bin/false -d /opt/sslcat sslcat

# Set ownership
sudo chown -R sslcat:sslcat /opt/sslcat
```

### Step 3: Create Configuration

```bash
# Create config directory
sudo mkdir -p /etc/sslcat

# Create basic configuration
sudo tee /etc/sslcat/sslcat.conf > /dev/null << EOF
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
  }
}
EOF
```

### Step 4: Create Systemd Service

```bash
# Create systemd service file
sudo tee /etc/systemd/system/sslcat.service > /dev/null << EOF
[Unit]
Description=SSLcat SSL Proxy Server
After=network.target

[Service]
Type=simple
User=sslcat
Group=sslcat
WorkingDirectory=/opt/sslcat
ExecStart=/opt/sslcat/bin/sslcat --config /etc/sslcat/sslcat.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload
sudo systemctl enable sslcat
```

## 🍎 macOS Installation

### Homebrew (if available)

```bash
# Install via Homebrew
brew install sslcat

# Start service
brew services start sslcat
```

### Manual Installation

```bash
# Download macOS binary
curl -fsSL https://cdn.wxside.com/xurenlu/sslcat/releases/download/v1.3.3/sslcat_v1.3.3_darwin-arm64.tar.gz -o sslcat.tgz

# Extract and install
tar -xzf sslcat.tgz
sudo install -m 0755 sslcat /usr/local/bin/sslcat

# Create config
mkdir -p ~/.sslcat
cat > ~/.sslcat/sslcat.conf << EOF
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
sslcat --config ~/.sslcat/sslcat.conf
```

## 🪟 Windows Installation

### Download and Install

1. Download the Windows binary from [GitHub Releases](https://github.com/xurenlu/sslcat/releases)
2. Extract the ZIP file
3. Run `sslcat.exe` from Command Prompt or PowerShell

### Windows Service (Advanced)

```powershell
# Install as Windows service using NSSM
nssm install sslcat "C:\path\to\sslcat.exe"
nssm set sslcat AppParameters "--config C:\path\to\sslcat.conf"
nssm start sslcat
```

## 🔧 Post-Installation Setup

### Initial Configuration

```bash
# Start SSLcat
sudo systemctl start sslcat

# Check status
sudo systemctl status sslcat

# View logs
sudo journalctl -u sslcat -f
```

### Web Interface Access

1. Open browser and navigate to: `http://your-server-ip/sslcat-panel`
2. Login with default credentials:
   - Username: `admin`
   - Password: `admin*9527`
3. Change password and configure settings

### Firewall Configuration

```bash
# Ubuntu/Debian
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## 🚨 Troubleshooting Installation

### Common Issues

**Permission Denied:**
```bash
# Check file permissions
ls -la /opt/sslcat/bin/sslcat
sudo chmod +x /opt/sslcat/bin/sslcat
```

**Port Already in Use:**
```bash
# Check what's using the port
sudo netstat -tlnp | grep :443
sudo lsof -i :443

# Stop conflicting service
sudo systemctl stop nginx
```

**Service Won't Start:**
```bash
# Check configuration
sslcat --config /etc/sslcat/sslcat.conf --log-level debug

# Check logs
sudo journalctl -u sslcat -f
```

### Verification Commands

```bash
# Check if SSLcat is running
sudo systemctl status sslcat

# Test configuration
sslcat --config /etc/sslcat/sslcat.conf --log-level debug

# Check ports
sudo netstat -tlnp | grep sslcat

# Test web interface
curl -I http://localhost/sslcat-panel
```

## 📋 Installation Checklist

### Pre-Installation
- [ ] System meets requirements
- [ ] Ports 80 and 443 are available
- [ ] Domain name points to server
- [ ] Firewall rules configured

### Installation
- [ ] Binary downloaded and installed
- [ ] System user created
- [ ] Configuration file created
- [ ] Service installed and enabled

### Post-Installation
- [ ] Service started successfully
- [ ] Web interface accessible
- [ ] SSL certificates working
- [ ] Proxy rules configured

## 🔄 Upgrading SSLcat

### Binary Upgrade

```bash
# Stop service
sudo systemctl stop sslcat

# Backup configuration
sudo cp /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.backup

# Download new version
wget https://github.com/xurenlu/sslcat/releases/download/v1.3.4/sslcat_v1.3.4_linux-amd64.tar.gz
tar -xzf sslcat_v1.3.4_linux-amd64.tar.gz

# Replace binary
sudo cp sslcat /opt/sslcat/bin/
sudo chmod +x /opt/sslcat/bin/sslcat

# Start service
sudo systemctl start sslcat
```

### Docker Upgrade

```bash
# Pull new image
docker pull sslcat/sslcat:latest

# Stop and remove old container
docker stop sslcat
docker rm sslcat

# Start new container
docker run -d --name sslcat -p 80:80 -p 443:443 -v /etc/sslcat:/etc/sslcat -v /opt/sslcat:/opt/sslcat sslcat/sslcat:latest
```

---

*Installation complete? Check out our [post-installation guide](post-install.md) for next steps.*
