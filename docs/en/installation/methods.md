# Installation Methods

This guide covers how to install SSLcat. We provide pre-compiled binary files that you can download and run the installation script.

## Download Installation Package

### Download Binary Files
```bash
# GitHub download
curl -L https://github.com/xurenlu/sslcat/releases/download/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -o sslcat.tar.gz

# CDN mirror download (faster for Chinese users)
curl -L https://cdn.wxside.com/xurenlu/sslcat/releases/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -o sslcat.tar.gz

# Or using wget
wget https://github.com/xurenlu/sslcat/releases/download/v1.3.20-rc2/sslcat_v1.3.20-rc2_linux-amd64.tar.gz -O sslcat.tar.gz
```

### Extract and Install
```bash
# Extract files
tar -xzf sslcat.tar.gz

# Run installation script
sudo ./install-sslcat.sh
```

## Installation Script Details

The installation script `install-sslcat.sh` automatically performs the following operations:

1. **Check system requirements** - Verify operating system and permissions
2. **Create system user** - Create `sslcat` user and group
3. **Create directory structure** - Set up necessary directories and permissions
4. **Install binary files** - Copy to system path and set permissions
5. **Create system service** - Configure systemd service
6. **Create default configuration** - Generate basic configuration file
7. **Start service** - Enable and start SSLcat service

### Installation Script Content
```bash
#!/bin/bash
# install-sslcat.sh

set -e

# Configuration variables
SSLCAT_VERSION="1.3.20-rc2"
SSLCAT_USER="sslcat"
SSLCAT_HOME="/opt/sslcat"
SSLCAT_CONFIG="/etc/sslcat"
SSLCAT_LOG="/var/log/sslcat"

# Check system requirements
check_requirements() {
    echo "Checking system requirements..."
    
    # Check operating system
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        echo "Error: Only Linux systems are supported"
        exit 1
    fi
    
    # Check permissions
    if [[ $EUID -ne 0 ]]; then
        echo "Error: Root privileges required"
        exit 1
    fi
    
    echo "System requirements check passed"
}

# Download SSLcat
download_sslcat() {
    echo "Downloading SSLcat ${SSLCAT_VERSION}..."
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) echo "Error: Unsupported architecture $ARCH"; exit 1 ;;
    esac
    
    # Download binary file
    DOWNLOAD_URL="https://github.com/xurenlu/sslcat/releases/download/v${SSLCAT_VERSION}/sslcat_v${SSLCAT_VERSION}_linux-${ARCH}.tar.gz"
    
    cd /tmp
    wget -q "$DOWNLOAD_URL" -O sslcat.tar.gz
    tar -xzf sslcat.tar.gz
    chmod +x sslcat
}

# Install SSLcat
install_sslcat() {
    echo "Installing SSLcat..."
    
    # Create user
    if ! id "$SSLCAT_USER" &>/dev/null; then
        useradd -r -s /bin/false "$SSLCAT_USER"
    fi
    
    # Create directories
    mkdir -p "$SSLCAT_HOME"
    mkdir -p "$SSLCAT_CONFIG"
    mkdir -p "$SSLCAT_LOG"
    
    # Copy binary file
    cp sslcat "$SSLCAT_HOME/"
    chmod +x "$SSLCAT_HOME/sslcat"
    
    # Create symbolic link
    ln -sf "$SSLCAT_HOME/sslcat" /usr/local/bin/sslcat
    
    # Set permissions
    chown -R "$SSLCAT_USER:$SSLCAT_USER" "$SSLCAT_HOME"
    chown -R "$SSLCAT_USER:$SSLCAT_USER" "$SSLCAT_CONFIG"
    chown -R "$SSLCAT_USER:$SSLCAT_USER" "$SSLCAT_LOG"
}

# Create system service
create_service() {
    echo "Creating system service..."
    
    cat > /etc/systemd/system/sslcat.service <<EOF
[Unit]
Description=SSLcat Proxy Server
After=network.target

[Service]
Type=simple
User=$SSLCAT_USER
Group=$SSLCAT_USER
ExecStart=$SSLCAT_HOME/sslcat -config $SSLCAT_CONFIG/sslcat.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sslcat
}

# Create default configuration
create_config() {
    echo "Creating default configuration..."
    
    cat > "$SSLCAT_CONFIG/sslcat.conf" <<EOF
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443
  debug: false

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true

ssl:
  certificates:
    - domain: "example.com"
      provider: "letsencrypt"
      email: "admin@example.com"
      auto_renew: true

monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
EOF

    chown "$SSLCAT_USER:$SSLCAT_USER" "$SSLCAT_CONFIG/sslcat.conf"
}

# Main function
main() {
    echo "Starting SSLcat installation..."
    
    check_requirements
    download_sslcat
    install_sslcat
    create_service
    create_config
    
    echo "SSLcat installation completed!"
    echo "Configuration file: $SSLCAT_CONFIG/sslcat.conf"
    echo "Start service: systemctl start sslcat"
    echo "Check status: systemctl status sslcat"
}

# Run main function
main "$@"
```

## Verification

### Check Installation
```bash
# Check version
sslcat --version

# Check service status
systemctl status sslcat

# Check ports
netstat -tlnp | grep sslcat
```

### Access Web Interface
```bash
# Web interface address
http://your-server-ip:8080/sslcat-panel

# Default login credentials
# Username: admin
# Password: admin*9527
```

## Uninstall

```bash
# Stop service
sudo systemctl stop sslcat
sudo systemctl disable sslcat

# Remove service file
sudo rm /etc/systemd/system/sslcat.service
sudo systemctl daemon-reload

# Remove files
sudo rm /usr/local/bin/sslcat
sudo rm -rf /etc/sslcat
sudo rm -rf /var/log/sslcat
sudo rm -rf /var/lib/sslcat

# Remove user
sudo userdel sslcat
```

## Related Documentation

- [System Requirements](requirements.md)
- [Configuration Guide](../configuration/basic.md)

---

*After installation, please access the web interface for initial configuration.*