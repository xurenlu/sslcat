# System Requirements

This document outlines the system requirements for running SSLcat in various environments, from development to production.

## 🖥️ Operating System Support

### Supported Operating Systems

| OS | Version | Architecture | Support Level |
|----|---------|--------------|---------------|
| **Ubuntu** | 18.04+ | x86_64, ARM64 | ✅ Full Support |
| **Debian** | 9+ | x86_64, ARM64 | ✅ Full Support |
| **CentOS** | 7+ | x86_64, ARM64 | ✅ Full Support |
| **RHEL** | 7+ | x86_64, ARM64 | ✅ Full Support |
| **macOS** | 10.14+ | x86_64, ARM64 | ✅ Full Support |
| **Windows** | 10+ | x86_64, ARM64 | ✅ Full Support |
| **Alpine Linux** | 3.12+ | x86_64, ARM64 | ✅ Full Support |

### Container Support

| Platform | Support Level | Notes |
|----------|---------------|-------|
| **Docker** | ✅ Full Support | Multi-architecture images available |
| **Kubernetes** | ✅ Full Support | Helm charts available |
| **Podman** | ✅ Full Support | Compatible with Docker images |

## 💻 Hardware Requirements

### Minimum Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **CPU** | 1 core, 1 GHz | Single-threaded performance matters |
| **Memory** | 512 MB RAM | Minimum for basic operation |
| **Storage** | 1 GB free space | For binary and certificates |
| **Network** | 100 Mbps | For certificate downloads and proxy traffic |

### Recommended Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **CPU** | 2+ cores, 2+ GHz | Better performance and concurrency |
| **Memory** | 2+ GB RAM | For handling multiple connections |
| **Storage** | 10+ GB free space | For certificates, logs, and data |
| **Network** | 1+ Gbps | For high-traffic scenarios |

### Production Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **CPU** | 4+ cores, 3+ GHz | High-performance processing |
| **Memory** | 8+ GB RAM | Large connection handling |
| **Storage** | 50+ GB free space | For certificates, logs, and backups |
| **Network** | 10+ Gbps | Enterprise-grade throughput |

## 🔧 Software Dependencies

### Required Dependencies

| Package | Version | Purpose | Installation |
|---------|---------|---------|--------------|
| **Go** | 1.21+ | Runtime (if building from source) | [Go Installation Guide](https://golang.org/doc/install) |
| **curl** | 7.0+ | Download and API calls | `apt install curl` / `yum install curl` |
| **wget** | 1.0+ | Download utility | `apt install wget` / `yum install wget` |

### Optional Dependencies

| Package | Version | Purpose | Installation |
|---------|---------|---------|--------------|
| **certbot** | 1.0+ | Manual certificate management | `apt install certbot` / `yum install certbot` |
| **nginx** | 1.0+ | Reverse proxy (if needed) | `apt install nginx` / `yum install nginx` |
| **systemd** | 230+ | Service management | Usually pre-installed |

### Development Dependencies

| Package | Version | Purpose | Installation |
|---------|---------|---------|--------------|
| **Git** | 2.0+ | Version control | `apt install git` / `yum install git` |
| **Make** | 4.0+ | Build system | `apt install build-essential` |
| **GCC** | 7.0+ | Compiler | `apt install gcc` / `yum install gcc` |

## 🌐 Network Requirements

### Port Requirements

| Port | Protocol | Purpose | Required |
|------|----------|---------|----------|
| **80** | TCP | HTTP (Let's Encrypt validation) | ✅ Yes |
| **443** | TCP | HTTPS (SSL termination) | ✅ Yes |
| **8080** | TCP | Admin interface (optional) | ⚠️ Optional |

### Firewall Configuration

#### Ubuntu/Debian (ufw)
```bash
# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Optional: Allow admin interface
sudo ufw allow 8080/tcp
```

#### CentOS/RHEL (firewalld)
```bash
# Allow HTTP and HTTPS
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https

# Optional: Allow admin interface
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

#### iptables
```bash
# Allow HTTP and HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Optional: Allow admin interface
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

### DNS Requirements

- **Domain Name**: A valid domain name pointing to your server
- **DNS Resolution**: Proper DNS configuration for your domain
- **Let's Encrypt**: Domain must be publicly accessible for certificate validation

## 🔒 Security Requirements

### SSL/TLS Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **TLS Version** | 1.2+ | Modern TLS support required |
| **Cipher Suites** | AES-256, ChaCha20 | Strong encryption algorithms |
| **Certificate** | Valid SSL certificate | Let's Encrypt or commercial CA |

### Access Control

- **Root Access**: Required for installation and service management
- **User Permissions**: SSLcat runs as dedicated user after installation
- **File Permissions**: Proper file permissions for configuration and certificates

## 📊 Performance Considerations

### CPU Performance
- **Single-threaded**: SSLcat is primarily single-threaded for SSL operations
- **Multi-core**: Additional cores help with concurrent connections
- **CPU Architecture**: x86_64 and ARM64 are fully supported

### Memory Usage
- **Base Memory**: ~50-100 MB for basic operation
- **Per Connection**: ~1-2 KB per active connection
- **Certificate Cache**: ~1-5 MB per certificate (depending on size)

### Network Performance
- **Bandwidth**: Depends on your traffic requirements
- **Latency**: SSLcat adds minimal latency (< 1ms typically)
- **Concurrent Connections**: Supports thousands of concurrent connections

## 🐳 Container Requirements

### Docker Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **Docker** | 20.10+ | Container runtime |
| **Docker Compose** | 2.0+ | Multi-container orchestration |
| **Storage** | 10+ GB | For container images and data |

### Kubernetes Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **Kubernetes** | 1.20+ | Container orchestration |
| **Helm** | 3.0+ | Package management |
| **Storage Class** | Any | For persistent volumes |

## 🔍 System Verification

### Pre-Installation Checklist

- [ ] **OS Compatibility**: Verify your OS is supported
- [ ] **Architecture**: Check if your architecture is supported
- [ ] **Memory**: Ensure sufficient RAM is available
- [ ] **Storage**: Verify adequate disk space
- [ ] **Network**: Confirm ports 80 and 443 are available
- [ ] **DNS**: Ensure domain points to your server
- [ ] **Firewall**: Configure firewall rules appropriately

### Verification Commands

```bash
# Check OS and architecture
uname -a

# Check available memory
free -h

# Check disk space
df -h

# Check network connectivity
curl -I https://google.com

# Check port availability
sudo netstat -tlnp | grep -E ':(80|443)'

# Check DNS resolution
nslookup your-domain.com
```

## 🚀 Performance Tuning

### System Optimization

```bash
# Increase file descriptor limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize network parameters
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### SSLcat Configuration

```json
{
  "server": {
    "max_connections": 10000,
    "read_timeout_sec": 30,
    "write_timeout_sec": 30,
    "idle_timeout_sec": 120
  }
}
```

## 📋 Installation Methods

### 1. Binary Installation (Recommended)
- **Pros**: Fast, simple, no compilation required
- **Cons**: Limited customization
- **Best for**: Production deployments

### 2. Source Installation
- **Pros**: Full customization, latest features
- **Cons**: Requires Go and build tools
- **Best for**: Development, custom builds

### 3. Container Installation
- **Pros**: Isolated, portable, easy deployment
- **Cons**: Additional complexity
- **Best for**: Cloud deployments, microservices

## 🔧 Troubleshooting Requirements

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| **Port in use** | Another service using port 80/443 | Stop conflicting service or change ports |
| **Permission denied** | Insufficient privileges | Run with sudo or check file permissions |
| **DNS not resolving** | Domain not pointing to server | Update DNS records |
| **Firewall blocking** | Ports not open | Configure firewall rules |

### Diagnostic Tools

```bash
# Check system resources
htop
iostat
netstat

# Check SSL/TLS
openssl s_client -connect your-domain.com:443

# Check certificate
openssl x509 -in certificate.crt -text -noout
```

---

*Ready to install? Check out our [installation methods](methods.md) guide for step-by-step instructions.*
