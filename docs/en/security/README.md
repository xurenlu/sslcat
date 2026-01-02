# SSLcat Security Features

Welcome to SSLcat Security Features documentation. SSLcat provides comprehensive security features including Web Application Firewall (WAF), multi-dimensional blocking, threat detection, and more.

## 📚 Documentation Navigation

### Core Features

- **[WAF Overview](waf-overview.md)** - Web Application Firewall overview
- **[WAF Multi-Dimensional Blocking](waf-multi-dim-blocking.md)** - Multi-dimensional blocking strategy (IP, TLS fingerprint, IP subnet)
- **[WAF Rate Limiting](waf-rate-limiting.md)** - Automatic blocking based on trigger frequency

### Management Features

- **[Blocking Management](blocking-management.md)** - IP and User-Agent blocking management (CLI, Web UI, API)
- **[Threat Detection](threat-detection.md)** - Threat intelligence and bot detection
- **[Scanner Detection](scanner-detection.md)** - Automatic vulnerability scanner detection and blocking

## 🚀 Quick Start

### 1. Enable WAF

Enable WAF in configuration file:

```json
{
  "security": {
    "enable_waf": true
  }
}
```

### 2. Configure Rate Limiting

Enable automatic blocking:

```json
{
  "security": {
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 60,
    "waf_rate_limit_max_hits": 10,
    "waf_rate_limit_block_sec": 3600
  }
}
```

### 3. Manually Block IP

Using CLI command:

```bash
sslcat block ip 192.168.1.100 -duration 24h -reason "Malicious scanning"
```

## 🛡️ Security Features List

### Web Application Firewall (WAF)

- ✅ SQL Injection Detection
- ✅ XSS Attack Detection
- ✅ Sensitive File Access Detection
- ✅ Malicious User-Agent Detection
- ✅ Path Traversal Detection
- ✅ Command Injection Detection
- ✅ Scanner Detection (Nmap, Masscan, Shodan, Censys, LeakIX, etc.)

### Blocking Management

- ✅ IP Address Blocking (Manual/Auto)
- ✅ User-Agent Blocking
- ✅ TLS Fingerprint Blocking
- ✅ IP Subnet Blocking
- ✅ Temporary and Permanent Blocking
- ✅ Block List Viewing and Management

### Threat Detection

- ✅ Threat Intelligence Integration
- ✅ Bot Detection
- ✅ Suspicious Behavior Detection
- ✅ Automated Attack Identification

## 📖 Feature Details

### WAF Multi-Dimensional Blocking

WAF Multi-Dimensional Blocking can automatically detect and block malicious attackers from multiple dimensions:

- **IP Address Blocking**: Block individual malicious IPs
- **TLS Fingerprint Blocking**: Block all connections using the same tool/script
- **IP Subnet Blocking**: Automatically block entire subnet when multiple IPs in same subnet are blocked

[View Detailed Documentation](waf-multi-dim-blocking.md)

### WAF Rate Limiting

WAF Rate Limiting automatically detects and blocks IP addresses that frequently trigger WAF rules:

- Automatically records trigger events
- Counts triggers within time window
- Auto blocks when threshold reached
- Temporary blocking, auto expires

[View Detailed Documentation](waf-rate-limiting.md)

### Blocking Management

Blocking Management provides multiple ways to manage IP and User-Agent blocking:

- **CLI Commands**: `block`, `unblock`, `blocked`
- **Web Interface**: Security settings in admin panel
- **API Endpoints**: RESTful API support

[View Detailed Documentation](blocking-management.md)

### Scanner Detection

SSLcat can automatically detect and block common vulnerability scanners:

- Nmap
- Masscan
- Shodan
- Censys
- LeakIX
- And other common scanning tools

[View Detailed Documentation](scanner-detection.md)

## 🔧 Configuration Guide

### Production Environment Recommended Configuration

```json
{
  "security": {
    "enable_waf": true,
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 60,
    "waf_rate_limit_max_hits": 10,
    "waf_rate_limit_block_sec": 3600,
    "waf_tls_block_enabled": true,
    "waf_tls_block_window": 60,
    "waf_tls_block_max_hits": 10,
    "waf_tls_block_duration_sec": 3600,
    "waf_subnet_block_enabled": true,
    "waf_subnet_mask": 24,
    "waf_subnet_threshold": 3,
    "waf_subnet_block_duration_sec": 7200
  }
}
```

### Testing Environment Recommended Configuration

```json
{
  "security": {
    "enable_waf": true,
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 120,
    "waf_rate_limit_max_hits": 20,
    "waf_rate_limit_block_sec": 1800
  }
}
```

## 📊 Monitoring and Logging

### View Block List

Using CLI command:

```bash
sslcat blocked
```

### View WAF Statistics

Access security settings page in admin panel to view:
- Total blocks
- Total events
- Total rules
- Detection rate

### Log Analysis

WAF events are logged:

```bash
# View WAF logs
sudo journalctl -u sslcat | grep "WAF"
```

## 🔗 Related Documentation

- [CLI Commands Reference](../administration/cli-commands.md) - Includes blocking management commands
- [Configuration Reference](../reference/configuration-reference.md) - Complete configuration options
- [Troubleshooting](../troubleshooting/common-issues.md) - Common issues and solutions

## 📝 Version Information

- **Current Version**: v1.3.31-rc18+
- **Documentation Version**: 1.0
- **Last Updated**: 2025-01-29

---

*This documentation is continuously updated to reflect the latest security features and best practices of SSLcat.*

