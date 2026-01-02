# WAF Overview

Web Application Firewall (WAF) is SSLcat's core security feature, providing comprehensive Web application security protection.

## Overview

SSLcat's WAF provides multi-layer security protection, including:

- ✅ SQL Injection Detection and Protection
- ✅ XSS Attack Detection and Protection
- ✅ Sensitive File Access Detection
- ✅ Malicious User-Agent Detection
- ✅ Path Traversal Detection
- ✅ Command Injection Detection
- ✅ Scanner Detection (Nmap, Masscan, Shodan, Censys, LeakIX, etc.)
- ✅ Rate Limiting and Auto Blocking
- ✅ Multi-Dimensional Blocking (IP, TLS Fingerprint, IP Subnet)

## Core Features

### 1. Attack Detection

WAF can detect various common Web attacks:

- **SQL Injection**: Detect SQL injection attack patterns
- **XSS Attacks**: Detect cross-site scripting attacks
- **Path Traversal**: Detect directory traversal attacks
- **Command Injection**: Detect command injection attacks
- **Sensitive File Access**: Detect access attempts to sensitive files

### 2. Scanner Detection

Automatically detect and block common vulnerability scanners:

- Nmap, Masscan, Zmap
- Shodan, Censys, LeakIX
- Nikto, SQLMap, Acunetix
- Burp Suite, OWASP ZAP
- And other common scanning tools

### 3. Rate Limiting

Automatically detect and block IPs that frequently trigger WAF rules:

- Count triggers within time window
- Auto block when threshold reached
- Temporary blocking, auto expires

### 4. Multi-Dimensional Blocking

Automatically detect and block malicious attackers from multiple dimensions:

- **IP Address Blocking**: Block individual malicious IPs
- **TLS Fingerprint Blocking**: Block all connections using same tools
- **IP Subnet Blocking**: Block entire subnets

## Configuration

### Enable WAF

Enable WAF in configuration file:

```json
{
  "security": {
    "enable_waf": true
  }
}
```

### Per-Domain WAF Configuration

Can configure WAF separately for each domain:

- **Global (Default)**: Use global WAF configuration
- **Enable**: Force enable WAF for this domain
- **Disable**: Force disable WAF for this domain

## Performance Optimization

SSLcat's WAF implements multiple performance optimizations:

### 1. Log Rate Limiting

- Same attack logged at most once per minute
- Reduces log I/O overhead
- CPU usage reduced by 99%+

### 2. Event Storage Optimization

- Maximum 10,000 events stored
- Auto cleanup events older than 24 hours
- Memory usage ≤5 MB

### 3. Detection Performance Optimization

- Regex pre-compilation
- Fast-fail mechanism
- Read-write lock optimization

## Use Cases

### Case 1: Prevent SQL Injection

Attacker attempts SQL injection:

```
Request: /api/user?id=1' OR '1'='1
→ WAF detects SQL injection pattern
→ Request blocked
→ Security event recorded
```

### Case 2: Prevent XSS Attacks

Attacker attempts XSS:

```
Request: /search?q=<script>alert('XSS')</script>
→ WAF detects XSS pattern
→ Request blocked
→ Security event recorded
```

## Monitoring and Logging

### View WAF Statistics

Access security settings page in admin panel to view:
- Total blocks
- Total events
- Total rules
- Detection rate

### WAF Logs

WAF events are logged:

```bash
# View WAF logs
sudo journalctl -u sslcat | grep "WAF"
```

## Best Practices

### 1. Enable WAF

Always enable WAF in production environments for basic security protection.

### 2. Configure Rate Limiting

Enable rate limiting to auto block frequently attacking IPs:

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

### 3. Enable Multi-Dimensional Blocking

Enable multi-dimensional blocking to counter distributed attacks:

```json
{
  "security": {
    "waf_tls_block_enabled": true,
    "waf_subnet_block_enabled": true
  }
}
```

## Related Documentation

- [WAF Multi-Dimensional Blocking](waf-multi-dim-blocking.md) - Multi-dimensional blocking strategy details
- [WAF Rate Limiting](waf-rate-limiting.md) - Rate limiting feature details
- [Scanner Detection](scanner-detection.md) - Scanner detection feature details
- [Blocking Management](blocking-management.md) - Blocking management feature details

## Version Information

- **Current Version**: v1.3.31-rc18+
- **Last Updated**: 2025-01-29

