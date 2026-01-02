# Scanner Detection

SSLcat can automatically detect and block common vulnerability scanners and security tools, effectively preventing malicious scanning and attacks.

## Overview

Scanner detection automatically identifies common vulnerability scanning tools and security scanners by analyzing request User-Agents and other characteristics, and can automatically block these tools.

## Supported Scanners

SSLcat supports detection of the following common vulnerability scanners and security tools:

### Network Scanning Tools

- **Nmap** - Network mapping and port scanning tool
- **Masscan** - Large-scale port scanning tool
- **Zmap** - Fast internet scanning tool

### Security Scanning Platforms

- **Shodan** - Internet-connected device search engine
- **Censys** - Internet device search engine
- **LeakIX** - Vulnerability search and network analysis platform

### Web Application Scanning Tools

- **Nikto** - Web server scanner
- **SQLMap** - SQL injection detection tool
- **Acunetix** - Web vulnerability scanner
- **AppScan** - IBM application security scanner
- **Nessus** - Vulnerability scanner
- **OpenVAS** - Open source vulnerability assessment system
- **Qualys** - Cloud security scanning platform
- **Burp Suite** - Web application security testing tool
- **OWASP ZAP** - OWASP security testing tool
- **Assetnote** - Asset discovery and vulnerability scanning platform

## Detection Mechanism

### User-Agent Detection

Scanner detection primarily identifies scanning tools by analyzing HTTP request User-Agent headers:

```go
// Scanner detection rules
scannerRules := []struct {
    name    string
    pattern string
}{
    {"Assetnote Scanner", `(?i)Assetnote`},
    {"Nmap Scanner", `(?i)nmap|Nmap`},
    {"Nikto Scanner", `(?i)nikto|Nikto`},
    {"SQLMap Scanner", `(?i)sqlmap`},
    {"Acunetix Scanner", `(?i)Acunetix|WVS`},
    {"AppScan Scanner", `(?i)AppScan|Rational`},
    {"Nessus Scanner", `(?i)Nessus`},
    {"OpenVAS Scanner", `(?i)OpenVAS`},
    {"Qualys Scanner", `(?i)Qualys`},
    {"Burp Scanner", `(?i)Burp`},
    {"OWASP Scanner", `(?i)OWASP|ZAP`},
    {"Masscan Scanner", `(?i)masscan`},
    {"Zmap Scanner", `(?i)zmap`},
    {"Shodan Scanner", `(?i)Shodan`},
    {"Censys Scanner", `(?i)Censys`},
    {"LeakIX Scanner", `(?i)leakix`},
}
```

### Detection Process

1. **Request Analysis**: Extract request User-Agent header
2. **Pattern Matching**: Use regex to match known scanner patterns
3. **Rule Trigger**: If match succeeds, trigger WAF rule
4. **Auto Blocking**: According to WAF configuration, can auto block or record event

## Configuration

### Enable Scanner Detection

Scanner detection is part of WAF functionality, WAF must be enabled first:

```json
{
  "security": {
    "enable_waf": true
  }
}
```

### Scanner Detection Rules

Scanner detection rules are enabled by default and automatically detect and block scanning tools. Rules are automatically loaded when WAF engine initializes.

### Custom Scanner Rules

To add custom scanner detection rules, modify the `scannerRules` array in `internal/waf/engine.go`:

```go
scannerRules := []struct {
    name    string
    pattern string
}{
    // Add custom rules
    {"Custom Scanner", `(?i)custom-scanner`},
}
```

## Use Cases

### Case 1: Prevent Malicious Scanning

Attacker uses Nmap to scan server ports:

```
Request User-Agent: Nmap/7.80
→ Detected Nmap Scanner
→ Triggered WAF rule
→ Auto blocked or recorded event based on configuration
```

### Case 2: Prevent Automated Attacks

Attacker uses SQLMap for SQL injection testing:

```
Request User-Agent: sqlmap/1.5.2
→ Detected SQLMap Scanner
→ Request immediately blocked
→ Security event recorded
```

### Case 3: Prevent Large-Scale Scanning

Platforms like Shodan, Censys perform internet scanning:

```
Request User-Agent: Shodan
→ Detected Shodan Scanner
→ Scanning request blocked
→ Protect server information leakage
```

## Integration with Other Security Features

### WAF Rate Limiting

Scanner detection works with WAF rate limiting:

1. Scanner detection identifies scanning tools
2. If scanners frequently trigger rules, rate limiting auto blocks IP
3. Forms multi-layer protection

### Multi-Dimensional Blocking

Scanner detection works with multi-dimensional blocking:

1. Scanner detection identifies scanning tools
2. If using same TLS fingerprint, TLS fingerprint blocking prevents all connections
3. If from same subnet, IP subnet blocking prevents entire subnet

## Best Practices

### 1. Enable WAF

Ensure WAF is enabled for scanner detection to work.

### 2. Configure Auto Blocking

Enable WAF rate limiting to auto block frequently scanning IPs:

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

### 3. Monitor Scanning Activity

Regularly review scanner detection events, analyze attack patterns:
- Which scanners are most commonly used
- Scanning frequency
- Whether rule adjustments are needed

## Troubleshooting

### Issue 1: Scanner Not Detected

**Possible Causes:**
- WAF not enabled
- User-Agent modified or hidden
- Scanner not in supported list

**Solution:**
1. Check if WAF is enabled
2. Review request logs, confirm User-Agent
3. Add custom scanner rules

### Issue 2: Legitimate Scanning Blocked

**Solution:**
1. Add legitimate scanning IPs to whitelist
2. Disable WAF for specific domains
3. Adjust scanner detection rules, exclude legitimate scanners

## Related Documentation

- [WAF Overview](waf-overview.md) - WAF feature overview
- [WAF Rate Limiting](waf-rate-limiting.md) - Automatic blocking features
- [WAF Multi-Dimensional Blocking](waf-multi-dim-blocking.md) - Multi-dimensional blocking strategy
- [Blocking Management](blocking-management.md) - Manual blocking management

## Version Information

- **Introduced in**: v1.3.31-rc18
- **Last Updated**: 2025-01-29

