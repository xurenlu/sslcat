# Threat Detection

SSLcat provides threat detection capabilities to identify and block malicious requests, bot attacks, and suspicious behavior.

## Overview

Threat detection automatically identifies threats by analyzing request characteristics, User-Agents, IP addresses, and other information, then takes appropriate protective measures.

## Detection Mechanisms

### 1. User-Agent Detection

Detect suspicious User-Agent patterns:

- Malicious crawlers
- Scanning tools
- Automated attack tools

### 2. Threat Intelligence Integration

Integrate threat intelligence data to identify known malicious IPs:

- Known malicious IP detection
- Malicious domain detection
- Malicious URL detection

### 3. Suspicious Behavior Detection

Detect suspicious request patterns:

- Abnormal request frequency
- Abnormal request paths
- Abnormal request parameters

## Configuration

Threat detection is part of WAF and security modules, enabled through:

```json
{
  "security": {
    "enable_waf": true,
    "enable_threat_intel": true
  }
}
```

## Use Cases

### Case 1: Bot Detection

Detect and block malicious bots:

```
Request User-Agent: bad-bot/1.0
→ Threat detection identifies as malicious bot
→ Request blocked
→ Security event recorded
```

### Case 2: Known Malicious IP

Detect known malicious IPs:

```
Request Source IP: 192.168.1.100 (known malicious IP)
→ Threat intelligence identifies as malicious IP
→ Request blocked
→ Security event recorded
```

## Related Documentation

- [WAF Overview](waf-overview.md) - WAF feature overview
- [Scanner Detection](scanner-detection.md) - Scanner detection feature
- [Blocking Management](blocking-management.md) - Blocking management feature

## Version Information

- **Current Version**: v1.3.31-rc18+
- **Last Updated**: 2025-01-29

