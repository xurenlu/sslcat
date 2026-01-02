# WAF Rate Limiting

## Overview

WAF Rate Limiting automatically detects and blocks IP addresses that frequently trigger WAF rules, effectively preventing malicious scanning and attack behaviors.

## How It Works

1. **Trigger Recording**: System records each event when an IP triggers any WAF rule
2. **Frequency Statistics**: Counts trigger events within specified time window
3. **Auto Blocking**: Automatically blocks IP when trigger count reaches threshold
4. **Temporary Blocking**: Blocks are temporary and automatically expire

## Configuration

Add the following configuration to the `security` section in `config.json`:

```json
{
  "security": {
    "enable_waf": true,
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 60,
    "waf_rate_limit_max_hits": 10,
    "waf_rate_limit_block_sec": 3600
  }
}
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `waf_rate_limit_enabled` | bool | false | Enable WAF rate limiting |
| `waf_rate_limit_window` | int | 60 | Time window (seconds) for counting triggers |
| `waf_rate_limit_max_hits` | int | 10 | Maximum trigger count within time window |
| `waf_rate_limit_block_sec` | int | 3600 | Block duration (seconds), default 1 hour |

## Configuration Examples

### Example 1: Strict Mode (Recommended for Production)

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 60,
  "waf_rate_limit_max_hits": 5,
  "waf_rate_limit_block_sec": 7200
}
```

- 5 triggers within 60 seconds → Block for 2 hours
- Suitable for: Production environments, high-security applications

### Example 2: Lenient Mode (Recommended for Testing)

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 120,
  "waf_rate_limit_max_hits": 20,
  "waf_rate_limit_block_sec": 1800
}
```

- 20 triggers within 120 seconds → Block for 30 minutes
- Suitable for: Testing environments, development environments

### Example 3: Ultra-Strict Mode (For Active Attacks)

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 30,
  "waf_rate_limit_max_hits": 3,
  "waf_rate_limit_block_sec": 86400
}
```

- 3 triggers within 30 seconds → Block for 24 hours
- Suitable for: Active attacks, maximum security required

## Use Cases

### Case 1: Prevent Malicious Scanning

Attackers using automated tools to scan for vulnerabilities will trigger many WAF rules in short time:

```
Time 0s:  Access /.git/config        → WAF Triggered (1/10)
Time 2s:  Access /.env               → WAF Triggered (2/10)
Time 4s:  Access /admin.php          → WAF Triggered (3/10)
...
Time 18s: Access /wp-admin/          → WAF Triggered (10/10) → 🚫 IP Blocked
```

### Case 2: Prevent Brute Force Attacks

Attackers attempting brute force on login interfaces trigger SQL injection or XSS detection rules:

```
Continuous injection attempts → Quickly reaches threshold → Auto blocked
```

## API Endpoints

### Get Blocked IP List

```http
GET /sslcat-panel/api/waf/rate-limit/blocked-ips
```

### Unblock IP

```http
POST /sslcat-panel/api/waf/rate-limit/unblock
Content-Type: application/json

{
  "ip": "192.168.1.100"
}
```

### Update Rate Limit Configuration

```http
POST /sslcat-panel/api/waf/rate-limit/config
Content-Type: application/json

{
  "enabled": true,
  "window_sec": 60,
  "max_hits": 10,
  "block_duration_sec": 3600
}
```

## Performance Impact

### Memory Usage

- Trigger history per IP: ~24 bytes × trigger count
- Each blocked IP: ~40 bytes
- Total memory usage: Usually < 1 MB

### CPU Usage

- Per-request check: < 0.1 ms
- Periodic cleanup: Every 5 minutes, < 1 ms

## Best Practices

### 1. Set Reasonable Thresholds

- **Production**: Recommend 5-10 triggers within 60 seconds
- **Testing**: Recommend 15-20 triggers within 120 seconds
- **High-traffic sites**: Increase threshold appropriately to avoid false positives

### 2. Monitor Blocking Status

- Regularly check blocked IP lists
- Analyze blocking reasons, optimize WAF rules
- Unblock false positives promptly

### 3. Combine with Other Security Measures

- Enable IP whitelist for internal IPs
- Configure geo-blocking for specific countries
- Use threat intelligence to identify known malicious IPs

## Troubleshooting

### Issue 1: Legitimate Users Blocked

**Cause**: Threshold too low, or user behavior triggered WAF rules

**Solution**:
1. Check WAF rules, eliminate false positives
2. Increase rate limit threshold
3. Add IP to whitelist

### Issue 2: Attackers Not Blocked

**Cause**: Threshold too high, or attackers using multiple IPs

**Solution**:
1. Lower rate limit threshold
2. Shorten time window
3. Enable geo-blocking

## Version Information

- Introduced in: v1.3.31-rc17
- Dependencies: WAF Engine v2.0+
- Compatibility: Backward compatible, disabled by default

## Related Documentation

- [WAF Multi-Dimensional Blocking](waf-multi-dim-blocking.md)
- [WAF Overview](waf-overview.md)
- [Blocking Management](blocking-management.md)

