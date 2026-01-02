# WAF Multi-Dimensional Blocking Strategy

## Overview

WAF Multi-Dimensional Blocking is a powerful security feature that automatically detects and blocks malicious attackers from multiple dimensions, effectively countering distributed attacks and advanced threats.

### Supported Blocking Dimensions

1. **IP Address Blocking** - Block individual malicious IPs
2. **TLS Fingerprint Blocking** - Block all connections using the same tool/script
3. **IP Subnet Blocking** - Automatically block entire subnets when multiple IPs in the same subnet are blocked

## How It Works

```
Client Request
    ↓
Extract Information (IP, TLS Fingerprint)
    ↓
Check if Already Blocked
    ├─ IP Blocked? → Return 403
    ├─ TLS Fingerprint Blocked? → Return 403
    └─ IP Subnet Blocked? → Return 403
    ↓
Execute WAF Rule Check
    ↓
Rule Triggered?
    ├─ Yes → Record Trigger Event
    │       ├─ Update IP Frequency Stats
    │       ├─ Update TLS Fingerprint Stats
    │       └─ Update IP Subnet Stats
    │       ↓
    │       Check if Threshold Reached
    │       ├─ IP Threshold → Block IP
    │       ├─ TLS Threshold → Block TLS Fingerprint
    │       └─ 3 IPs in Same Subnet Blocked → Block Entire Subnet
    └─ No → Allow Request
```

## Configuration

### Configuration Example

Add the following configuration to the `security` section in `config.json`:

```json
{
  "security": {
    "enable_waf": true,
    
    "// IP Rate Limiting (existing)": "",
    "waf_rate_limit_enabled": true,
    "waf_rate_limit_window": 60,
    "waf_rate_limit_max_hits": 10,
    "waf_rate_limit_block_sec": 3600,
    
    "// TLS Fingerprint Blocking (new)": "",
    "waf_tls_block_enabled": true,
    "waf_tls_block_window": 60,
    "waf_tls_block_max_hits": 10,
    "waf_tls_block_duration_sec": 3600,
    
    "// IP Subnet Blocking (new)": "",
    "waf_subnet_block_enabled": true,
    "waf_subnet_mask": 24,
    "waf_subnet_threshold": 3,
    "waf_subnet_block_duration_sec": 7200
  }
}
```

### Configuration Parameters

#### IP Dimension Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `waf_rate_limit_enabled` | bool | false | Enable IP rate limiting |
| `waf_rate_limit_window` | int | 60 | Time window (seconds) |
| `waf_rate_limit_max_hits` | int | 10 | Maximum trigger count within time window |
| `waf_rate_limit_block_sec` | int | 3600 | Block duration (seconds), default 1 hour |

#### TLS Fingerprint Dimension Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `waf_tls_block_enabled` | bool | false | Enable TLS fingerprint blocking |
| `waf_tls_block_window` | int | 60 | Time window (seconds) |
| `waf_tls_block_max_hits` | int | 10 | Maximum trigger count within time window |
| `waf_tls_block_duration_sec` | int | 3600 | Block duration (seconds), default 1 hour |

#### IP Subnet Dimension Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `waf_subnet_block_enabled` | bool | false | Enable IP subnet blocking |
| `waf_subnet_mask` | int | 24 | Subnet mask (/24 = 256 IPs) |
| `waf_subnet_threshold` | int | 3 | Threshold for blocked IPs in same subnet |
| `waf_subnet_block_duration_sec` | int | 7200 | Block duration (seconds), default 2 hours |

## Use Cases

### Case 1: Single IP Attack

**Attack Behavior**:
```
IP 192.168.1.100 accesses within 60 seconds:
- /.git/config
- /.env
- /admin.php
- /wp-config.php
... (10 WAF rule triggers total)
```

**System Response**:
1. Detects IP 192.168.1.100 triggered 10 WAF rules within 60 seconds
2. Automatically blocks the IP for 1 hour
3. All subsequent requests from this IP return 403 Forbidden

### Case 2: Multi-IP Attack from Same Subnet

**Attack Behavior**:
```
Attacker uses multiple IPs from same subnet:
- 192.168.1.100 → Blocked
- 192.168.1.101 → Blocked
- 192.168.1.102 → Blocked
```

**System Response**:
1. Detects 3 IPs blocked in 192.168.1.0/24 subnet
2. Automatically blocks entire 192.168.1.0/24 subnet for 2 hours
3. All IPs in this subnet (192.168.1.0 - 192.168.1.255) are blocked

### Case 3: Same TLS Fingerprint Attack

**Attack Behavior**:
```
Attacker uses automation tools (e.g., Python requests) from different IPs:
- IP 10.0.0.1 (TLS Fingerprint: abc123...) → Triggers WAF
- IP 10.0.0.2 (TLS Fingerprint: abc123...) → Triggers WAF
- IP 10.0.0.3 (TLS Fingerprint: abc123...) → Triggers WAF
... (10 times total)
```

**System Response**:
1. Detects TLS fingerprint `abc123...` triggered 10 WAF rules within 60 seconds
2. Automatically blocks the TLS fingerprint for 1 hour
3. All connections using this TLS fingerprint (regardless of IP) are blocked

**Advantages**:
- Effectively counters distributed attacks using same tools/scripts
- Attackers still blocked even after changing IPs
- Identifies and blocks automated attack tools

## API Endpoints

### 1. Get Blocked List

**Request**:
```http
GET /sslcat-panel/api/waf/blocked-list?dimension=ip
```

**Parameters**:
- `dimension` (optional): Blocking dimension
  - `ip` - Return only IP block list
  - `tls` - Return only TLS fingerprint block list
  - `subnet` - Return only IP subnet block list
  - Not provided - Return all dimensions

**Response Example**:
```json
{
  "success": true,
  "data": [
    {
      "dimension": "ip",
      "value": "192.168.1.100",
      "reason": "Triggered 10 WAF rules within 1m0s",
      "expire_time": "2024-01-01T15:00:00Z",
      "hit_count": 10,
      "first_seen": "2024-01-01T14:00:00Z",
      "last_seen": "2024-01-01T14:01:00Z"
    }
  ]
}
```

### 2. Unblock

**Request**:
```http
POST /sslcat-panel/api/waf/unblock
Content-Type: application/json

{
  "dimension": "ip",
  "value": "192.168.1.100"
}
```

**Parameters**:
- `dimension`: Blocking dimension (`ip`, `tls_fingerprint`, `ip_subnet`)
- `value`: Value to unblock (IP address, TLS fingerprint, or CIDR)

### 3. Get Subnet Statistics

**Request**:
```http
GET /sslcat-panel/api/waf/subnet-stats
```

### 4. Get TLS Fingerprint Statistics

**Request**:
```http
GET /sslcat-panel/api/waf/tls-stats
```

## Recommended Configurations

### Production Environment (Standard)

```json
{
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
```

### Production Environment (Strict)

```json
{
  "waf_rate_limit_enabled": true,
  "waf_rate_limit_window": 60,
  "waf_rate_limit_max_hits": 5,
  "waf_rate_limit_block_sec": 7200,
  
  "waf_tls_block_enabled": true,
  "waf_tls_block_window": 60,
  "waf_tls_block_max_hits": 5,
  "waf_tls_block_duration_sec": 7200,
  
  "waf_subnet_block_enabled": true,
  "waf_subnet_mask": 24,
  "waf_subnet_threshold": 2,
  "waf_subnet_block_duration_sec": 14400
}
```

## Best Practices

1. **Enable Gradually**:
   - Phase 1: Enable IP blocking only
   - Phase 2: Enable TLS fingerprint blocking
   - Phase 3: Enable IP subnet blocking

2. **Monitor Blocking Status**:
   - Regularly check blocked lists
   - Analyze blocking reasons and patterns
   - Unblock false positives promptly

3. **Combine with Other Security Measures**:
   - IP whitelist for internal IPs
   - Geo-blocking for specific countries
   - Threat intelligence for known malicious IPs

## Version Information

- Introduced in: v1.3.31-rc18
- Dependencies: WAF Engine v2.0+
- Compatibility: Backward compatible, disabled by default

## Related Documentation

- [WAF Rate Limiting](waf-rate-limiting.md)
- [WAF Overview](waf-overview.md)
- [Blocking Management](blocking-management.md)

