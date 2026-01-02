# Blocking Management

SSLcat provides comprehensive blocking management features, supporting IP address, User-Agent, and TLS fingerprint blocking through CLI commands, Web interface, and API endpoints.

## Overview

Blocking management supports the following blocking dimensions:

1. **IP Address Blocking** - Block individual IP addresses
2. **User-Agent Blocking** - Block specific User-Agents
3. **TLS Fingerprint Blocking** - Block all connections using the same TLS fingerprint (via WAF Multi-Dimensional Blocking)

## Blocking Types

### Temporary Blocking

Temporary blocks automatically expire after specified duration. Supported time formats:
- `1h` - 1 hour
- `24h` - 24 hours
- `7d` - 7 days
- `30d` - 30 days

### Permanent Blocking

Set duration to `0` or use `-duration 0` for permanent blocking until manually unblocked.

## CLI Commands

### Block IP or User-Agent

```bash
# Block IP (default 24 hours)
sslcat block ip 192.168.1.100

# Block IP with specified duration
sslcat block ip 192.168.1.100 -duration 1h
sslcat block ip 192.168.1.100 -duration 7d
sslcat block ip 192.168.1.100 -duration 0  # Permanent

# Block IP with reason
sslcat block ip 192.168.1.100 -reason "Malicious scanning"

# Block User-Agent
sslcat block user-agent "bad-bot/1.0" -duration 24h -reason "Malicious crawler"

# Can also use ua as shorthand for user-agent
sslcat block ua "bad-bot/1.0" -duration 24h
```

**Parameters:**
- `ip <ip>` - IP address to block
- `user-agent <ua>` or `ua <ua>` - User-Agent to block
- `-duration <duration>` - Block duration: `1h`, `24h`, `7d`, `0` (permanent)
- `-reason <reason>` - Block reason (optional)

### Unblock IP or User-Agent

```bash
# Unblock IP
sslcat unblock ip 192.168.1.100

# Unblock User-Agent
sslcat unblock user-agent "bad-bot/1.0"

# Can also use ua as shorthand
sslcat unblock ua "bad-bot/1.0"
```

### View Block List

```bash
# View all blocked IPs and User-Agents
sslcat blocked
```

**Example Output:**
```
Blocked IPs:
============
  IP: 192.168.1.100
    Reason: Malicious scanning
    Blocked at: 2025-01-29 10:30:00
    Expires at: 2025-01-30 10:30:00

Blocked User-Agents:
====================
  User-Agent: bad-bot/1.0
    Reason: Malicious crawler
    Blocked at: 2025-01-29 09:15:00
    Expires at: 2025-01-30 09:15:00
```

## Web Interface

### Access Blocking Management

1. Log in to SSLcat admin panel
2. Navigate to **Security Settings** → **Blocking Management**
3. View current block list

### Manual Blocking

1. In blocking management page, click **Add Block**
2. Select block type:
   - **IP Address**
   - **User-Agent**
   - **TLS Fingerprint** (requires WAF Multi-Dimensional Blocking)
3. Enter value to block
4. Set block duration (or select permanent)
5. Enter block reason (optional)
6. Click **Confirm Block**

### Unblock

1. In block list, find item to unblock
2. Click **Unblock** button
3. Confirm operation

## API Endpoints

### 1. Get Block List

**Request**:
```http
GET /sslcat-panel/api/security/blocked-list
```

**Response Example**:
```json
{
  "success": true,
  "data": {
    "ips": [
      {
        "ip": "192.168.1.100",
        "reason": "Malicious scanning",
        "block_time": "2025-01-29T10:30:00Z",
        "expire_time": "2025-01-30T10:30:00Z"
      }
    ],
    "user_agents": [
      {
        "user_agent": "bad-bot/1.0",
        "reason": "Malicious crawler",
        "block_time": "2025-01-29T09:15:00Z",
        "expire_time": "2025-01-30T09:15:00Z"
      }
    ]
  }
}
```

### 2. Block IP or User-Agent

**Request**:
```http
POST /sslcat-panel/api/security/block
Content-Type: application/json

{
  "type": "ip",
  "value": "192.168.1.100",
  "duration": 86400,
  "reason": "Malicious scanning"
}
```

**Parameters:**
- `type` - Block type: `ip`, `user_agent`, `tls_fingerprint`
- `value` - Value to block (IP address, User-Agent, or TLS fingerprint)
- `duration` - Block duration (seconds), `0` for permanent
- `reason` - Block reason (optional)

### 3. Unblock

**Request**:
```http
POST /sslcat-panel/api/security/unblock
Content-Type: application/json

{
  "type": "ip",
  "value": "192.168.1.100"
}
```

## Blocking Dimensions

### IP Address Blocking

IP address blocking prevents all requests from specified IP. Blocking applies to:
- Security Manager (basic security module)
- WAF Multi-Dimensional Blocking (if enabled)

**Use Cases:**
- Known malicious IPs
- Frequently attacking IPs
- IPs requiring temporary blocking

### User-Agent Blocking

User-Agent blocking prevents all requests using specified User-Agent.

**Use Cases:**
- Malicious crawlers
- Scanning tools
- Automated attack tools

### TLS Fingerprint Blocking

TLS fingerprint blocking prevents all connections using the same TLS fingerprint, regardless of IP. Requires WAF Multi-Dimensional Blocking.

**Use Cases:**
- Distributed attacks (using same tools)
- Automated attack scripts
- Attackers bypassing IP blocks

## Best Practices

### 1. Set Reasonable Block Duration

- **Temporary**: For suspicious behavior, recommend 1-24 hours
- **Long-term**: For confirmed malicious behavior, recommend 7-30 days
- **Permanent**: Only for confirmed malicious IPs or tools

### 2. Record Block Reasons

Always record block reasons for analysis and auditing:
- Malicious scanning
- SQL injection attempts
- Brute force attacks
- Malicious crawlers

### 3. Regularly Review Block List

Regularly check block list:
- Confirm blocks are still effective
- Unblock false positives
- Analyze attack patterns

### 4. Combine with Auto Blocking

Manual blocking should work with auto blocking (WAF rate limiting, multi-dimensional blocking):
- Auto blocking handles common attacks
- Manual blocking handles special cases
- Combined provides comprehensive protection

## Troubleshooting

### Issue 1: Block Not Effective

**Possible Causes:**
- Configuration not saved
- Service not restarted
- Invalid IP address format

**Solution:**
1. Check if configuration is saved correctly
2. Restart SSLcat service
3. Verify IP address format (IPv4 or IPv6)

### Issue 2: Legitimate Users Blocked

**Solution:**
1. Immediately unblock: `sslcat unblock ip <ip>`
2. Check block reason
3. Add IP to whitelist (if supported)
4. Adjust auto-blocking thresholds

## Related Documentation

- [CLI Commands Reference](../administration/cli-commands.md) - Complete CLI command documentation
- [WAF Multi-Dimensional Blocking](waf-multi-dim-blocking.md) - TLS fingerprint and IP subnet blocking
- [WAF Rate Limiting](waf-rate-limiting.md) - Automatic blocking features
- [Scanner Detection](scanner-detection.md) - Automatic scanner detection and blocking

## Version Information

- **Introduced in**: v1.3.31-rc18
- **Last Updated**: 2025-01-29

