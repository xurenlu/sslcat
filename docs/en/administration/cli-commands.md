# CLI Commands Reference

SSLcat provides a comprehensive command-line interface (CLI) for managing and configuring SSLcat directly on the server. Even when the Web interface is unavailable, administrators can perform all configuration management tasks through CLI commands without manually editing configuration files.

## Important Notes

⚠️ **All CLI commands must be run as root on the server** (SSLcat requires root privileges to bind to privileged ports).

## Basic Usage

### Command Format

```bash
sslcat <command> [subcommand] [options]
```

### Configuration File

All CLI commands use `sslcat.conf` as the default configuration file. To specify a different configuration file, use the `-config` parameter:

```bash
sslcat -config /path/to/sslcat.conf <command>
```

## Available Commands

### 1. Configuration Management (`config`)

Configuration management commands are used to view, get, and set configuration items.

#### Show Complete Configuration

```bash
# Display complete configuration in JSON format
sslcat config show

# Use custom configuration file
sslcat -config /etc/sslcat/sslcat.conf config show
```

**Example Output:**
```json
{
  "server": {
    "port": 443,
    "host": "0.0.0.0",
    ...
  },
  "ssl": {
    "email": "admin@example.com",
    ...
  },
  ...
}
```

#### Get Configuration Item

```bash
# Get server port
sslcat config get server.port

# Get SSL email
sslcat config get ssl.email

# Get proxy rules count (need to check structure first)
sslcat config get proxy.rules
```

**Use dot-separated paths to access nested configuration items**, for example:
- `server.port` - Server port
- `ssl.email` - SSL certificate email
- `ssl.staging` - Use Let's Encrypt staging environment
- `proxy.cache.enabled` - Enable proxy cache

#### Set Configuration Item

```bash
# Set server port
sslcat config set server.port 8080

# Set SSL email
sslcat config set ssl.email admin@example.com

# Enable SSL staging
sslcat config set ssl.staging true

# Disable SSL staging
sslcat config set ssl.staging false
```

**Notes:**
- Configuration changes are saved to the configuration file immediately
- After modifying configuration, you need to restart the SSLcat service for changes to take effect
- Use dot-separated paths to access nested configuration items
- Supported types: string, integer, boolean, float

---

### 2. Proxy Management (`proxy`)

Proxy management commands are used to manage reverse proxy rules.

#### List All Proxy Rules

```bash
sslcat proxy list
```

**Example Output:**
```
Proxy Rules:
============
1. Domain: api.example.com
   Target: localhost:8080
   Enabled: true
   SSL Only: false

2. Domain: app.example.com
   Target: localhost:3000
   Enabled: true
   SSL Only: true
```

#### Add Proxy Rule

```bash
# Basic usage: add a proxy rule
sslcat proxy add -domain example.com -target localhost -port 8080

# Enable SSL enforcement
sslcat proxy add -domain example.com -target localhost -port 8080 -ssl

# Add rule as disabled
sslcat proxy add -domain example.com -target localhost -port 8080 -disabled

# Complete example
sslcat proxy add -domain api.example.com -target localhost -port 3000 -ssl -enabled
```

**Parameters:**
- `-domain <domain>` - **Required**, domain name (e.g., `example.com`)
- `-target <target>` - **Required**, target server address (e.g., `localhost` or `192.168.1.100`)
- `-port <port>` - **Optional**, target port (default: `80`)
- `-ssl` - **Optional**, enforce HTTPS (SSL Only)
- `-enabled` - **Optional**, enable rule (default: enabled)
- `-disabled` - **Optional**, disable rule

**Notes:**
- Domain names cannot be duplicated; an error will be shown if it already exists
- Rules are automatically saved to the configuration file after adding
- After adding a rule, you need to restart the SSLcat service for it to take effect

#### Update Proxy Rule

```bash
# Update target address
sslcat proxy update -domain example.com -target localhost -port 3000

# Update port
sslcat proxy update -domain example.com -port 8080

# Enable SSL enforcement
sslcat proxy update -domain example.com -ssl

# Disable SSL enforcement
sslcat proxy update -domain example.com -no-ssl

# Disable rule
sslcat proxy update -domain example.com -disabled

# Enable rule
sslcat proxy update -domain example.com -enabled
```

**Parameters:**
- `-domain <domain>` - **Required**, domain to update
- `-target <target>` - **Optional**, new target address
- `-port <port>` - **Optional**, new target port
- `-ssl` - **Optional**, enable SSL enforcement
- `-no-ssl` - **Optional**, disable SSL enforcement
- `-enabled` - **Optional**, enable rule
- `-disabled` - **Optional**, disable rule

**Notes:**
- Only specified fields are updated; unspecified fields remain unchanged
- Updates are automatically saved to the configuration file
- After updating a rule, you need to restart the SSLcat service for it to take effect

#### Delete Proxy Rule

```bash
# Delete proxy rule for specified domain
sslcat proxy delete -domain example.com
```

**Notes:**
- Delete operations cannot be undone; please use with caution
- Deletions are automatically saved to the configuration file
- After deleting a rule, you need to restart the SSLcat service for it to take effect

---

### 3. SSL Certificate Management (`ssl`)

SSL certificate management commands are used to manage SSL certificates. **Note: Some SSL command functionalities in the current version are placeholder implementations, and full functionality is under development.**

#### List Certificates

```bash
sslcat ssl list
```

**Current Implementation:** Displays the list of domains from enabled proxy rules in the configuration.

#### Show Certificate Details

```bash
sslcat ssl show -domain example.com
```

**Current Implementation:** Placeholder, shows informational message.

#### Request Certificate

```bash
# Use email from configuration file
sslcat ssl request -domain example.com

# Specify email
sslcat ssl request -domain example.com -email admin@example.com
```

**Parameters:**
- `-domain <domain>` - **Required**, domain to request certificate for
- `-email <email>` - **Optional**, Let's Encrypt email (if not specified, uses `ssl.email` from configuration file)

**Current Implementation:** Placeholder, shows informational message.

#### Renew Certificate

```bash
sslcat ssl renew -domain example.com
```

**Current Implementation:** Placeholder, shows informational message.

#### Delete Certificate

```bash
sslcat ssl delete -domain example.com
```

**Current Implementation:** Placeholder, shows informational message.

---

### 4. Help Command (`help`)

Display help information for all available commands.

```bash
sslcat help
```

**Example Output:**
```
SSLcat CLI Commands:

  config          Configuration management
  proxy           Proxy management
  ssl             SSL certificate management
  help            Show help information

Use 'sslcat <command> --help' for detailed help
```

---

## Startup Parameters

In addition to CLI subcommands, SSLcat also supports the following startup parameters:

### Basic Parameters

```bash
# Specify configuration file
sslcat -config /path/to/sslcat.conf

# Specify admin panel path prefix
sslcat -admin-prefix /sslcat-panel

# Specify listening address and port
sslcat -host 0.0.0.0 -port 443

# Specify SSL email
sslcat -email admin@example.com

# Use Let's Encrypt staging environment
sslcat -staging

# Specify log level
sslcat -log-level debug
```

### Configuration Validation

```bash
# Test configuration file syntax
sslcat -config sslcat.conf -test

# Check configuration file integrity
sslcat -config sslcat.conf -check

# Show version information
sslcat -version
```

**Complete Parameter List:**
- `-config` - Configuration file path (default: `/etc/sslcat/sslcat.conf`)
- `-admin-prefix` - Admin panel path prefix (default: `/sslcat-panel`)
- `-host` - Listening address (default: `0.0.0.0`)
- `-port` - Listening port (default: `443`)
- `-email` - SSL certificate email
- `-staging` - Use Let's Encrypt staging environment
- `-log-level` - Log level: `debug`, `info`, `warn`, `error` (default: `info`)
- `-test` - Test configuration file syntax
- `-check` - Check configuration file integrity
- `-version` - Show version information

---

## Usage Examples

### Complete Workflow Example

```bash
# 1. View current configuration
sslcat config show

# 2. Add proxy rule
sslcat proxy add -domain api.example.com -target localhost -port 3000 -ssl

# 3. View proxy rules list
sslcat proxy list

# 4. Set SSL email
sslcat config set ssl.email admin@example.com

# 5. Request SSL certificate (placeholder)
sslcat ssl request -domain api.example.com

# 6. View configuration item
sslcat config get ssl.email

# 7. Update proxy rule
sslcat proxy update -domain api.example.com -port 8080

# 8. Delete proxy rule
sslcat proxy delete -domain api.example.com
```

### Batch Operations Example

```bash
# Batch add multiple proxy rules
for domain in api.example.com app.example.com www.example.com; do
    sslcat proxy add -domain $domain -target localhost -port 8080 -ssl
done

# Batch update proxy rule ports
for domain in api.example.com app.example.com; do
    sslcat proxy update -domain $domain -port 3000
done
```

### Configuration Management Example

```bash
# View server configuration
sslcat config get server.port
sslcat config get server.host

# Modify server port
sslcat config set server.port 8443

# View SSL configuration
sslcat config get ssl.email
sslcat config get ssl.staging

# Modify SSL configuration
sslcat config set ssl.email newadmin@example.com
sslcat config set ssl.staging false
```

---

## Configuration File Format

CLI commands operate on JSON-format configuration files. Basic structure of the configuration file:

```json
{
  "server": {
    "port": 443,
    "host": "0.0.0.0"
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "localhost",
        "port": 8080,
        "enabled": true,
        "ssl_only": false
      }
    ]
  }
}
```

When using `config get` and `config set` commands, use dot-separated paths to access nested fields.

---

## Best Practices

### 1. Backup Configuration File

Before modifying configuration, it's recommended to backup the configuration file:

```bash
cp /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.backup
```

### 2. Test Configuration

After modifying configuration, use the `-test` parameter to validate:

```bash
sslcat -config /etc/sslcat/sslcat.conf -test
```

### 3. Restart Service

After modifying configuration, you need to restart the SSLcat service for changes to take effect:

```bash
# If using systemd
sudo systemctl restart sslcat

# If using other methods
# Stop current process, then restart
```

### 4. View Logs

After modifying configuration, check logs to confirm configuration is loaded correctly:

```bash
# If using systemd
sudo journalctl -u sslcat -f

# Or check log file
tail -f /var/log/sslcat/sslcat.log
```

---

## Troubleshooting

### Command Cannot Execute

**Problem:** Running `sslcat` command shows command not found or insufficient permissions

**Solution:**
1. Ensure SSLcat is properly installed
2. Ensure command path is in PATH, or use full path
3. Ensure running as root (SSLcat requires root privileges)

### Configuration File Cannot Be Read

**Problem:** Prompt shows configuration file doesn't exist or cannot be read

**Solution:**
1. Check if configuration file path is correct
2. Use `-config` parameter to specify full path
3. Ensure configuration file has read permissions

### Configuration Cannot Be Saved

**Problem:** After modifying configuration, prompt shows save failed

**Solution:**
1. Ensure configuration file has write permissions
2. Ensure configuration file path is correct
3. Check if disk space is sufficient

### Configuration Format Error

**Problem:** After using `config set`, configuration file format is incorrect

**Solution:**
1. Check if configuration path is correct (use dot-separated paths)
2. Check if value type is correct (string, number, boolean)
3. Restore configuration file from backup

---

## Related Documentation

- [User Management](user-management.md)
- [Web Interface](web-interface.md)
- [Configuration Reference](../reference/configuration-reference.md)
- [Troubleshooting](../troubleshooting/common-issues.md)
- [Quick Start](../getting-started/quick-start.md)

---

## Version Information

This documentation applies to SSLcat v1.3.21-rc5 and later versions.

**Last Updated:** 2025-01-29
