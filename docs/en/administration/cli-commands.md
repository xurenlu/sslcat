# CLI Commands

SSLcat provides a comprehensive command-line interface for configuration, management, and troubleshooting.

## Basic Commands

### Start SSLcat
```bash
# Start with default configuration
sslcat

# Start with custom configuration file
sslcat -config /path/to/sslcat.conf

# Start with specific host and port
sslcat -host 0.0.0.0 -port 80 -ssl-port 443

# Start in debug mode
sslcat -debug

# Start with custom log level
sslcat -log-level debug
```

### Configuration Management
```bash
# Validate configuration file
sslcat -config sslcat.conf -validate

# Test configuration without starting
sslcat -config sslcat.conf -test

# Dry run (check configuration and exit)
sslcat -config sslcat.conf -dry-run

# Show configuration
sslcat -config sslcat.conf -show-config
```

## Certificate Management

### SSL Certificate Operations
```bash
# Generate new certificate
sslcat cert generate -domain example.com -email admin@example.com

# Renew certificate
sslcat cert renew -domain example.com

# Renew all certificates
sslcat cert renew -all

# Check certificate status
sslcat cert status -domain example.com

# List all certificates
sslcat cert list

# Delete certificate
sslcat cert delete -domain example.com
```

### Let's Encrypt Integration
```bash
# Register with Let's Encrypt
sslcat cert register -email admin@example.com

# Generate certificate with Let's Encrypt
sslcat cert generate -domain example.com -provider letsencrypt

# Check Let's Encrypt rate limits
sslcat cert limits
```

## Proxy Management

### Proxy Rules
```bash
# List proxy rules
sslcat proxy list

# Add proxy rule
sslcat proxy add -domain api.example.com -target http://localhost:8080 -ssl

# Update proxy rule
sslcat proxy update -id rule-1 -target http://localhost:8081

# Delete proxy rule
sslcat proxy delete -id rule-1

# Test proxy rule
sslcat proxy test -domain api.example.com
```

### Load Balancing
```bash
# List backends
sslcat lb list

# Add backend
sslcat lb add -url http://localhost:8080 -weight 1

# Remove backend
sslcat lb remove -url http://localhost:8080

# Check backend health
sslcat lb health -url http://localhost:8080

# Update backend status
sslcat lb status -url http://localhost:8080 -status disabled
```

## Monitoring and Diagnostics

### System Information
```bash
# Show version information
sslcat version

# Show system information
sslcat system info

# Show configuration summary
sslcat config summary

# Show running processes
sslcat processes
```

### Health Checks
```bash
# Check SSLcat health
sslcat health

# Check specific component
sslcat health -component proxy
sslcat health -component ssl
sslcat health -component cache

# Detailed health report
sslcat health -detailed
```

### Metrics and Statistics
```bash
# Show current metrics
sslcat metrics

# Show metrics in JSON format
sslcat metrics -format json

# Show specific metrics
sslcat metrics -metric requests_total
sslcat metrics -metric response_time

# Export metrics
sslcat metrics -export -file metrics.json
```

### Logging
```bash
# Show logs
sslcat logs

# Show logs with specific level
sslcat logs -level error

# Show logs for specific component
sslcat logs -component proxy

# Follow logs in real-time
sslcat logs -follow

# Export logs
sslcat logs -export -file logs.json
```

## Cache Management

### Cache Operations
```bash
# Show cache statistics
sslcat cache stats

# Clear all cache
sslcat cache clear

# Clear cache by pattern
sslcat cache clear -pattern "*.css"

# Clear cache for specific domain
sslcat cache clear -domain example.com

# Show cache contents
sslcat cache list

# Warm cache
sslcat cache warm -url https://example.com/api/popular
```

## User Management

### User Operations
```bash
# List users
sslcat users list

# Create user
sslcat users create -username admin -email admin@example.com -role admin

# Update user
sslcat users update -username admin -role super-admin

# Delete user
sslcat users delete -username admin

# Change password
sslcat users password -username admin
```

## Backup and Restore

### Backup Operations
```bash
# Create backup
sslcat backup create

# Create backup with specific name
sslcat backup create -name backup-20240101

# List backups
sslcat backup list

# Show backup details
sslcat backup info -name backup-20240101

# Delete backup
sslcat backup delete -name backup-20240101
```

### Restore Operations
```bash
# Restore from backup
sslcat backup restore -name backup-20240101

# Restore specific configuration
sslcat backup restore -name backup-20240101 -config proxy

# Validate backup
sslcat backup validate -name backup-20240101
```

## Service Management

### Service Control
```bash
# Start service
sslcat service start

# Stop service
sslcat service stop

# Restart service
sslcat service restart

# Reload configuration
sslcat service reload

# Check service status
sslcat service status
```

### Process Management
```bash
# Show running processes
sslcat processes

# Kill specific process
sslcat processes kill -pid 1234

# Show process details
sslcat processes info -pid 1234
```

## Network Diagnostics

### Connectivity Tests
```bash
# Test connectivity to backend
sslcat test -url http://localhost:8080

# Test SSL connectivity
sslcat test -url https://example.com -ssl

# Test with specific headers
sslcat test -url https://example.com -header "X-Custom: value"

# Test load balancing
sslcat test -url https://example.com -backend http://localhost:8080
```

### DNS Resolution
```bash
# Resolve domain
sslcat dns resolve -domain example.com

# Check DNS propagation
sslcat dns check -domain example.com

# Test DNS from different locations
sslcat dns test -domain example.com -locations us,eu,asia
```

## Performance Tuning

### Performance Analysis
```bash
# Show performance metrics
sslcat performance

# Profile CPU usage
sslcat performance -cpu

# Profile memory usage
sslcat performance -memory

# Profile network usage
sslcat performance -network

# Generate performance report
sslcat performance -report -file performance.json
```

### Optimization
```bash
# Optimize configuration
sslcat optimize

# Check for optimization opportunities
sslcat optimize -check

# Apply optimizations
sslcat optimize -apply

# Revert optimizations
sslcat optimize -revert
```

## Security Operations

### Security Checks
```bash
# Run security audit
sslcat security audit

# Check SSL configuration
sslcat security ssl-check

# Check for vulnerabilities
sslcat security scan

# Generate security report
sslcat security report -file security.json
```

### Access Control
```bash
# List access rules
sslcat access list

# Add access rule
sslcat access add -ip 192.168.1.0/24 -action allow

# Remove access rule
sslcat access remove -ip 192.168.1.0/24

# Test access
sslcat access test -ip 192.168.1.100
```

## Troubleshooting

### Debug Commands
```bash
# Enable debug mode
sslcat -debug

# Set debug level
sslcat -debug -log-level debug

# Debug specific component
sslcat debug -component proxy

# Debug specific request
sslcat debug -request-id req-123456
```

### Diagnostic Tools
```bash
# Run diagnostics
sslcat diagnose

# Check system requirements
sslcat diagnose -system

# Check configuration
sslcat diagnose -config

# Check network
sslcat diagnose -network

# Generate diagnostic report
sslcat diagnose -report -file diagnostic.json
```

## Advanced Operations

### Plugin Management
```bash
# List plugins
sslcat plugins list

# Install plugin
sslcat plugins install -name custom-plugin

# Uninstall plugin
sslcat plugins uninstall -name custom-plugin

# Enable plugin
sslcat plugins enable -name custom-plugin

# Disable plugin
sslcat plugins disable -name custom-plugin
```

### API Management
```bash
# Generate API key
sslcat api key generate -user admin

# List API keys
sslcat api keys list

# Revoke API key
sslcat api key revoke -key abc123

# Test API endpoint
sslcat api test -endpoint /api/v1/config
```

## Configuration Examples

### Environment Variables
```bash
# Set environment variables
export SSLCAT_CONFIG=/path/to/sslcat.conf
export SSLCAT_LOG_LEVEL=debug
export SSLCAT_DEBUG=true

# Use environment variables
sslcat
```

### Configuration Files
```bash
# Use multiple configuration files
sslcat -config base.conf -config override.conf

# Include configuration from directory
sslcat -config-dir /etc/sslcat/conf.d

# Use configuration from URL
sslcat -config https://config.example.com/sslcat.conf
```

## Scripting and Automation

### Batch Operations
```bash
# Execute multiple commands
sslcat batch -file commands.txt

# Run commands in parallel
sslcat parallel -commands "sslcat health,sslcat metrics,sslcat logs"

# Schedule commands
sslcat schedule -command "sslcat backup create" -interval "0 2 * * *"
```

### Output Formats
```bash
# JSON output
sslcat metrics -format json

# YAML output
sslcat config -format yaml

# CSV output
sslcat logs -format csv

# Table output
sslcat users list -format table
```

## Best Practices

### Command Line Tips
1. **Use Configuration Files**: Prefer configuration files over command-line options
2. **Enable Logging**: Always enable appropriate logging for troubleshooting
3. **Use Health Checks**: Regularly check service health
4. **Monitor Metrics**: Set up monitoring for key metrics
5. **Backup Regularly**: Schedule regular configuration backups

### Security Considerations
1. **Secure API Keys**: Protect API keys and credentials
2. **Limit Access**: Use appropriate access controls
3. **Regular Updates**: Keep SSLcat updated
4. **Audit Logs**: Monitor and review audit logs
5. **Secure Communication**: Use HTTPS for all communications

## Related Documentation

- [Web Interface](web-interface.md)
- [Configuration Guide](../configuration/basic.md)
- [Troubleshooting](../troubleshooting/common-issues.md)
- [API Reference](../reference/api-reference.md)

---

*The CLI provides powerful tools for managing SSLcat in both interactive and automated environments.*
