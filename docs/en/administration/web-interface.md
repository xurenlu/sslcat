# Web Management Interface

SSLcat provides a modern, intuitive web-based management interface for configuring, monitoring, and managing your proxy server.

## Accessing the Interface

### Default Access
- **URL**: `http://localhost:18080/admin` (or your configured admin port)
- **Default Username**: `admin`
- **Default Password**: `admin123` (change immediately!)

### Custom Configuration
```json
{
  "server": {
    "admin": {
      "enabled": true,
      "host": "0.0.0.0",
      "port": 18080,
      "path": "/admin",
      "auth": {
        "username": "admin",
        "password": "your-secure-password"
      }
    }
  }
}
```

## Dashboard Overview

The main dashboard provides a comprehensive overview of your SSLcat instance:

### Key Metrics
- **Request Rate**: Requests per second
- **Response Time**: Average response time
- **Active Connections**: Current active connections
- **SSL Certificates**: Certificate status and expiration
- **Backend Health**: Status of all backend services

### Real-time Monitoring
- **Live Request Log**: Real-time request/response logs
- **Performance Charts**: CPU, memory, and network usage
- **Error Tracking**: Failed requests and error rates
- **Traffic Analysis**: Request patterns and trends

## Configuration Management

### Proxy Rules
Create and manage proxy rules through the web interface:

#### Basic Proxy Rule
```json
{
  "domain": "example.com",
  "target": "http://backend:8080",
  "ssl": true
}
```

#### Advanced Proxy Rule
```json
{
  "domain": "api.example.com",
  "target": "http://api-backend:8080",
  "ssl": true,
  "load_balancing": {
    "enabled": true,
    "algorithm": "round_robin",
    "backends": [
      "http://api-1:8080",
      "http://api-2:8080",
      "http://api-3:8080"
    ]
  },
  "health_check": {
    "enabled": true,
    "path": "/health",
    "interval": "30s"
  }
}
```

### SSL Certificate Management
- **Automatic Certificates**: Let's Encrypt integration
- **Manual Certificates**: Upload custom certificates
- **Certificate Monitoring**: Expiration alerts and renewal
- **Domain Management**: Add/remove domains

### Load Balancing Configuration
- **Algorithm Selection**: Round-robin, least connections, IP hash
- **Backend Management**: Add/remove backend servers
- **Health Checks**: Configure health check endpoints
- **Failover Settings**: Automatic failover configuration

## Monitoring and Analytics

### Real-time Metrics
- **Request Volume**: Requests per second/minute/hour
- **Response Times**: P50, P95, P99 response times
- **Error Rates**: 4xx and 5xx error percentages
- **SSL Metrics**: Certificate status and SSL handshake times

### Historical Data
- **Performance Trends**: Long-term performance analysis
- **Traffic Patterns**: Request patterns over time
- **Error Analysis**: Error rate trends and patterns
- **Capacity Planning**: Resource usage trends

### Alerting
- **Threshold Alerts**: Set custom alert thresholds
- **Email Notifications**: Configure email alerts
- **Webhook Integration**: Send alerts to external systems
- **Dashboard Alerts**: Visual alerts in the interface

## User Management

### Authentication
- **Local Users**: Manage local user accounts
- **LDAP Integration**: Connect to LDAP/Active Directory
- **OAuth Integration**: Support for OAuth providers
- **Multi-factor Authentication**: Enable 2FA for security

### Authorization
- **Role-based Access**: Define user roles and permissions
- **Resource Access**: Control access to specific features
- **API Access**: Manage API key permissions
- **Audit Logging**: Track user actions and changes

## API Management

### REST API Access
The web interface provides access to the full REST API:

```bash
# Get current configuration
curl -H "Authorization: Bearer your-token" \
     http://localhost:18080/api/v1/config

# Update proxy rules
curl -X PUT -H "Authorization: Bearer your-token" \
     -H "Content-Type: application/json" \
     -d '{"domain":"example.com","target":"http://backend:8080"}' \
     http://localhost:18080/api/v1/proxy/rules
```

### API Documentation
- **Interactive API Docs**: Built-in Swagger/OpenAPI documentation
- **Code Examples**: Sample code for common operations
- **SDK Downloads**: Download SDKs for various languages
- **Webhook Configuration**: Set up webhook endpoints

## Backup and Restore

### Configuration Backup
- **Automatic Backups**: Scheduled configuration backups
- **Manual Backups**: On-demand backup creation
- **Version History**: Track configuration changes
- **Export Options**: Export configurations in various formats

### Restore Operations
- **Point-in-time Recovery**: Restore to specific points
- **Selective Restore**: Restore specific configuration sections
- **Validation**: Validate configurations before restore
- **Rollback**: Quick rollback to previous configurations

## Security Features

### Access Control
- **IP Whitelisting**: Restrict access by IP address
- **Session Management**: Configure session timeouts
- **Password Policies**: Enforce strong password requirements
- **Login Attempts**: Limit failed login attempts

### Audit Logging
- **User Actions**: Log all user actions and changes
- **Configuration Changes**: Track configuration modifications
- **Access Logs**: Monitor access patterns
- **Security Events**: Log security-related events

## Troubleshooting

### Common Issues

1. **Cannot Access Web Interface**
   - Check if admin interface is enabled
   - Verify port configuration
   - Check firewall settings
   - Verify authentication credentials

2. **Performance Issues**
   - Monitor resource usage
   - Check for memory leaks
   - Verify backend health
   - Review configuration complexity

3. **Configuration Errors**
   - Validate YAML syntax
   - Check proxy rule configuration
   - Verify SSL certificate settings
   - Review load balancing configuration

### Debug Mode
Enable debug mode for detailed logging:

```json
{
  "server": {
    "debug": true,
    "admin": {
      "debug": true,
      "log_level": "DEBUG"
    }
  }
}
```

## Best Practices

### Security
1. **Change Default Credentials**: Immediately change default admin password
2. **Use HTTPS**: Enable HTTPS for the admin interface
3. **Regular Updates**: Keep SSLcat updated to latest version
4. **Access Control**: Implement proper access controls
5. **Audit Logging**: Enable comprehensive audit logging

### Performance
1. **Resource Monitoring**: Monitor CPU and memory usage
2. **Configuration Optimization**: Optimize proxy rules
3. **Caching**: Enable appropriate caching strategies
4. **Load Balancing**: Configure efficient load balancing
5. **Health Checks**: Implement proper health monitoring

### Maintenance
1. **Regular Backups**: Schedule automatic backups
2. **Configuration Review**: Regularly review configurations
3. **Security Updates**: Apply security updates promptly
4. **Performance Tuning**: Continuously optimize performance
5. **Documentation**: Maintain configuration documentation

## Related Documentation

- [CLI Commands](cli-commands.md)
- [User Management](user-management.md)
- [Backup & Restore](backup-restore.md)
- [Security Configuration](../configuration/security.md)
- [Monitoring](../features/monitoring.md)

---

*The web management interface provides a powerful and intuitive way to manage your SSLcat instance without needing to edit configuration files directly.*
