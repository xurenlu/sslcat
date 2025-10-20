# SSLcat Architecture Overview

This document provides a comprehensive overview of SSLcat's architecture, components, and how they work together to provide SSL proxy functionality.

## 🏗️ System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SSLcat System                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Web Client   │  │   API Client    │  │  Proxy Client   │  │
│  │   (Browser)    │  │   (REST/WS)     │  │   (HTTPS/HTTP)  │  │
│  └─────────┬───────┘  └─────────┬───────┘  └─────────┬───────┘  │
│            │                    │                    │          │
│            └────────────────────┼────────────────────┘          │
│                                 │                               │
│  ┌─────────────────────────────▼─────────────────────────────┐  │
│  │                SSLcat Core Engine                        │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              Request Router                         │  │  │
│  │  │  • Domain Resolution                               │  │  │
│  │  │  • Path Matching                                   │  │  │
│  │  │  • Rule Evaluation                                 │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              SSL Manager                           │  │  │
│  │  │  • Certificate Management                          │  │  │
│  │  │  • Let's Encrypt Integration                       │  │  │
│  │  │  • Auto-renewal                                    │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              Proxy Engine                          │  │  │
│  │  │  • HTTP/HTTPS Forwarding                           │  │  │
│  │  │  • WebSocket Support                               │  │  │
│  │  │  • Load Balancing                                  │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │              Security Layer                        │  │  │
│  │  │  • IP Blocking                                     │  │  │
│  │  │  • Rate Limiting                                   │  │  │
│  │  │  • Access Control                                   │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              Web Management Interface                  │  │
│  │  • Dashboard                                           │  │
│  │  • Configuration Management                            │  │
│  │  • Monitoring & Logs                                   │  │
│  │  • User Management                                     │  │
│  └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Backend Services                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Web Apps     │  │   API Services  │  │  Other Services │  │
│  │   (Port 8080)  │  │   (Port 3000)  │  │   (Port 5000)  │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 🔧 Core Components

### 1. Request Router
The request router is the entry point for all incoming requests. It handles:

- **Domain Resolution**: Determines which proxy rule applies to the request
- **Path Matching**: Matches request paths against configured rules
- **Rule Evaluation**: Applies the appropriate proxy configuration
- **Protocol Detection**: Identifies HTTP vs HTTPS requests

### 2. SSL Manager
The SSL manager handles all certificate-related operations:

- **Certificate Acquisition**: Requests certificates from Let's Encrypt
- **Certificate Storage**: Manages certificate files and metadata
- **Auto-renewal**: Monitors certificate expiration and renews automatically
- **Certificate Validation**: Validates certificate chain and trust

### 3. Proxy Engine
The proxy engine handles the actual forwarding of requests:

- **HTTP/HTTPS Forwarding**: Forwards requests to backend services
- **WebSocket Support**: Handles WebSocket connections
- **Load Balancing**: Distributes load across multiple backends
- **Health Checking**: Monitors backend service health

### 4. Security Layer
The security layer provides protection and access control:

- **IP Blocking**: Blocks malicious IP addresses
- **Rate Limiting**: Prevents abuse and DoS attacks
- **Access Control**: Manages user permissions and authentication
- **Audit Logging**: Records security events and access attempts

## 🔄 Request Flow

### 1. Incoming Request
```
Client Request → SSLcat Server (Port 443/80)
```

### 2. SSL Termination
```
HTTPS Request → SSL Certificate Validation → Decrypt Request
```

### 3. Domain Resolution
```
Request → Domain Lookup → Proxy Rule Matching
```

### 4. Backend Forwarding
```
Matched Rule → Backend Service → Response Processing
```

### 5. Response Delivery
```
Backend Response → SSL Encryption → Client Response
```

## 📊 Data Flow Architecture

### Configuration Management
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Interface │───▶│  Config Parser  │───▶│  Rule Engine    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Config Storage │    │  Runtime State  │
                       └─────────────────┘    └─────────────────┘
```

### Certificate Management
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Let's Encrypt  │───▶│  SSL Manager    │───▶│  Certificate    │
│     API         │    │                 │    │    Storage      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Auto-renewal   │    │  Certificate   │
                       │    Scheduler    │    │    Cache       │
                       └─────────────────┘    └─────────────────┘
```

## 🗄️ Storage Architecture

### Configuration Storage
- **Primary Config**: `/etc/sslcat/sslcat.conf` (JSON format)
- **Backup Config**: `/opt/sslcat/backup/sslcat.conf.backup`
- **Runtime Config**: In-memory configuration cache

### Certificate Storage
- **Certificate Files**: `/opt/sslcat/certs/domain.crt`
- **Private Keys**: `/opt/sslcat/keys/domain.key`
- **Certificate Metadata**: `/opt/sslcat/data/certificates.json`

### Log Storage
- **Access Logs**: `/opt/sslcat/logs/access.log`
- **Error Logs**: `/opt/sslcat/logs/error.log`
- **Security Logs**: `/opt/sslcat/logs/security.log`

### Data Storage
- **User Data**: `/opt/sslcat/data/users.json`
- **Session Data**: `/opt/sslcat/data/sessions.json`
- **Statistics**: `/opt/sslcat/data/statistics.json`

## 🔐 Security Architecture

### Authentication Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Login    │───▶│  Auth Manager   │───▶│  Session Store  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Token Manager  │    │  Permission     │
                       │                 │    │  Validator      │
                       └─────────────────┘    └─────────────────┘
```

### Security Layers
1. **Network Security**: TLS encryption, certificate validation
2. **Application Security**: Input validation, output encoding
3. **Access Control**: Role-based permissions, API authentication
4. **Audit Security**: Comprehensive logging, security monitoring

## 🚀 Performance Architecture

### Connection Pooling
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Client Request │───▶│  Connection     │───▶│  Backend        │
│                 │    │     Pool        │    │   Service       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Caching Strategy
- **Certificate Cache**: In-memory certificate storage
- **Configuration Cache**: Runtime configuration cache
- **Response Cache**: Static content caching
- **DNS Cache**: Domain resolution caching

### Load Balancing
- **Round Robin**: Distribute requests evenly
- **Health Checks**: Monitor backend availability
- **Failover**: Automatic backend switching
- **Weighted Distribution**: Custom backend priorities

## 🔧 Configuration Architecture

### Configuration Hierarchy
1. **Command Line**: Highest priority
2. **Environment Variables**: Second priority
3. **Configuration File**: Default settings
4. **Built-in Defaults**: Fallback values

### Configuration Validation
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Config Input   │───▶│  Schema         │───▶│  Validated      │
│                 │    │  Validator      │    │  Configuration  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📈 Monitoring Architecture

### Metrics Collection
- **System Metrics**: CPU, memory, disk usage
- **Application Metrics**: Request rates, response times
- **Security Metrics**: Failed logins, blocked IPs
- **Certificate Metrics**: Expiration dates, renewal status

### Logging Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │───▶│   Log Manager   │───▶│   Log Storage   │
│     Events      │    │                 │    │   (Files/DB)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔄 Deployment Architecture

### Single Instance
```
┌─────────────────┐
│   SSLcat        │
│   (Single)      │
└─────────────────┘
```

### High Availability
```
┌─────────────────┐    ┌─────────────────┐
│   SSLcat A      │    │   SSLcat B      │
│   (Primary)     │    │   (Secondary)   │
└─────────────────┘    └─────────────────┘
```

### Load Balanced
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load          │───▶│   SSLcat A      │    │   SSLcat B      │
│   Balancer      │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🛠️ Development Architecture

### Code Organization
```
sslcat/
├── main.go                 # Application entry point
├── internal/              # Internal packages
│   ├── config/           # Configuration management
│   ├── ssl/              # SSL certificate handling
│   ├── proxy/            # Proxy functionality
│   ├── security/         # Security features
│   ├── web/              # Web interface
│   └── graceful/         # Graceful restart
├── web/                  # Web assets
│   ├── templates/        # HTML templates
│   └── static/           # Static files
└── scripts/              # Utility scripts
```

### API Architecture
- **REST API**: HTTP-based API for configuration
- **WebSocket API**: Real-time communication
- **Internal API**: Inter-component communication
- **External API**: Third-party integrations

## 🔍 Troubleshooting Architecture

### Error Handling
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Error         │───▶│   Error         │───▶│   Error         │
│   Detection     │    │   Classification│    │   Response      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Health Monitoring
- **Service Health**: Process status, resource usage
- **Network Health**: Connectivity, latency
- **Certificate Health**: Validity, expiration
- **Backend Health**: Service availability, response times

---

*This architecture provides a solid foundation for SSLcat's functionality. For implementation details, see the [Development Guide](../development/setup.md).*
