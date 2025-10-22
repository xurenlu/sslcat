#!/bin/bash

# SSLcat Documentation Organization Script
# This script organizes existing documentation into the new structure

set -e

DOCS_DIR="/Users/rocky/Sites/sslcat/docs"
EN_DIR="$DOCS_DIR/en"
ZH_DIR="$DOCS_DIR/zh"

echo "🚀 Starting SSLcat documentation organization..."

# Create directory structure for English docs
echo "📁 Creating English documentation structure..."
mkdir -p "$EN_DIR/features"
mkdir -p "$EN_DIR/configuration"
mkdir -p "$EN_DIR/administration"
mkdir -p "$EN_DIR/api"
mkdir -p "$EN_DIR/deployment"
mkdir -p "$EN_DIR/integration"
mkdir -p "$EN_DIR/examples"
mkdir -p "$EN_DIR/troubleshooting"
mkdir -p "$EN_DIR/development"
mkdir -p "$EN_DIR/reference"

# Create directory structure for Chinese docs
echo "📁 Creating Chinese documentation structure..."
mkdir -p "$ZH_DIR/features"
mkdir -p "$ZH_DIR/configuration"
mkdir -p "$ZH_DIR/administration"
mkdir -p "$ZH_DIR/api"
mkdir -p "$ZH_DIR/deployment"
mkdir -p "$ZH_DIR/integration"
mkdir -p "$ZH_DIR/examples"
mkdir -p "$ZH_DIR/troubleshooting"
mkdir -p "$ZH_DIR/development"
mkdir -p "$ZH_DIR/reference"

# Move existing files to appropriate locations
echo "📄 Organizing existing documentation..."

# Move feature-related docs
if [ -f "$DOCS_DIR/HTTP2_IMPLEMENTATION.md" ]; then
    cp "$DOCS_DIR/HTTP2_IMPLEMENTATION.md" "$EN_DIR/features/http2.md"
    echo "✅ Moved HTTP2_IMPLEMENTATION.md to features/http2.md"
fi

if [ -f "$DOCS_DIR/HTTP2_SUPPORT_ANALYSIS.md" ]; then
    cp "$DOCS_DIR/HTTP2_SUPPORT_ANALYSIS.md" "$EN_DIR/features/http2-analysis.md"
    echo "✅ Moved HTTP2_SUPPORT_ANALYSIS.md to features/http2-analysis.md"
fi

if [ -f "$DOCS_DIR/COMPRESSION_CACHE_GUIDE.md" ]; then
    cp "$DOCS_DIR/COMPRESSION_CACHE_GUIDE.md" "$EN_DIR/features/compression.md"
    echo "✅ Moved COMPRESSION_CACHE_GUIDE.md to features/compression.md"
fi

if [ -f "$DOCS_DIR/UNIFIED_CACHE_MANAGER.md" ]; then
    cp "$DOCS_DIR/UNIFIED_CACHE_MANAGER.md" "$EN_DIR/features/caching.md"
    echo "✅ Moved UNIFIED_CACHE_MANAGER.md to features/caching.md"
fi

# Move configuration docs
if [ -f "$DOCS_DIR/port-configuration-guide.md" ]; then
    cp "$DOCS_DIR/port-configuration-guide.md" "$EN_DIR/configuration/ports.md"
    echo "✅ Moved port-configuration-guide.md to configuration/ports.md"
fi

# Move troubleshooting docs
if [ -f "$DOCS_DIR/CPU_TROUBLESHOOTING_GUIDE.md" ]; then
    cp "$DOCS_DIR/CPU_TROUBLESHOOTING_GUIDE.md" "$EN_DIR/troubleshooting/performance.md"
    echo "✅ Moved CPU_TROUBLESHOOTING_GUIDE.md to troubleshooting/performance.md"
fi

if [ -f "$DOCS_DIR/LOGGING_AND_PERFORMANCE_OPTIMIZATION.md" ]; then
    cp "$DOCS_DIR/LOGGING_AND_PERFORMANCE_OPTIMIZATION.md" "$EN_DIR/troubleshooting/logging.md"
    echo "✅ Moved LOGGING_AND_PERFORMANCE_OPTIMIZATION.md to troubleshooting/logging.md"
fi

# Move deployment docs
if [ -f "$DOCS_DIR/docker-compose-deploy.md" ]; then
    cp "$DOCS_DIR/docker-compose-deploy.md" "$EN_DIR/deployment/docker.md"
    echo "✅ Moved docker-compose-deploy.md to deployment/docker.md"
fi

# Move development docs
if [ -f "$DOCS_DIR/builder-architecture.md" ]; then
    cp "$DOCS_DIR/builder-architecture.md" "$EN_DIR/development/architecture.md"
    echo "✅ Moved builder-architecture.md to development/architecture.md"
fi

# Create quick start guide
echo "📝 Creating quick start guide..."
cat > "$EN_DIR/getting-started/quick-start.md" << 'EOF'
# Quick Start Guide

Get SSLcat running in 5 minutes with this quick start guide.

## Prerequisites

- Linux, macOS, or Windows
- Go 1.21+ (for building from source)
- Docker (for container deployment)

## Installation

### Option 1: Download Binary
```bash
# Download the latest release
curl -L https://github.com/xurenlu/sslcat/releases/latest/download/sslcat_linux_amd64.tar.gz | tar xz
sudo mv sslcat /usr/local/bin/
```

### Option 2: Docker
```bash
docker run -d --name sslcat \
  -p 80:80 -p 443:443 \
  -v $(pwd)/sslcat.conf:/app/sslcat.conf \
  xurenlu/sslcat:latest
```

## Basic Configuration

Create a basic configuration file:

```yaml
# sslcat.conf
server:
  host: "0.0.0.0"
  port: 80
  ssl_port: 443

proxy:
  rules:
    - domain: "example.com"
      target: "http://localhost:8080"
      ssl: true
```

## Start SSLcat

```bash
# Start with configuration file
sslcat -config sslcat.conf

# Or start with Docker
docker run -d --name sslcat \
  -p 80:80 -p 443:443 \
  -v $(pwd)/sslcat.conf:/app/sslcat.conf \
  xurenlu/sslcat:latest
```

## Test Your Setup

```bash
# Test HTTP
curl http://example.com

# Test HTTPS (if SSL is configured)
curl https://example.com
```

## Next Steps

- [Configuration Guide](../configuration/basic.md)
- [SSL Certificates](../configuration/ssl-certificates.md)
- [Load Balancing](../features/load-balancing.md)
EOF

# Create architecture overview
echo "📝 Creating architecture overview..."
cat > "$EN_DIR/getting-started/architecture.md" << 'EOF'
# Architecture Overview

SSLcat is designed as a high-performance, enterprise-grade SSL proxy server with a modular architecture.

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client        │    │   SSLcat        │    │   Backend       │
│   (Browser)     │◄──►│   Proxy         │◄──►│   Services      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Management    │
                       │   Interface     │
                       └─────────────────┘
```

## Core Components

### 1. SSL Termination Layer
- Handles SSL/TLS encryption and decryption
- Automatic certificate management
- Modern cipher suite support
- Certificate monitoring and renewal

### 2. Proxy Engine
- Request routing and forwarding
- Header management and modification
- Protocol support (HTTP/1.1, HTTP/2, WebSocket)
- Request/response processing

### 3. Load Balancer
- Multiple balancing algorithms
- Health checking and monitoring
- Automatic failover
- Session persistence

### 4. Cache Manager
- Multi-layer caching system
- CDN integration
- Compression support
- Cache invalidation

### 5. Monitoring System
- Distributed tracing
- Metrics collection
- Logging and alerting
- Performance monitoring

## Data Flow

1. **Request Reception**: Client sends request to SSLcat
2. **SSL Processing**: SSL termination and certificate validation
3. **Routing Decision**: Determine target backend based on rules
4. **Load Balancing**: Select healthy backend if multiple available
5. **Request Forwarding**: Forward request with proper headers
6. **Response Processing**: Handle response from backend
7. **Caching**: Store response in cache if applicable
8. **Response Delivery**: Send response to client

## Scalability

SSLcat is designed for horizontal scaling:
- Stateless architecture
- Shared configuration
- Distributed caching
- Load balancer integration

## Security

- Built-in DDoS protection
- Rate limiting
- IP filtering
- Security headers
- Access control
EOF

echo "✅ Documentation organization completed!"
echo ""
echo "📚 New documentation structure:"
echo "   - English docs: $EN_DIR"
echo "   - Chinese docs: $ZH_DIR"
echo ""
echo "🎯 Next steps:"
echo "   1. Review the organized documentation"
echo "   2. Translate content to Chinese"
echo "   3. Add missing documentation"
echo "   4. Update links and references"
echo ""
echo "✨ Documentation is now organized like a comprehensive book!"
