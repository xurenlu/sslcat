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

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 80,
    "ssl_port": 443
  },
  "proxy": {
    "rules": [
      {
        "domain": "example.com",
        "target": "http://localhost:8080",
        "ssl": true
      }
    ]
  }
}
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
