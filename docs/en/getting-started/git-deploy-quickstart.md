# Git Deployment Quick Start Guide

## Prerequisites

1. SSLcat server running normally
2. SSH access permissions
3. Git client installed

## Step 1: Set Up Git User

Create a git user on the server (if it doesn't exist):

```bash
sudo useradd -r -s /bin/bash -m -d /home/git git
```

## Step 2: Start SSLcat

SSLcat will automatically configure the SSH environment:

```bash
./sslcat
```

On first startup, SSLcat will:
- Create `/home/git/.ssh` directory
- Generate `authorized_keys` file
- Configure SSHD to use git-shell
- Create git-shell-commands directory

## Step 3: Add SSH Public Key

### Method 1: Through Web UI

1. Visit `https://your-domain/admin/git-server`
2. Click "SSH Keys" tab
3. Add your SSH public key

### Method 2: Through API

```bash
# Get your public key
cat ~/.ssh/id_rsa.pub

# Add to SSLcat
curl -X POST http://localhost:8080/admin/api/git-server/ssh-key/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "my-laptop",
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
  }'
```

### Method 3: Manual Setup

```bash
# Copy your public key to the server
ssh-copy-id git@your-server-ip

# Or manually add to authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." >> /home/git/.ssh/authorized_keys
```

## Step 4: Deploy Your First Application

### 4.1 Create a Simple Application

Create a simple Node.js application:

```bash
mkdir my-app
cd my-app

# Initialize package.json
npm init -y

# Install Express
npm install express

# Create app.js
cat > app.js << 'EOF'
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Hello from SSLcat!');
});

app.listen(port, () => {
  console.log(`App running on port ${port}`);
});
EOF

# Create package.json start script
npm pkg set scripts.start="node app.js"
```

### 4.2 Initialize Git Repository

```bash
git init
git add .
git commit -m "Initial commit"
```

### 4.3 Add SSLcat Remote

```bash
# Add SSLcat as remote
git remote add sslcat git@your-server-ip:my-app.git

# Push to deploy
git push sslcat main
```

## Step 5: Access Your Application

After successful deployment, your application will be available at:

- **HTTP**: `http://your-server-ip:3000`
- **HTTPS**: `https://your-server-ip:3000` (if SSL is configured)

## Supported Application Types

### Node.js Applications

**Detection**: `package.json` file

**Supported Frameworks**:
- Express
- Koa
- Fastify
- Next.js
- Nest.js

**Example**:
```json
{
  "name": "my-app",
  "version": "1.0.0",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "express": "^4.18.0"
  }
}
```

### Python Applications

**Detection**: `requirements.txt` or `pyproject.toml`

**Supported Frameworks**:
- Flask
- Django
- FastAPI
- Bottle

**Example**:
```python
# app.py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello from SSLcat!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

### Go Applications

**Detection**: `go.mod` or `main.go`

**Example**:
```go
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello from SSLcat!")
}

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}
```

### Static Websites

**Detection**: `index.html` or build output

**Supported**:
- HTML/CSS/JavaScript
- React (built)
- Vue (built)
- Angular (built)

## Configuration Options

### Application Configuration

Create `sslcat.json` in your project root:

```json
{
  "name": "my-app",
  "port": 3000,
  "environment": {
    "NODE_ENV": "production"
  },
  "health_check": {
    "path": "/health",
    "timeout": "30s"
  }
}
```

### SSL Configuration

```json
{
  "ssl": {
    "enabled": true,
    "domain": "my-app.example.com",
    "email": "admin@example.com"
  }
}
```

### Proxy Configuration

```json
{
  "proxy": {
    "rules": [
      {
        "domain": "my-app.example.com",
        "target": "http://localhost:3000",
        "ssl": true
      }
    ]
  }
}
```

## Advanced Features

### Environment Variables

Set environment variables for your application:

```json
{
  "environment": {
    "NODE_ENV": "production",
    "DATABASE_URL": "postgres://user:pass@localhost/db",
    "API_KEY": "your-api-key"
  }
}
```

### Health Checks

Configure health check endpoints:

```json
{
  "health_check": {
    "path": "/health",
    "timeout": "30s",
    "interval": "10s"
  }
}
```

### Custom Ports

Specify custom ports for your application:

```json
{
  "port": 8080,
  "ssl_port": 8443
}
```

## Troubleshooting

### Common Issues

1. **SSH Connection Failed**
   ```bash
   # Test SSH connection
   ssh -T git@your-server-ip
   
   # Check SSH key
   ssh-add -l
   ```

2. **Build Failed**
   ```bash
   # Check build logs
   curl http://localhost:8080/admin/api/git-server/logs/my-app
   ```

3. **Application Not Starting**
   ```bash
   # Check application logs
   curl http://localhost:8080/admin/api/git-server/logs/my-app/application
   ```

### Debug Mode

Enable debug mode for detailed logging:

```json
{
  "server": {
    "debug": true
  }
}
```

### Logs

View deployment logs:

```bash
# View deployment logs
curl http://localhost:8080/admin/api/git-server/logs/my-app

# View application logs
curl http://localhost:8080/admin/api/git-server/logs/my-app/application
```

## Best Practices

### 1. Repository Structure

```
my-app/
├── package.json          # Node.js dependencies
├── app.js                # Application entry point
├── sslcat.json          # SSLcat configuration
├── .gitignore           # Git ignore file
└── README.md            # Documentation
```

### 2. Environment Configuration

- Use environment variables for configuration
- Never commit secrets to git
- Use `.env` files for local development

### 3. Health Checks

- Implement health check endpoints
- Use appropriate timeouts
- Monitor application status

### 4. SSL Configuration

- Use Let's Encrypt for SSL certificates
- Configure proper domains
- Enable automatic renewal

## Related Documentation

- [Builder Architecture](../development/builder-architecture.md)
- [Port Configuration](../configuration/port-configuration-guide.md)
- [SSL Certificates](../configuration/ssl-certificates.md)
- [Troubleshooting](../troubleshooting/common-issues.md)
