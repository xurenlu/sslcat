# SSLcat Port Configuration Design

## 🎯 Design Goals

1. **Simplify User Experience**: Default to listening on ports 80 and 443
2. **Clear Feature Selection**: Users must actively enable "custom port" to modify
3. **Clear Function Description**: Inform users of the impact of their choices
4. **Backward Compatibility**: Maintain compatibility with existing configurations

## 📋 Current Problem Analysis

### Configuration Inconsistency
- **Frontend Display**: `httpPort: '80'`, `httpsPort: '443'`
- **Backend Reality**: Only one `server.port` configuration item
- **Hidden Rule**: Port 443 automatically listens on port 80

### User Experience Confusion
- Users see two port settings but only one actually controls
- No clear explanation of port configuration rules and limitations
- Users don't know that modifying ports will lose HTTPS functionality

## 🎨 New Design Solution

### 1. Configuration Structure Changes

```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "standard",  // "standard" | "custom"
    "port": 80,              // HTTP port (standard mode)
    "ssl_port": 443,         // HTTPS port (standard mode)
    "custom_port": 8080,     // Custom port (custom mode)
    "enable_https": true     // HTTPS support (standard mode only)
  }
}
```

### 2. Port Mode Explanation

#### Standard Mode (Default)
- **HTTP Port**: 80
- **HTTPS Port**: 443
- **Features**: Full SSL certificate management
- **Use Case**: Production environments

#### Custom Mode
- **Port**: User-defined (e.g., 8080)
- **Protocol**: HTTP only
- **Features**: No SSL certificate management
- **Use Case**: Development, internal networks, reverse proxy backend

### 3. Frontend Interface Design

#### Port Mode Selection
```html
<div class="port-mode-selection">
  <label>
    <input type="radio" name="port_mode" value="standard" checked>
    Standard Mode (Ports 80 & 443)
  </label>
  <label>
    <input type="radio" name="port_mode" value="custom">
    Custom Mode (Single Port)
  </label>
</div>
```

#### Standard Mode Configuration
```html
<div class="standard-mode-config" v-if="portMode === 'standard'">
  <div class="form-group">
    <label>HTTP Port</label>
    <input type="number" v-model="httpPort" value="80" readonly>
    <small>Standard HTTP port (read-only)</small>
  </div>
  <div class="form-group">
    <label>HTTPS Port</label>
    <input type="number" v-model="httpsPort" value="443" readonly>
    <small>Standard HTTPS port (read-only)</small>
  </div>
  <div class="form-group">
    <label>
      <input type="checkbox" v-model="enableHttps" checked>
      Enable HTTPS Support
    </label>
    <small>Automatic SSL certificate management</small>
  </div>
</div>
```

#### Custom Mode Configuration
```html
<div class="custom-mode-config" v-if="portMode === 'custom'">
  <div class="form-group">
    <label>Custom Port</label>
    <input type="number" v-model="customPort" placeholder="8080">
    <small>Single port for HTTP only</small>
  </div>
  <div class="warning">
    <strong>⚠️ Warning:</strong> Custom mode disables HTTPS support and SSL certificate management.
  </div>
</div>
```

## 🔧 Implementation Details

### 1. Backend Configuration Validation

```go
type ServerConfig struct {
    Host        string `json:"host"`
    PortMode    string `json:"port_mode"`
    Port        int    `json:"port"`
    SSLPort     int    `json:"ssl_port"`
    CustomPort  int    `json:"custom_port"`
    EnableHTTPS bool   `json:"enable_https"`
}

func (c *ServerConfig) Validate() error {
    switch c.PortMode {
    case "standard":
        if c.Port != 80 || c.SSLPort != 443 {
            return errors.New("standard mode requires ports 80 and 443")
        }
        if !c.EnableHTTPS {
            return errors.New("standard mode requires HTTPS enabled")
        }
    case "custom":
        if c.CustomPort <= 0 || c.CustomPort > 65535 {
            return errors.New("invalid custom port")
        }
        if c.EnableHTTPS {
            return errors.New("custom mode does not support HTTPS")
        }
    default:
        return errors.New("invalid port mode")
    }
    return nil
}
```

### 2. Server Startup Logic

```go
func (s *Server) Start() error {
    switch s.Config.Server.PortMode {
    case "standard":
        return s.startStandardMode()
    case "custom":
        return s.startCustomMode()
    default:
        return errors.New("invalid port mode")
    }
}

func (s *Server) startStandardMode() error {
    // Start HTTP server on port 80
    go s.startHTTPServer(":80")
    
    // Start HTTPS server on port 443
    return s.startHTTPSServer(":443")
}

func (s *Server) startCustomMode() error {
    // Start HTTP server on custom port
    return s.startHTTPServer(fmt.Sprintf(":%d", s.Config.Server.CustomPort))
}
```

### 3. Frontend State Management

```javascript
const portConfiguration = {
  data() {
    return {
      portMode: 'standard',
      httpPort: 80,
      httpsPort: 443,
      customPort: 8080,
      enableHttps: true
    }
  },
  computed: {
    isStandardMode() {
      return this.portMode === 'standard'
    },
    isCustomMode() {
      return this.portMode === 'custom'
    },
    canEditPorts() {
      return this.portMode === 'custom'
    }
  },
  methods: {
    onPortModeChange() {
      if (this.portMode === 'standard') {
        this.httpPort = 80
        this.httpsPort = 443
        this.enableHttps = true
      } else {
        this.customPort = 8080
        this.enableHttps = false
      }
    }
  }
}
```

## 📊 Migration Strategy

### 1. Backward Compatibility

```go
func (c *ServerConfig) MigrateFromOldFormat(oldConfig map[string]interface{}) {
    // Check if old format
    if port, exists := oldConfig["port"]; exists {
        if port == 443 {
            // Old HTTPS configuration
            c.PortMode = "standard"
            c.Port = 80
            c.SSLPort = 443
            c.EnableHTTPS = true
        } else {
            // Old custom port configuration
            c.PortMode = "custom"
            c.CustomPort = port.(int)
            c.EnableHTTPS = false
        }
    }
}
```

### 2. Configuration Upgrade

```go
func UpgradeConfiguration(configPath string) error {
    // Read old configuration
    oldConfig, err := readOldConfig(configPath)
    if err != nil {
        return err
    }
    
    // Create new configuration
    newConfig := &Config{
        Server: ServerConfig{
            PortMode: "standard", // Default to standard mode
        },
    }
    
    // Migrate settings
    newConfig.Server.MigrateFromOldFormat(oldConfig)
    
    // Save new configuration
    return saveNewConfig(configPath, newConfig)
}
```

## 🎯 User Experience Improvements

### 1. Clear Mode Selection

```html
<div class="port-mode-explanation">
  <h3>Choose Port Configuration Mode</h3>
  
  <div class="mode-option">
    <h4>Standard Mode (Recommended)</h4>
    <p>Listen on ports 80 and 443 with full HTTPS support</p>
    <ul>
      <li>✅ Automatic SSL certificate management</li>
      <li>✅ HTTP to HTTPS redirection</li>
      <li>✅ Production-ready configuration</li>
    </ul>
  </div>
  
  <div class="mode-option">
    <h4>Custom Mode</h4>
    <p>Listen on a single custom port (HTTP only)</p>
    <ul>
      <li>⚠️ No SSL certificate management</li>
      <li>⚠️ HTTP protocol only</li>
      <li>✅ Suitable for development</li>
    </ul>
  </div>
</div>
```

### 2. Configuration Warnings

```javascript
const warnings = {
  customMode: {
    title: "Custom Mode Limitations",
    message: "Custom mode disables HTTPS support and SSL certificate management. This is suitable for development or internal networks only.",
    type: "warning"
  },
  standardMode: {
    title: "Standard Mode Benefits",
    message: "Standard mode provides full HTTPS support with automatic SSL certificate management. Recommended for production environments.",
    type: "info"
  }
}
```

## 📚 Related Documentation

- [Port Configuration Guide](port-configuration-guide.md)
- [Basic Configuration](basic.md)
- [SSL Certificates](ssl-certificates.md)
- [Troubleshooting](../troubleshooting/common-issues.md)
