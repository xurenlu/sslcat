# SSLcat Builder Architecture Documentation

## Overview

SSLcat uses a plugin-based Builder architecture to support automatic building and deployment of multiple programming languages and frameworks. Each language has a corresponding Builder implementation responsible for detecting, building, and starting applications.

## Architecture Design

### Core Components

1. **AppBuilder Interface**: Defines methods that all Builders must implement
2. **BaseBuilder**: Provides common functionality base implementation
3. **BuilderRegistry**: Manages registration of all Builders
4. **Language-specific Builders**: Specific implementations for each language

### Interface Definition

```go
type AppBuilder interface {
    Detect(appPath string) (bool, error)          // Detect application type
    GetType() string                               // Get type identifier
    GetDisplayName() string                        // Get display name
    Build(app *GitApp) error                       // Build application
    BuildWithLogging(app *GitApp, logger *DeployLogger) error  // Build with logging
    Start(app *GitApp) error                       // Start application
    StartWithLogging(app *GitApp, logger *DeployLogger) error  // Start with logging
    GetDefaultPort() int                           // Get default port
    GetHealthCheckPath() string                    // Get health check path
}
```

## Supported Languages and Frameworks

### 1. Node.js (`nodejs`)
**Detection File**: `package.json`

**Supported Package Managers**:
- npm (default)
- yarn (`yarn.lock`)
- pnpm (`pnpm-lock.yaml`)

**Supported Frameworks**:
- Express
- Koa
- Fastify
- Next.js
- Nest.js
- Any Node.js application

**Default Port**: 3000

**Build Process**:
1. Install dependencies using detected package manager
2. Run build script if available
3. Start application using start script or main file

### 2. Python (`python`)
**Detection Files**: `requirements.txt`, `pyproject.toml`, `Pipfile`

**Supported Frameworks**:
- Flask
- Django
- FastAPI
- Bottle
- Any WSGI/ASGI application

**Default Port**: 8000

**Build Process**:
1. Create virtual environment
2. Install dependencies
3. Run application with appropriate server

### 3. Go (`go`)
**Detection Files**: `go.mod`, `main.go`

**Supported Frameworks**:
- Standard library
- Gin
- Echo
- Fiber
- Any Go web application

**Default Port**: 8080

**Build Process**:
1. Download dependencies
2. Build binary
3. Run binary

### 4. Java (`java`)
**Detection Files**: `pom.xml`, `build.gradle`, `build.gradle.kts`

**Supported Frameworks**:
- Spring Boot
- Spring MVC
- JAX-RS
- Any JVM web application

**Default Port**: 8080

**Build Process**:
1. Install dependencies
2. Compile application
3. Run with appropriate JVM arguments

### 5. PHP (`php`)
**Detection Files**: `composer.json`, `index.php`

**Supported Frameworks**:
- Laravel
- Symfony
- CodeIgniter
- Any PHP web application

**Default Port**: 8000

**Build Process**:
1. Install Composer dependencies
2. Configure PHP settings
3. Start PHP server

### 6. Ruby (`ruby`)
**Detection Files**: `Gemfile`, `config.ru`

**Supported Frameworks**:
- Rails
- Sinatra
- Rack
- Any Ruby web application

**Default Port**: 3000

**Build Process**:
1. Install Bundler dependencies
2. Run application with appropriate server

### 7. Static (`static`)
**Detection Files**: `index.html`, `package.json` (with build scripts)

**Supported Types**:
- HTML/CSS/JavaScript
- React (built)
- Vue (built)
- Angular (built)
- Any static website

**Default Port**: 80

**Build Process**:
1. Serve static files
2. Configure web server

## Builder Implementation

### BaseBuilder

All language-specific builders inherit from `BaseBuilder`, which provides:

```go
type BaseBuilder struct {
    Type        string
    DisplayName string
    DefaultPort int
}

func (b *BaseBuilder) GetType() string
func (b *BaseBuilder) GetDisplayName() string
func (b *BaseBuilder) GetDefaultPort() int
func (b *BaseBuilder) GetHealthCheckPath() string
```

### Builder Registry

The `BuilderRegistry` manages all available builders:

```go
type BuilderRegistry struct {
    builders map[string]AppBuilder
}

func (r *BuilderRegistry) Register(builder AppBuilder)
func (r *BuilderRegistry) GetBuilder(appType string) AppBuilder
func (r *BuilderRegistry) DetectAppType(appPath string) (string, error)
func (r *BuilderRegistry) GetAllBuilders() []AppBuilder
```

## Build Process

### 1. Detection Phase

```go
func (r *BuilderRegistry) DetectAppType(appPath string) (string, error) {
    for _, builder := range r.builders {
        if detected, err := builder.Detect(appPath); err != nil {
            return "", err
        } else if detected {
            return builder.GetType(), nil
        }
    }
    return "", errors.New("no supported application type detected")
}
```

### 2. Build Phase

```go
func (b *NodeJSBuilder) Build(app *GitApp) error {
    // 1. Install dependencies
    if err := b.installDependencies(app); err != nil {
        return err
    }
    
    // 2. Run build script if available
    if err := b.runBuildScript(app); err != nil {
        return err
    }
    
    // 3. Prepare start command
    if err := b.prepareStartCommand(app); err != nil {
        return err
    }
    
    return nil
}
```

### 3. Start Phase

```go
func (b *NodeJSBuilder) Start(app *GitApp) error {
    // 1. Set environment variables
    if err := b.setEnvironment(app); err != nil {
        return err
    }
    
    // 2. Start application process
    if err := b.startProcess(app); err != nil {
        return err
    }
    
    // 3. Wait for health check
    if err := b.waitForHealthCheck(app); err != nil {
        return err
    }
    
    return nil
}
```

## Configuration

### Builder Configuration

Each builder can be configured through the main SSLcat configuration:

```json
{
  "builders": {
    "nodejs": {
      "enabled": true,
      "default_port": 3000,
      "health_check_timeout": "30s",
      "build_timeout": "5m"
    },
    "python": {
      "enabled": true,
      "default_port": 8000,
      "health_check_timeout": "30s",
      "build_timeout": "5m"
    }
  }
}
```

### Application Configuration

Applications can override default settings:

```json
{
  "builders": {
    "nodejs": {
      "port": 3001,
      "health_check_path": "/health",
      "environment": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

## Error Handling

### Build Errors

```go
type BuildError struct {
    Type    string `json:"type"`
    Message string `json:"message"`
    Details string `json:"details"`
}

func (e *BuildError) Error() string {
    return fmt.Sprintf("build error [%s]: %s", e.Type, e.Message)
}
```

### Common Error Types

- `DependencyError`: Failed to install dependencies
- `BuildScriptError`: Build script execution failed
- `StartError`: Failed to start application
- `HealthCheckError`: Health check failed

## Logging

### DeployLogger

The `DeployLogger` provides structured logging for build and deployment processes:

```go
type DeployLogger struct {
    AppID   string
    UserID  string
    LogChan chan LogEntry
}

type LogEntry struct {
    Timestamp time.Time `json:"timestamp"`
    Level     string    `json:"level"`
    Message   string    `json:"message"`
    Data      map[string]interface{} `json:"data,omitempty"`
}
```

### Log Levels

- `INFO`: General information
- `WARN`: Warning messages
- `ERROR`: Error messages
- `DEBUG`: Debug information

## Extending the Builder System

### Creating a Custom Builder

1. Implement the `AppBuilder` interface:

```go
type CustomBuilder struct {
    *BaseBuilder
}

func (b *CustomBuilder) Detect(appPath string) (bool, error) {
    // Implement detection logic
    return false, nil
}

func (b *CustomBuilder) Build(app *GitApp) error {
    // Implement build logic
    return nil
}

func (b *CustomBuilder) Start(app *GitApp) error {
    // Implement start logic
    return nil
}
```

2. Register the builder:

```go
registry.Register(&CustomBuilder{
    BaseBuilder: &BaseBuilder{
        Type:        "custom",
        DisplayName: "Custom Application",
        DefaultPort: 9000,
    },
})
```

## Best Practices

### 1. Detection Logic
- Use multiple detection files when possible
- Check for framework-specific files
- Consider build tool configurations

### 2. Build Process
- Use appropriate package managers
- Handle different build scripts
- Support both development and production builds

### 3. Start Process
- Set appropriate environment variables
- Handle different start commands
- Implement proper health checks

### 4. Error Handling
- Provide clear error messages
- Include troubleshooting information
- Log detailed error information

## Troubleshooting

### Common Issues

1. **Detection Failures**
   - Check for required files
   - Verify file formats
   - Test detection logic

2. **Build Failures**
   - Check dependencies
   - Verify build scripts
   - Review error logs

3. **Start Failures**
   - Check port availability
   - Verify health check endpoints
   - Review application logs

### Debug Mode

Enable debug mode for detailed logging:

```json
{
  "server": {
    "debug": true
  },
  "builders": {
    "debug": true
  }
}
```

## Related Documentation

- [Git Deployment Guide](../deployment/git-deployment.md)
- [Application Configuration](../configuration/application.md)
- [Troubleshooting Guide](../troubleshooting/builder-issues.md)
