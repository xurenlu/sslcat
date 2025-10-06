package runner

import (
	"fmt"
	"os"
	"path/filepath"
)

// AppBuilder 应用构建器接口
type AppBuilder interface {
	// Detect 检测是否支持该应用类型
	Detect(appPath string) (bool, error)

	// GetType 获取应用类型标识
	GetType() string

	// GetDisplayName 获取显示名称
	GetDisplayName() string

	// Build 构建应用（不带日志）
	Build(app *GitApp) error

	// BuildWithLogging 构建应用（带日志记录）
	BuildWithLogging(app *GitApp, logger *DeployLogger) error

	// Start 启动应用
	Start(app *GitApp) error

	// StartWithLogging 启动应用（带日志记录）
	StartWithLogging(app *GitApp, logger *DeployLogger) error

	// GetDefaultPort 获取默认端口
	GetDefaultPort() int

	// GetHealthCheckPath 获取健康检查路径
	GetHealthCheckPath() string
}

// BaseBuilder 基础构建器（提供通用功能）
type BaseBuilder struct {
	appType     string
	displayName string
	defaultPort int
	gs          *GitServer
}

// NewBaseBuilder 创建基础构建器
func NewBaseBuilder(appType, displayName string, defaultPort int, gs *GitServer) *BaseBuilder {
	return &BaseBuilder{
		appType:     appType,
		displayName: displayName,
		defaultPort: defaultPort,
		gs:          gs,
	}
}

// GetType 获取应用类型
func (b *BaseBuilder) GetType() string {
	return b.appType
}

// GetDisplayName 获取显示名称
func (b *BaseBuilder) GetDisplayName() string {
	return b.displayName
}

// GetDefaultPort 获取默认端口
func (b *BaseBuilder) GetDefaultPort() int {
	return b.defaultPort
}

// GetHealthCheckPath 获取健康检查路径
func (b *BaseBuilder) GetHealthCheckPath() string {
	return "/"
}

// fileExists 检查文件是否存在
func (b *BaseBuilder) fileExists(appPath, filename string) bool {
	_, err := os.Stat(filepath.Join(appPath, filename))
	return err == nil
}

// anyFileExists 检查任意文件是否存在
func (b *BaseBuilder) anyFileExists(appPath string, filenames []string) bool {
	for _, filename := range filenames {
		if b.fileExists(appPath, filename) {
			return true
		}
	}
	return false
}

// runCommand 执行命令
func (b *BaseBuilder) runCommand(workDir, command string, args ...string) error {
	return b.gs.runCommand(workDir, command, args...)
}

// runCommandWithLogging 执行命令（带日志）
func (b *BaseBuilder) runCommandWithLogging(workDir string, logger *DeployLogger, command string, args ...string) error {
	return b.gs.runCommandWithLogging(workDir, logger, command, args...)
}

// startProcess 启动进程
func (b *BaseBuilder) startProcess(app *GitApp, command string) error {
	return b.gs.startAppProcess(app, command)
}

// startProcessWithLogging 启动进程（带日志）
func (b *BaseBuilder) startProcessWithLogging(app *GitApp, command string, logger *DeployLogger) error {
	return b.gs.startAppProcessWithLogging(app, command, logger)
}

// BuilderRegistry 构建器注册表
type BuilderRegistry struct {
	builders []AppBuilder
}

// NewBuilderRegistry 创建构建器注册表
func NewBuilderRegistry() *BuilderRegistry {
	return &BuilderRegistry{
		builders: make([]AppBuilder, 0),
	}
}

// Register 注册构建器
func (r *BuilderRegistry) Register(builder AppBuilder) {
	r.builders = append(r.builders, builder)
}

// DetectBuilder 检测应用类型并返回对应的构建器
func (r *BuilderRegistry) DetectBuilder(appPath string) (AppBuilder, error) {
	// 优先级顺序检测
	for _, builder := range r.builders {
		detected, err := builder.Detect(appPath)
		if err != nil {
			continue
		}
		if detected {
			return builder, nil
		}
	}
	return nil, fmt.Errorf("无法识别应用类型")
}

// GetBuilder 根据类型获取构建器
func (r *BuilderRegistry) GetBuilder(appType string) (AppBuilder, error) {
	for _, builder := range r.builders {
		if builder.GetType() == appType {
			return builder, nil
		}
	}
	return nil, fmt.Errorf("不支持的应用类型: %s", appType)
}

// ListBuilders 列出所有构建器
func (r *BuilderRegistry) ListBuilders() []AppBuilder {
	return r.builders
}

// InitBuilders 初始化所有构建器
func (gs *GitServer) InitBuilders() *BuilderRegistry {
	registry := NewBuilderRegistry()

	// 按优先级注册构建器
	registry.Register(NewDockerComposeBuilder(gs)) // 最高优先级：Docker Compose
	registry.Register(NewDockerBuilder(gs))        // Dockerfile
	registry.Register(NewNodeJSBuilder(gs))        // Node.js
	registry.Register(NewDenoBuilder(gs))          // Deno
	registry.Register(NewBunBuilder(gs))           // Bun
	registry.Register(NewPythonBuilder(gs))        // Python
	registry.Register(NewGoBuilder(gs))            // Go
	registry.Register(NewRustBuilder(gs))          // Rust
	registry.Register(NewJavaBuilder(gs))          // Java
	registry.Register(NewRubyBuilder(gs))          // Ruby
	registry.Register(NewPHPBuilder(gs))           // PHP
	registry.Register(NewDotNetBuilder(gs))        // .NET
	registry.Register(NewStaticBuilder(gs))        // 最低优先级：静态文件

	return registry
}
