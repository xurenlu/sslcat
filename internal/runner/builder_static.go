package runner

import (
	"fmt"
)

// StaticBuilder 静态文件应用构建器
type StaticBuilder struct {
	*BaseBuilder
}

// NewStaticBuilder 创建静态文件构建器
func NewStaticBuilder(gs *GitServer) *StaticBuilder {
	return &StaticBuilder{
		BaseBuilder: NewBaseBuilder("static", "Static", 8080, gs),
	}
}

// Detect 检测是否为静态文件应用（默认兜底）
func (b *StaticBuilder) Detect(appPath string) (bool, error) {
	// 静态文件构建器作为兜底，总是返回 true
	// 但在注册表中应该是最低优先级
	return b.anyFileExists(appPath, []string{"index.html", "index.htm"}), nil
}

// Build 构建应用（静态文件无需构建）
func (b *StaticBuilder) Build(app *GitApp) error {
	// 静态文件无需构建
	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *StaticBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "static", "检测到静态文件应用")
	logger.WriteLog("info", "static", "静态文件无需构建步骤")
	return nil
}

// Start 启动应用（使用简单的 HTTP 服务器）
func (b *StaticBuilder) Start(app *GitApp) error {
	// 使用 Python 的 http.server 或其他简单服务器
	return b.startHTTPServer(app)
}

// StartWithLogging 启动应用（带日志）
func (b *StaticBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "static", "启动静态文件服务器...")

	if err := b.startHTTPServerWithLogging(app, logger); err != nil {
		return fmt.Errorf("静态服务器启动失败: %w", err)
	}

	logger.WriteLog("info", "static", "静态文件服务器启动成功")
	return nil
}

// startHTTPServer 启动 HTTP 服务器
func (b *StaticBuilder) startHTTPServer(app *GitApp) error {
	// 尝试多种静态文件服务器

	// 优先使用 Python 3
	if err := b.testCommand("python3", "--version"); err == nil {
		command := fmt.Sprintf("python3 -m http.server ${PORT:-8080}")
		return b.startProcess(app, command)
	}

	// 尝试 Python 2
	if err := b.testCommand("python", "--version"); err == nil {
		command := fmt.Sprintf("python -m SimpleHTTPServer ${PORT:-8080}")
		return b.startProcess(app, command)
	}

	// 尝试 Node.js 的 http-server (如果已安装)
	if err := b.testCommand("npx", "--version"); err == nil {
		command := fmt.Sprintf("npx http-server -p ${PORT:-8080}")
		return b.startProcess(app, command)
	}

	return fmt.Errorf("未找到可用的静态文件服务器（需要 Python 或 Node.js）")
}

// startHTTPServerWithLogging 启动 HTTP 服务器（带日志）
func (b *StaticBuilder) startHTTPServerWithLogging(app *GitApp, logger *DeployLogger) error {
	// 尝试多种静态文件服务器

	// 优先使用 Python 3
	if err := b.testCommand("python3", "--version"); err == nil {
		logger.WriteLog("info", "static", "使用 Python 3 http.server")
		command := fmt.Sprintf("python3 -m http.server ${PORT:-8080}")
		return b.startProcessWithLogging(app, command, logger)
	}

	// 尝试 Python 2
	if err := b.testCommand("python", "--version"); err == nil {
		logger.WriteLog("info", "static", "使用 Python 2 SimpleHTTPServer")
		command := fmt.Sprintf("python -m SimpleHTTPServer ${PORT:-8080}")
		return b.startProcessWithLogging(app, command, logger)
	}

	// 尝试 Node.js 的 http-server
	if err := b.testCommand("npx", "--version"); err == nil {
		logger.WriteLog("info", "static", "使用 npx http-server")
		command := fmt.Sprintf("npx http-server -p ${PORT:-8080}")
		return b.startProcessWithLogging(app, command, logger)
	}

	return fmt.Errorf("未找到可用的静态文件服务器（需要 Python 或 Node.js）")
}

// testCommand 测试命令是否可用
func (b *StaticBuilder) testCommand(command string, args ...string) error {
	return b.runCommand(".", command, args...)
}

// GetDefaultPort 静态文件默认端口
func (b *StaticBuilder) GetDefaultPort() int {
	return 8080
}
