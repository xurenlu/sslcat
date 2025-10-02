package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GoBuilder Go 应用构建器
type GoBuilder struct {
	*BaseBuilder
}

// NewGoBuilder 创建 Go 构建器
func NewGoBuilder(gs *GitServer) *GoBuilder {
	return &GoBuilder{
		BaseBuilder: NewBaseBuilder("go", "Go", 8080, gs),
	}
}

// Detect 检测是否为 Go 应用
func (b *GoBuilder) Detect(appPath string) (bool, error) {
	return b.fileExists(appPath, "go.mod"), nil
}

// Build 构建应用
func (b *GoBuilder) Build(app *GitApp) error {
	// 下载依赖
	if err := b.runCommand(app.GitPath, "go", "mod", "download"); err != nil {
		return fmt.Errorf("go mod download 失败: %w", err)
	}

	// 构建应用
	outputPath := filepath.Join(app.GitPath, "app")
	if err := b.runCommand(app.GitPath, "go", "build", "-o", outputPath, "."); err != nil {
		return fmt.Errorf("go build 失败: %w", err)
	}

	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *GoBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "go", "开始 Go 应用构建流程")

	// 下载依赖
	logger.WriteLog("info", "go", "下载依赖...")
	if err := b.runCommandWithLogging(app.GitPath, logger, "go", "mod", "download"); err != nil {
		return fmt.Errorf("go mod download 失败: %w", err)
	}

	// 构建应用
	logger.WriteLog("info", "go", "编译应用...")
	outputPath := filepath.Join(app.GitPath, "app")
	if err := b.runCommandWithLogging(app.GitPath, logger, "go", "build", "-o", outputPath, "."); err != nil {
		return fmt.Errorf("go build 失败: %w", err)
	}

	logger.WriteLog("info", "go", "构建完成")
	return nil
}

// Start 启动应用
func (b *GoBuilder) Start(app *GitApp) error {
	binaryPath := filepath.Join(app.GitPath, "app")
	return b.startProcess(app, binaryPath)
}

// StartWithLogging 启动应用（带日志）
func (b *GoBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "go", "启动 Go 应用...")

	binaryPath := filepath.Join(app.GitPath, "app")
	logger.WriteLog("info", "go", fmt.Sprintf("启动命令: %s", binaryPath))

	if err := b.startProcessWithLogging(app, binaryPath, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "go", "应用启动成功")
	return nil
}

// detectFramework 检测 Go 框架
func (b *GoBuilder) detectFramework(appPath string) string {
	goMod, err := os.ReadFile(filepath.Join(appPath, "go.mod"))
	if err != nil {
		return ""
	}

	content := strings.ToLower(string(goMod))
	if strings.Contains(content, "gin-gonic/gin") {
		return "Gin"
	}
	if strings.Contains(content, "labstack/echo") {
		return "Echo"
	}
	if strings.Contains(content, "gofiber/fiber") {
		return "Fiber"
	}
	if strings.Contains(content, "gorilla/mux") {
		return "Gorilla"
	}

	return ""
}

// GetDefaultPort Go 默认端口
func (b *GoBuilder) GetDefaultPort() int {
	return 8080
}
