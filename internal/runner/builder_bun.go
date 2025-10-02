package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// BunBuilder Bun 应用构建器
type BunBuilder struct {
	*BaseBuilder
}

// NewBunBuilder 创建 Bun 构建器
func NewBunBuilder(gs *GitServer) *BunBuilder {
	return &BunBuilder{
		BaseBuilder: NewBaseBuilder("bun", "Bun", 3000, gs),
	}
}

// Detect 检测是否为 Bun 应用
func (b *BunBuilder) Detect(appPath string) (bool, error) {
	// 检查 bun.lockb 或 bunfig.toml
	if b.fileExists(appPath, "bun.lockb") || b.fileExists(appPath, "bunfig.toml") {
		return true, nil
	}

	// 检查 package.json 中是否指定了 bun
	if pkg := b.readPackageJSON(appPath); pkg != nil {
		if pkg.PackageManager != "" && pkg.PackageManager[:3] == "bun" {
			return true, nil
		}
	}

	return false, nil
}

// Build 构建应用
func (b *BunBuilder) Build(app *GitApp) error {
	// 安装依赖
	if err := b.runCommand(app.GitPath, "bun", "install"); err != nil {
		return fmt.Errorf("bun install 失败: %w", err)
	}

	// 执行构建脚本（如果存在）
	if b.hasBuildScript(app.GitPath) {
		if err := b.runCommand(app.GitPath, "bun", "run", "build"); err != nil {
			return fmt.Errorf("bun build 失败: %w", err)
		}
	}

	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *BunBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "bun", "开始 Bun 应用构建流程")

	// 安装依赖
	logger.WriteLog("info", "bun", "安装依赖...")
	if err := b.runCommandWithLogging(app.GitPath, logger, "bun", "install"); err != nil {
		return fmt.Errorf("bun install 失败: %w", err)
	}

	// 执行构建脚本
	if b.hasBuildScript(app.GitPath) {
		logger.WriteLog("info", "bun", "执行构建脚本...")
		if err := b.runCommandWithLogging(app.GitPath, logger, "bun", "run", "build"); err != nil {
			logger.WriteLog("warn", "bun", "构建脚本执行失败，继续部署")
		}
	}

	logger.WriteLog("info", "bun", "构建完成")
	return nil
}

// Start 启动应用
func (b *BunBuilder) Start(app *GitApp) error {
	startCommand := b.getStartCommand(app.GitPath)
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *BunBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "bun", "启动 Bun 应用...")
	startCommand := b.getStartCommand(app.GitPath)
	logger.WriteLog("info", "bun", fmt.Sprintf("启动命令: %s", startCommand))

	if err := b.startProcessWithLogging(app, startCommand, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "bun", "应用启动成功")
	return nil
}

// hasBuildScript 检查是否有构建脚本
func (b *BunBuilder) hasBuildScript(appPath string) bool {
	pkg := b.readPackageJSON(appPath)
	if pkg == nil {
		return false
	}
	_, exists := pkg.Scripts["build"]
	return exists
}

// getStartCommand 获取启动命令
func (b *BunBuilder) getStartCommand(appPath string) string {
	pkg := b.readPackageJSON(appPath)
	if pkg != nil && pkg.Scripts["start"] != "" {
		return "bun run start"
	}

	// 检测常见的入口文件
	entryFiles := []string{"index.ts", "index.js", "server.ts", "server.js", "app.ts", "app.js", "main.ts", "main.js"}
	for _, file := range entryFiles {
		if b.fileExists(appPath, file) {
			return fmt.Sprintf("bun run %s", file)
		}
	}

	return "bun run index.ts"
}

// readPackageJSON 读取 package.json
func (b *BunBuilder) readPackageJSON(appPath string) *BunPackageJSON {
	data, err := os.ReadFile(filepath.Join(appPath, "package.json"))
	if err != nil {
		return nil
	}

	var pkg BunPackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	return &pkg
}

// BunPackageJSON package.json 结构（Bun 扩展）
type BunPackageJSON struct {
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	Scripts        map[string]string `json:"scripts"`
	Dependencies   map[string]string `json:"dependencies"`
	PackageManager string            `json:"packageManager"`
}

// GetDefaultPort Bun 默认端口
func (b *BunBuilder) GetDefaultPort() int {
	return 3000
}
