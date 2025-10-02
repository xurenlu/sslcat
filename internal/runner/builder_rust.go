package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RustBuilder Rust 应用构建器
type RustBuilder struct {
	*BaseBuilder
}

// NewRustBuilder 创建 Rust 构建器
func NewRustBuilder(gs *GitServer) *RustBuilder {
	return &RustBuilder{
		BaseBuilder: NewBaseBuilder("rust", "Rust", 8080, gs),
	}
}

// Detect 检测是否为 Rust 应用
func (b *RustBuilder) Detect(appPath string) (bool, error) {
	return b.fileExists(appPath, "Cargo.toml"), nil
}

// Build 构建应用
func (b *RustBuilder) Build(app *GitApp) error {
	// 使用 release 模式构建
	if err := b.runCommand(app.GitPath, "cargo", "build", "--release"); err != nil {
		return fmt.Errorf("Cargo 构建失败: %w", err)
	}

	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *RustBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "rust", "开始 Rust 应用构建流程")
	logger.WriteLog("info", "rust", "使用 Cargo 构建（release 模式）...")

	if err := b.runCommandWithLogging(app.GitPath, logger, "cargo", "build", "--release"); err != nil {
		return fmt.Errorf("Cargo 构建失败: %w", err)
	}

	logger.WriteLog("info", "rust", "构建完成")
	return nil
}

// Start 启动应用
func (b *RustBuilder) Start(app *GitApp) error {
	binaryPath := b.findBinary(app.GitPath)
	if binaryPath == "" {
		return fmt.Errorf("未找到可执行文件")
	}

	startCommand := binaryPath
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *RustBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "rust", "启动 Rust 应用...")

	binaryPath := b.findBinary(app.GitPath)
	if binaryPath == "" {
		return fmt.Errorf("未找到可执行文件")
	}

	logger.WriteLog("info", "rust", fmt.Sprintf("找到可执行文件: %s", binaryPath))
	logger.WriteLog("info", "rust", fmt.Sprintf("启动命令: %s", binaryPath))

	if err := b.startProcessWithLogging(app, binaryPath, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "rust", "应用启动成功")
	return nil
}

// findBinary 查找编译后的二进制文件
func (b *RustBuilder) findBinary(appPath string) string {
	// 从 Cargo.toml 获取项目名称
	projectName := b.getProjectName(appPath)
	if projectName == "" {
		projectName = filepath.Base(appPath)
	}

	// Release 构建输出路径
	binaryPath := filepath.Join(appPath, "target", "release", projectName)
	if b.fileExists(appPath, filepath.Join("target", "release", projectName)) {
		return binaryPath
	}

	// 如果没有找到，尝试查找第一个可执行文件
	releaseDir := filepath.Join(appPath, "target", "release")
	entries, err := filepath.Glob(filepath.Join(releaseDir, "*"))
	if err == nil {
		for _, entry := range entries {
			// 跳过带扩展名的文件和目录
			if !strings.Contains(filepath.Base(entry), ".") {
				return entry
			}
		}
	}

	return ""
}

// getProjectName 从 Cargo.toml 获取项目名称
func (b *RustBuilder) getProjectName(appPath string) string {
	data, err := os.ReadFile(filepath.Join(appPath, "Cargo.toml"))
	if err != nil {
		return ""
	}

	// 简单解析 name = "xxx"
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name") && strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				name = strings.Trim(name, "\"")
				return name
			}
		}
	}

	return ""
}

// GetDefaultPort Rust 默认端口
func (b *RustBuilder) GetDefaultPort() int {
	return 8080
}
