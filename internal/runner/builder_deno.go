package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DenoBuilder Deno 应用构建器
type DenoBuilder struct {
	*BaseBuilder
}

// NewDenoBuilder 创建 Deno 构建器
func NewDenoBuilder(gs *GitServer) *DenoBuilder {
	return &DenoBuilder{
		BaseBuilder: NewBaseBuilder("deno", "Deno", 8000, gs),
	}
}

// Detect 检测是否为 Deno 应用
func (b *DenoBuilder) Detect(appPath string) (bool, error) {
	// 检查 deno.json 或 deno.jsonc
	return b.anyFileExists(appPath, []string{"deno.json", "deno.jsonc"}), nil
}

// Build 构建应用（Deno 通常不需要构建）
func (b *DenoBuilder) Build(app *GitApp) error {
	// Deno 应用通常不需要构建步骤
	// 但可以缓存依赖
	if config := b.readDenoConfig(app.GitPath); config != nil {
		if config.Tasks["build"] != "" {
			if err := b.runCommand(app.GitPath, "deno", "task", "build"); err != nil {
				return fmt.Errorf("deno task build 失败: %w", err)
			}
		}
	}
	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *DenoBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "deno", "开始 Deno 应用构建流程")

	// 缓存依赖
	logger.WriteLog("info", "deno", "缓存依赖...")
	mainFile := b.findMainFile(app.GitPath)
	if mainFile != "" {
		if err := b.runCommandWithLogging(app.GitPath, logger, "deno", "cache", mainFile); err != nil {
			logger.WriteLog("warn", "deno", "依赖缓存失败，继续部署")
		}
	}

	// 执行构建任务（如果存在）
	if config := b.readDenoConfig(app.GitPath); config != nil {
		if config.Tasks["build"] != "" {
			logger.WriteLog("info", "deno", "执行构建任务...")
			if err := b.runCommandWithLogging(app.GitPath, logger, "deno", "task", "build"); err != nil {
				logger.WriteLog("warn", "deno", "构建任务执行失败，继续部署")
			}
		}
	}

	logger.WriteLog("info", "deno", "构建完成")
	return nil
}

// Start 启动应用
func (b *DenoBuilder) Start(app *GitApp) error {
	startCommand := b.getStartCommand(app.GitPath)
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *DenoBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "deno", "启动 Deno 应用...")
	startCommand := b.getStartCommand(app.GitPath)
	logger.WriteLog("info", "deno", fmt.Sprintf("启动命令: %s", startCommand))

	if err := b.startProcessWithLogging(app, startCommand, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "deno", "应用启动成功")
	return nil
}

// getStartCommand 获取启动命令
func (b *DenoBuilder) getStartCommand(appPath string) string {
	// 检查 deno.json 中的 start 任务
	if config := b.readDenoConfig(appPath); config != nil {
		if config.Tasks["start"] != "" {
			return "deno task start"
		}
	}

	// 查找主文件
	mainFile := b.findMainFile(appPath)
	if mainFile == "" {
		mainFile = "main.ts"
	}

	return fmt.Sprintf("deno run --allow-net --allow-read --allow-env %s", mainFile)
}

// findMainFile 查找主文件
func (b *DenoBuilder) findMainFile(appPath string) string {
	// 从 deno.json 读取
	if config := b.readDenoConfig(appPath); config != nil {
		if config.Tasks["start"] != "" {
			return "" // 使用 task start
		}
	}

	// 常见的入口文件
	entryFiles := []string{"main.ts", "main.js", "mod.ts", "index.ts", "server.ts", "app.ts"}
	for _, file := range entryFiles {
		if b.fileExists(appPath, file) {
			return file
		}
	}

	return ""
}

// readDenoConfig 读取 deno.json
func (b *DenoBuilder) readDenoConfig(appPath string) *DenoConfig {
	configFiles := []string{"deno.json", "deno.jsonc"}
	for _, configFile := range configFiles {
		data, err := os.ReadFile(filepath.Join(appPath, configFile))
		if err != nil {
			continue
		}

		var config DenoConfig
		if err := json.Unmarshal(data, &config); err != nil {
			continue
		}

		return &config
	}

	return nil
}

// DenoConfig deno.json 配置
type DenoConfig struct {
	Tasks       map[string]string `json:"tasks"`
	ImportMap   string            `json:"importMap"`
	CompilerOpt map[string]any    `json:"compilerOptions"`
}

// GetDefaultPort Deno 默认端口
func (b *DenoBuilder) GetDefaultPort() int {
	return 8000
}
