package runner

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DotNetBuilder .NET 应用构建器
type DotNetBuilder struct {
	*BaseBuilder
}

// NewDotNetBuilder 创建 .NET 构建器
func NewDotNetBuilder(gs *GitServer) *DotNetBuilder {
	return &DotNetBuilder{
		BaseBuilder: NewBaseBuilder("dotnet", ".NET", 5000, gs),
	}
}

// Detect 检测是否为 .NET 应用
func (b *DotNetBuilder) Detect(appPath string) (bool, error) {
	// 检查项目文件
	csprojFiles, _ := filepath.Glob(filepath.Join(appPath, "*.csproj"))
	fsprojFiles, _ := filepath.Glob(filepath.Join(appPath, "*.fsproj"))
	vbprojFiles, _ := filepath.Glob(filepath.Join(appPath, "*.vbproj"))

	return len(csprojFiles) > 0 || len(fsprojFiles) > 0 || len(vbprojFiles) > 0, nil
}

// Build 构建应用
func (b *DotNetBuilder) Build(app *GitApp) error {
	// 恢复依赖
	if err := b.runCommand(app.GitPath, "dotnet", "restore"); err != nil {
		return fmt.Errorf("dotnet restore 失败: %w", err)
	}

	// 构建应用
	if err := b.runCommand(app.GitPath, "dotnet", "build", "--configuration", "Release", "--no-restore"); err != nil {
		return fmt.Errorf("dotnet build 失败: %w", err)
	}

	// 发布应用
	if err := b.runCommand(app.GitPath, "dotnet", "publish", "--configuration", "Release", "--output", "./publish", "--no-build"); err != nil {
		return fmt.Errorf("dotnet publish 失败: %w", err)
	}

	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *DotNetBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "dotnet", "开始 .NET 应用构建流程")

	// 恢复依赖
	logger.WriteLog("info", "dotnet", "恢复 NuGet 依赖...")
	if err := b.runCommandWithLogging(app.GitPath, logger, "dotnet", "restore"); err != nil {
		return fmt.Errorf("dotnet restore 失败: %w", err)
	}

	// 构建应用
	logger.WriteLog("info", "dotnet", "构建应用（Release 模式）...")
	if err := b.runCommandWithLogging(app.GitPath, logger, "dotnet", "build", "--configuration", "Release", "--no-restore"); err != nil {
		return fmt.Errorf("dotnet build 失败: %w", err)
	}

	// 发布应用
	logger.WriteLog("info", "dotnet", "发布应用...")
	if err := b.runCommandWithLogging(app.GitPath, logger, "dotnet", "publish", "--configuration", "Release", "--output", "./publish", "--no-build"); err != nil {
		return fmt.Errorf("dotnet publish 失败: %w", err)
	}

	logger.WriteLog("info", "dotnet", "构建完成")
	return nil
}

// Start 启动应用
func (b *DotNetBuilder) Start(app *GitApp) error {
	dllPath := b.findDll(app.GitPath)
	if dllPath == "" {
		return fmt.Errorf("未找到可执行的 DLL 文件")
	}

	startCommand := fmt.Sprintf("dotnet %s --urls http://0.0.0.0:${PORT:-5000}", dllPath)
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *DotNetBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "dotnet", "启动 .NET 应用...")

	dllPath := b.findDll(app.GitPath)
	if dllPath == "" {
		return fmt.Errorf("未找到可执行的 DLL 文件")
	}

	logger.WriteLog("info", "dotnet", fmt.Sprintf("找到 DLL 文件: %s", dllPath))
	startCommand := fmt.Sprintf("dotnet %s --urls http://0.0.0.0:${PORT:-5000}", dllPath)
	logger.WriteLog("info", "dotnet", fmt.Sprintf("启动命令: %s", startCommand))

	if err := b.startProcessWithLogging(app, startCommand, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "dotnet", "应用启动成功")
	return nil
}

// findDll 查找生成的 DLL 文件
func (b *DotNetBuilder) findDll(appPath string) string {
	// 在 publish 目录中查找
	publishDir := filepath.Join(appPath, "publish")
	dllFiles, err := filepath.Glob(filepath.Join(publishDir, "*.dll"))
	if err == nil && len(dllFiles) > 0 {
		// 排除一些系统 DLL
		for _, dll := range dllFiles {
			name := filepath.Base(dll)
			// 跳过 Microsoft 和 System 开头的 DLL
			if !strings.HasPrefix(name, "Microsoft.") &&
				!strings.HasPrefix(name, "System.") &&
				!strings.HasPrefix(name, "Newtonsoft.") {
				return dll
			}
		}
		// 如果都是系统 DLL，返回第一个
		if len(dllFiles) > 0 {
			return dllFiles[0]
		}
	}

	return ""
}

// GetDefaultPort .NET 默认端口（ASP.NET Core）
func (b *DotNetBuilder) GetDefaultPort() int {
	return 5000
}
