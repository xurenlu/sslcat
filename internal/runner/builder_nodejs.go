package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// NodeJSBuilder Node.js 应用构建器
type NodeJSBuilder struct {
	*BaseBuilder
}

// NewNodeJSBuilder 创建 Node.js 构建器
func NewNodeJSBuilder(gs *GitServer) *NodeJSBuilder {
	return &NodeJSBuilder{
		BaseBuilder: NewBaseBuilder("nodejs", "Node.js", 3000, gs),
	}
}

// Detect 检测是否为 Node.js 应用
func (b *NodeJSBuilder) Detect(appPath string) (bool, error) {
	return b.fileExists(appPath, "package.json"), nil
}

// Build 构建应用
func (b *NodeJSBuilder) Build(app *GitApp) error {
	// 检查 package.json
	packageJSONPath := filepath.Join(app.GitPath, "package.json")
	if _, err := os.Stat(packageJSONPath); os.IsNotExist(err) {
		return fmt.Errorf("未找到 package.json 文件")
	}

	// 检测包管理器（npm/yarn/pnpm）
	packageManager := b.detectPackageManager(app.GitPath)

	// 安装依赖
	switch packageManager {
	case "pnpm":
		if err := b.runCommand(app.GitPath, "pnpm", "install"); err != nil {
			return fmt.Errorf("pnpm install 失败: %w", err)
		}
	case "yarn":
		if err := b.runCommand(app.GitPath, "yarn", "install"); err != nil {
			return fmt.Errorf("yarn install 失败: %w", err)
		}
	default:
		if err := b.runCommand(app.GitPath, "npm", "install"); err != nil {
			return fmt.Errorf("npm install 失败: %w", err)
		}
	}

	// 执行构建脚本（如果存在）
	if b.hasBuildScript(app.GitPath) {
		switch packageManager {
		case "pnpm":
			if err := b.runCommand(app.GitPath, "pnpm", "run", "build"); err != nil {
				return fmt.Errorf("pnpm build 失败: %w", err)
			}
		case "yarn":
			if err := b.runCommand(app.GitPath, "yarn", "build"); err != nil {
				return fmt.Errorf("yarn build 失败: %w", err)
			}
		default:
			if err := b.runCommand(app.GitPath, "npm", "run", "build"); err != nil {
				return fmt.Errorf("npm build 失败: %w", err)
			}
		}
	}

	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *NodeJSBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "nodejs", "开始 Node.js 应用构建流程")

	packageManager := b.detectPackageManager(app.GitPath)

	// 检测多个 lockfile 并输出警告到日志
	hasPnpm := b.fileExists(app.GitPath, "pnpm-lock.yaml")
	hasYarn := b.fileExists(app.GitPath, "yarn.lock")
	hasNpmLock := b.fileExists(app.GitPath, "package-lock.json")
	lockfileCount := 0
	lockfiles := []string{}
	if hasPnpm {
		lockfileCount++
		lockfiles = append(lockfiles, "pnpm")
	}
	if hasYarn {
		lockfileCount++
		lockfiles = append(lockfiles, "Yarn")
	}
	if hasNpmLock {
		lockfileCount++
		lockfiles = append(lockfiles, "npm")
	}

	if lockfileCount > 1 {
		logger.WriteLog("warn", "nodejs", fmt.Sprintf("检测到多个包管理器 lockfile: %v", lockfiles))
		logger.WriteLog("warn", "nodejs", "建议只保留一个 lockfile 以避免依赖冲突")
	}

	logger.WriteLog("info", "nodejs", fmt.Sprintf("使用包管理器: %s", packageManager))

	// 安装依赖
	logger.WriteLog("info", "nodejs", "安装依赖中...")
	switch packageManager {
	case "pnpm":
		if err := b.runCommandWithLogging(app.GitPath, logger, "pnpm", "install"); err != nil {
			return fmt.Errorf("pnpm install 失败: %w", err)
		}
	case "yarn":
		if err := b.runCommandWithLogging(app.GitPath, logger, "yarn", "install"); err != nil {
			return fmt.Errorf("yarn install 失败: %w", err)
		}
	default:
		if err := b.runCommandWithLogging(app.GitPath, logger, "npm", "install"); err != nil {
			return fmt.Errorf("npm install 失败: %w", err)
		}
	}

	// 执行构建脚本
	if b.hasBuildScript(app.GitPath) {
		logger.WriteLog("info", "nodejs", "执行构建脚本...")
		switch packageManager {
		case "pnpm":
			if err := b.runCommandWithLogging(app.GitPath, logger, "pnpm", "run", "build"); err != nil {
				logger.WriteLog("warn", "nodejs", "构建脚本执行失败，继续部署")
			}
		case "yarn":
			if err := b.runCommandWithLogging(app.GitPath, logger, "yarn", "build"); err != nil {
				logger.WriteLog("warn", "nodejs", "构建脚本执行失败，继续部署")
			}
		default:
			if err := b.runCommandWithLogging(app.GitPath, logger, "npm", "run", "build"); err != nil {
				logger.WriteLog("warn", "nodejs", "构建脚本执行失败，继续部署")
			}
		}
	}

	logger.WriteLog("info", "nodejs", "构建完成")
	return nil
}

// Start 启动应用
func (b *NodeJSBuilder) Start(app *GitApp) error {
	startCommand := b.getStartCommand(app.GitPath)
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *NodeJSBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "nodejs", "启动应用...")
	startCommand := b.getStartCommand(app.GitPath)
	logger.WriteLog("info", "nodejs", fmt.Sprintf("启动命令: %s", startCommand))

	if err := b.startProcessWithLogging(app, startCommand, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "nodejs", "应用启动成功")
	return nil
}

// detectPackageManager 检测包管理器
func (b *NodeJSBuilder) detectPackageManager(appPath string) string {
	hasPnpm := b.fileExists(appPath, "pnpm-lock.yaml")
	hasYarn := b.fileExists(appPath, "yarn.lock")
	hasNpmLock := b.fileExists(appPath, "package-lock.json")

	// 检测是否有多个 lockfile
	lockfileCount := 0
	lockfiles := []string{}
	if hasPnpm {
		lockfileCount++
		lockfiles = append(lockfiles, "pnpm-lock.yaml")
	}
	if hasYarn {
		lockfileCount++
		lockfiles = append(lockfiles, "yarn.lock")
	}
	if hasNpmLock {
		lockfileCount++
		lockfiles = append(lockfiles, "package-lock.json")
	}

	// 如果有多个 lockfile，输出警告
	if lockfileCount > 1 {
		b.gs.logger.Warnf("⚠️  检测到多个包管理器 lockfile: %v", lockfiles)
		b.gs.logger.Warnf("   建议只保留一个 lockfile，删除其他的以避免依赖冲突")
		b.gs.logger.Warnf("   将使用优先级: pnpm > yarn > npm")
	}

	// 按优先级返回
	if hasPnpm {
		return "pnpm"
	}
	if hasYarn {
		return "yarn"
	}
	return "npm"
}

// hasBuildScript 检查是否有构建脚本
func (b *NodeJSBuilder) hasBuildScript(appPath string) bool {
	packageJSON, err := b.readPackageJSON(appPath)
	if err != nil {
		return false
	}
	_, exists := packageJSON.Scripts["build"]
	return exists
}

// getStartCommand 获取启动命令
func (b *NodeJSBuilder) getStartCommand(appPath string) string {
	packageJSON, err := b.readPackageJSON(appPath)
	if err == nil {
		if _, exists := packageJSON.Scripts["start"]; exists {
			packageManager := b.detectPackageManager(appPath)
			switch packageManager {
			case "pnpm":
				return "pnpm start"
			case "yarn":
				return "yarn start"
			default:
				return "npm start"
			}
		}
	}

	// 检测常见的入口文件
	entryFiles := []string{"index.js", "server.js", "app.js", "main.js", "src/index.js", "src/server.js"}
	for _, file := range entryFiles {
		if b.fileExists(appPath, file) {
			return fmt.Sprintf("node %s", file)
		}
	}

	return "node index.js"
}

// readPackageJSON 读取 package.json
func (b *NodeJSBuilder) readPackageJSON(appPath string) (*PackageJSONFull, error) {
	data, err := os.ReadFile(filepath.Join(appPath, "package.json"))
	if err != nil {
		return nil, err
	}

	var pkg PackageJSONFull
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	return &pkg, nil
}

// PackageJSONFull package.json 完整结构
type PackageJSONFull struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Engines         map[string]string `json:"engines"`
}
