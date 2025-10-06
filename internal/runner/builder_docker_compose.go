package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DockerComposeBuilder Docker Compose 应用构建器
type DockerComposeBuilder struct {
	*BaseBuilder
}

// NewDockerComposeBuilder 创建 Docker Compose 构建器
func NewDockerComposeBuilder(gs *GitServer) *DockerComposeBuilder {
	return &DockerComposeBuilder{
		BaseBuilder: NewBaseBuilder("docker-compose", "Docker Compose", 8080, gs),
	}
}

// Detect 检测是否为 Docker Compose 应用
func (b *DockerComposeBuilder) Detect(appPath string) (bool, error) {
	// 检查是否存在 docker-compose 文件
	return b.anyFileExists(appPath, []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"compose.yml",
		"compose.yaml",
	}), nil
}

// Build 构建应用
func (b *DockerComposeBuilder) Build(app *GitApp) error {
	// Docker Compose 构建逻辑
	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *DockerComposeBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "docker-compose", "开始 Docker Compose 应用构建流程")

	// 查找 docker-compose 文件
	composeFile := b.findComposeFile(app.RepoDir)
	if composeFile == "" {
		return fmt.Errorf("未找到 docker-compose 配置文件")
	}

	logger.WriteLog("info", "docker-compose", fmt.Sprintf("使用配置文件: %s", composeFile))

	// 读取并检查配置文件
	if err := b.validateComposeFile(app.RepoDir, composeFile, logger); err != nil {
		logger.WriteLog("warn", "docker-compose", fmt.Sprintf("配置文件验证警告: %v", err))
	}

	// 拉取镜像（如果需要）
	logger.WriteLog("info", "docker-compose", "拉取所需的 Docker 镜像...")
	if err := b.runCommandWithLogging(app.RepoDir, logger, "docker-compose", "-f", composeFile, "pull", "--ignore-pull-failures"); err != nil {
		logger.WriteLog("warn", "docker-compose", "部分镜像拉取失败，将尝试使用本地镜像")
	}

	// 构建镜像（如果配置文件中有 build 指令）
	logger.WriteLog("info", "docker-compose", "构建自定义镜像...")
	if err := b.runCommandWithLogging(app.RepoDir, logger, "docker-compose", "-f", composeFile, "build", "--pull"); err != nil {
		logger.WriteLog("warn", "docker-compose", fmt.Sprintf("镜像构建警告: %v", err))
		// 不返回错误，因为可能没有需要构建的镜像
	}

	logger.WriteLog("success", "docker-compose", "Docker Compose 构建完成")
	return nil
}

// Start 启动应用
func (b *DockerComposeBuilder) Start(app *GitApp) error {
	composeFile := b.findComposeFile(app.RepoDir)
	if composeFile == "" {
		return fmt.Errorf("未找到 docker-compose 配置文件")
	}

	// 生成项目名称（避免冲突）
	projectName := b.getProjectName(app)

	// 停止旧容器
	b.runCommand(app.RepoDir, "docker-compose", "-f", composeFile, "-p", projectName, "down")

	// 启动新容器
	if err := b.runCommand(app.RepoDir, "docker-compose", "-f", composeFile, "-p", projectName, "up", "-d"); err != nil {
		return fmt.Errorf("Docker Compose 启动失败: %w", err)
	}

	return nil
}

// StartWithLogging 启动应用（带日志）
func (b *DockerComposeBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "docker-compose", "启动 Docker Compose 应用...")

	composeFile := b.findComposeFile(app.RepoDir)
	if composeFile == "" {
		return fmt.Errorf("未找到 docker-compose 配置文件")
	}

	// 生成项目名称（避免冲突）
	projectName := b.getProjectName(app)
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("项目名称: %s", projectName))

	// 停止并删除旧容器（蓝绿部署）
	logger.WriteLog("info", "docker-compose", "停止旧版本容器...")
	if err := b.runCommandWithLogging(app.RepoDir, logger, "docker-compose", "-f", composeFile, "-p", projectName, "down", "--remove-orphans"); err != nil {
		logger.WriteLog("warn", "docker-compose", fmt.Sprintf("停止旧容器时出现警告: %v", err))
	}

	// 设置环境变量
	envArgs := b.buildEnvArgs(app)

	// 启动新容器
	logger.WriteLog("info", "docker-compose", "启动新版本容器...")
	args := []string{"-f", composeFile, "-p", projectName}

	// 添加环境变量文件（如果存在）
	envFile := filepath.Join(app.RepoDir, ".env")
	if _, err := os.Stat(envFile); err == nil {
		args = append(args, "--env-file", ".env")
		logger.WriteLog("info", "docker-compose", "使用环境变量文件: .env")
	}

	args = append(args, "up", "-d", "--remove-orphans")

	// 如果有自定义环境变量，需要导出
	if len(envArgs) > 0 {
		logger.WriteLog("info", "docker-compose", fmt.Sprintf("设置 %d 个环境变量", len(envArgs)))
		// 将环境变量写入临时 .env.sslcat 文件
		if err := b.writeEnvFile(app, envArgs, logger); err != nil {
			logger.WriteLog("warn", "docker-compose", fmt.Sprintf("写入环境变量文件失败: %v", err))
		} else {
			args = append([]string{"-f", composeFile, "-p", projectName, "--env-file", ".env.sslcat"}, args[3:]...)
		}
	}

	if err := b.runCommandWithLogging(app.RepoDir, logger, "docker-compose", args...); err != nil {
		return fmt.Errorf("Docker Compose 启动失败: %w", err)
	}

	// 等待容器启动
	logger.WriteLog("info", "docker-compose", "等待容器启动...")

	// 检查容器状态
	logger.WriteLog("info", "docker-compose", "检查容器状态...")
	if err := b.runCommandWithLogging(app.RepoDir, logger, "docker-compose", "-f", composeFile, "-p", projectName, "ps"); err != nil {
		logger.WriteLog("warn", "docker-compose", "无法获取容器状态")
	}

	logger.WriteLog("success", "docker-compose", "Docker Compose 应用启动成功")

	// 显示服务信息
	b.logServiceInfo(app, composeFile, projectName, logger)

	return nil
}

// GetDefaultPort Docker Compose 默认端口
func (b *DockerComposeBuilder) GetDefaultPort() int {
	return 8080
}

// findComposeFile 查找 docker-compose 配置文件
func (b *DockerComposeBuilder) findComposeFile(appPath string) string {
	candidates := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"compose.yml",
		"compose.yaml",
	}

	for _, file := range candidates {
		path := filepath.Join(appPath, file)
		if _, err := os.Stat(path); err == nil {
			return file
		}
	}

	return ""
}

// validateComposeFile 验证 compose 文件
func (b *DockerComposeBuilder) validateComposeFile(appPath, composeFile string, logger *DeployLogger) error {
	// 使用 docker-compose config 验证配置
	if err := b.runCommandWithLogging(appPath, logger, "docker-compose", "-f", composeFile, "config", "--quiet"); err != nil {
		return fmt.Errorf("配置文件验证失败: %w", err)
	}
	return nil
}

// getProjectName 生成项目名称
func (b *DockerComposeBuilder) getProjectName(app *GitApp) string {
	// 使用应用名称作为项目名称，确保唯一性
	return fmt.Sprintf("sslcat-%s", app.Name)
}

// buildEnvArgs 构建环境变量参数
func (b *DockerComposeBuilder) buildEnvArgs(app *GitApp) map[string]string {
	envArgs := make(map[string]string)

	// 添加应用的环境变量
	for key, value := range app.EnvVars {
		envArgs[key] = value
	}

	// 添加 SSLcat 相关的环境变量
	envArgs["SSLCAT_APP_NAME"] = app.Name
	envArgs["SSLCAT_APP_PORT"] = fmt.Sprintf("%d", app.Port)
	envArgs["SSLCAT_APP_DOMAIN"] = app.Domain

	return envArgs
}

// writeEnvFile 写入环境变量文件
func (b *DockerComposeBuilder) writeEnvFile(app *GitApp, envVars map[string]string, logger *DeployLogger) error {
	envFile := filepath.Join(app.RepoDir, ".env.sslcat")

	var lines []string
	lines = append(lines, "# SSLcat 自动生成的环境变量文件")
	lines = append(lines, fmt.Sprintf("# 生成时间: %s", logger.startTime.Format("2006-01-02 15:04:05")))
	lines = append(lines, "")

	for key, value := range envVars {
		// 转义特殊字符
		escapedValue := strings.ReplaceAll(value, "\"", "\\\"")
		lines = append(lines, fmt.Sprintf("%s=\"%s\"", key, escapedValue))
	}

	content := strings.Join(lines, "\n")
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		return err
	}

	logger.WriteLog("info", "docker-compose", fmt.Sprintf("环境变量文件已写入: %s", envFile))
	return nil
}

// logServiceInfo 输出服务信息
func (b *DockerComposeBuilder) logServiceInfo(app *GitApp, composeFile, projectName string, logger *DeployLogger) {
	logger.WriteLog("info", "docker-compose", "")
	logger.WriteLog("info", "docker-compose", "=== 部署信息 ===")
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("应用名称: %s", app.Name))
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("项目名称: %s", projectName))
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("配置文件: %s", composeFile))
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("访问域名: %s", app.Domain))
	logger.WriteLog("info", "docker-compose", "")
	logger.WriteLog("info", "docker-compose", "=== 管理命令 ===")
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("查看日志: docker-compose -f %s -p %s logs -f", composeFile, projectName))
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("停止服务: docker-compose -f %s -p %s stop", composeFile, projectName))
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("重启服务: docker-compose -f %s -p %s restart", composeFile, projectName))
	logger.WriteLog("info", "docker-compose", fmt.Sprintf("删除服务: docker-compose -f %s -p %s down", composeFile, projectName))
	logger.WriteLog("info", "docker-compose", "")
}
