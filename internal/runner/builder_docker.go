package runner

import (
	"fmt"
)

// DockerBuilder Docker 应用构建器
type DockerBuilder struct {
	*BaseBuilder
}

// NewDockerBuilder 创建 Docker 构建器
func NewDockerBuilder(gs *GitServer) *DockerBuilder {
	return &DockerBuilder{
		BaseBuilder: NewBaseBuilder("docker", "Docker", 8080, gs),
	}
}

// Detect 检测是否为 Docker 应用
func (b *DockerBuilder) Detect(appPath string) (bool, error) {
	return b.fileExists(appPath, "Dockerfile"), nil
}

// Build 构建应用
func (b *DockerBuilder) Build(app *GitApp) error {
	// Docker 构建逻辑由 DockerRegistry 处理
	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *DockerBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "docker", "开始 Docker 应用构建流程")

	// 检查是否有 Docker Registry
	dockerRegistry := b.gs.GetDockerRegistry()

	imageName := fmt.Sprintf("sslcat-%s:latest", app.Name)

	// 判断是否启用了 Registry
	registryEnabled := false
	if dockerRegistry != nil {
		config := dockerRegistry.GetConfig()
		registryEnabled = config != nil && config.Enabled
	}

	if registryEnabled {
		// 有 Registry：构建并推送到私有仓库
		logger.WriteLog("info", "docker", "使用 Docker Registry 构建镜像")
		image, err := dockerRegistry.BuildAndPushImage(app, logger)
		if err != nil {
			return fmt.Errorf("Docker 镜像构建失败: %w", err)
		}
		logger.WriteLog("info", "docker", fmt.Sprintf("镜像构建并推送成功: %s", image.Name))
	} else {
		// 没有 Registry：直接在本地构建
		logger.WriteLog("info", "docker", "本地构建 Docker 镜像（无 Registry）")

		// 执行 docker build
		if err := b.runCommandWithLogging(app.RepoDir, logger, "docker", "build", "-t", imageName, "."); err != nil {
			return fmt.Errorf("本地 Docker 镜像构建失败: %w", err)
		}

		logger.WriteLog("info", "docker", fmt.Sprintf("本地镜像构建成功: %s", imageName))
	}

	return nil
}

// Start 启动应用
func (b *DockerBuilder) Start(app *GitApp) error {
	// Docker 容器启动逻辑
	imageName := fmt.Sprintf("sslcat-%s:latest", app.Name)
	containerName := fmt.Sprintf("sslcat-%s", app.Name)

	// 停止并删除旧容器
	b.runCommand(app.GitPath, "docker", "stop", containerName)
	b.runCommand(app.GitPath, "docker", "rm", containerName)

	// 启动新容器
	portMapping := fmt.Sprintf("%d:8080", app.Port)
	if err := b.runCommand(app.GitPath, "docker", "run", "-d",
		"--name", containerName,
		"-p", portMapping,
		imageName); err != nil {
		return fmt.Errorf("Docker 容器启动失败: %w", err)
	}

	return nil
}

// StartWithLogging 启动应用（带日志）
func (b *DockerBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "docker", "启动 Docker 容器...")

	imageName := fmt.Sprintf("sslcat-%s:latest", app.Name)
	containerName := fmt.Sprintf("sslcat-%s", app.Name)

	// 停止旧容器
	logger.WriteLog("info", "docker", "停止旧容器...")
	b.runCommandWithLogging(app.GitPath, logger, "docker", "stop", containerName)
	b.runCommandWithLogging(app.GitPath, logger, "docker", "rm", containerName)

	// 启动新容器
	logger.WriteLog("info", "docker", "启动新容器...")
	portMapping := fmt.Sprintf("%d:8080", app.Port)

	// 构建环境变量参数
	envArgs := []string{"run", "-d", "--name", containerName, "-p", portMapping}
	for key, value := range app.EnvVars {
		envArgs = append(envArgs, "-e", fmt.Sprintf("%s=%s", key, value))
	}
	envArgs = append(envArgs, imageName)

	if err := b.runCommandWithLogging(app.GitPath, logger, "docker", envArgs...); err != nil {
		return fmt.Errorf("Docker 容器启动失败: %w", err)
	}

	logger.WriteLog("info", "docker", "容器启动成功")
	return nil
}

// GetDefaultPort Docker 默认端口
func (b *DockerBuilder) GetDefaultPort() int {
	return 8080
}
