package runner

import (
	"fmt"
	"os"
	"path/filepath"
)

// StaticBuilder 静态文件应用构建器（基于 Nginx）
type StaticBuilder struct {
	*BaseBuilder
}

// NewStaticBuilder 创建静态文件构建器
func NewStaticBuilder(gs *GitServer) *StaticBuilder {
	return &StaticBuilder{
		BaseBuilder: NewBaseBuilder("static", "Static (Nginx)", 80, gs),
	}
}

// Detect 检测是否为静态文件应用
// 只有当其他所有 builder 都检测不出来，且根目录存在 index.html 或 index.htm 时才触发
func (b *StaticBuilder) Detect(appPath string) (bool, error) {
	// 检测根目录是否存在 index.html 或 index.htm
	return b.anyFileExists(appPath, []string{"index.html", "index.htm"}), nil
}

// Build 构建应用（创建临时 Dockerfile 并构建 Docker 镜像）
func (b *StaticBuilder) Build(app *GitApp) error {
	return b.buildDockerImage(app, nil)
}

// BuildWithLogging 构建应用（带日志）
func (b *StaticBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "static", "检测到静态文件应用")
	logger.WriteLog("info", "static", "准备使用 Nginx 镜像构建...")
	return b.buildDockerImage(app, logger)
}

// buildDockerImage 构建 Docker 镜像
func (b *StaticBuilder) buildDockerImage(app *GitApp, logger *DeployLogger) error {
	// 创建临时 Dockerfile
	dockerfilePath := filepath.Join(app.RepoDir, "Dockerfile.sslcat-static")

	// 生成 Dockerfile 内容
	dockerfileContent := `FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
`

	if logger != nil {
		logger.WriteLog("info", "static", "创建临时 Dockerfile...")
	}

	// 写入临时 Dockerfile
	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
		return fmt.Errorf("创建 Dockerfile 失败: %w", err)
	}

	// 确保构建完成后删除临时 Dockerfile
	defer os.Remove(dockerfilePath)

	imageName := fmt.Sprintf("sslcat-%s:latest", app.Name)

	if logger != nil {
		logger.WriteLog("info", "static", fmt.Sprintf("构建 Docker 镜像: %s", imageName))
		if err := b.runCommandWithLogging(app.RepoDir, logger, "docker", "build", "-f", "Dockerfile.sslcat-static", "-t", imageName, "."); err != nil {
			return fmt.Errorf("Docker 镜像构建失败: %w", err)
		}
		logger.WriteLog("info", "static", "镜像构建成功")
	} else {
		if err := b.runCommand(app.RepoDir, "docker", "build", "-f", "Dockerfile.sslcat-static", "-t", imageName, "."); err != nil {
			return fmt.Errorf("Docker 镜像构建失败: %w", err)
		}
	}

	return nil
}

// Start 启动应用（使用 Docker 容器运行 Nginx）
func (b *StaticBuilder) Start(app *GitApp) error {
	imageName := fmt.Sprintf("sslcat-%s:latest", app.Name)
	containerName := fmt.Sprintf("sslcat-%s", app.Name)

	// 停止并删除旧容器
	b.runCommand(app.RepoDir, "docker", "stop", containerName)
	b.runCommand(app.RepoDir, "docker", "rm", containerName)

	// 启动新容器
	portMapping := fmt.Sprintf("%d:80", app.Port)
	if err := b.runCommand(app.RepoDir, "docker", "run", "-d",
		"--name", containerName,
		"-p", portMapping,
		imageName); err != nil {
		return fmt.Errorf("Docker 容器启动失败: %w", err)
	}

	return nil
}

// StartWithLogging 启动应用（带日志）
func (b *StaticBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "static", "启动 Nginx 容器...")

	imageName := fmt.Sprintf("sslcat-%s:latest", app.Name)
	containerName := fmt.Sprintf("sslcat-%s", app.Name)

	// 停止旧容器
	logger.WriteLog("info", "static", "停止旧容器（如果存在）...")
	b.runCommandWithLogging(app.RepoDir, logger, "docker", "stop", containerName)
	b.runCommandWithLogging(app.RepoDir, logger, "docker", "rm", containerName)

	// 启动新容器
	logger.WriteLog("info", "static", "启动新的 Nginx 容器...")
	portMapping := fmt.Sprintf("%d:80", app.Port)

	// 构建环境变量参数
	args := []string{"run", "-d", "--name", containerName, "-p", portMapping}
	for key, value := range app.EnvVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
	}
	args = append(args, imageName)

	if err := b.runCommandWithLogging(app.RepoDir, logger, "docker", args...); err != nil {
		return fmt.Errorf("Nginx 容器启动失败: %w", err)
	}

	logger.WriteLog("info", "static", fmt.Sprintf("静态站点已成功部署到 http://localhost:%d", app.Port))
	return nil
}

// GetDefaultPort 静态文件默认端口（Nginx 默认是 80）
func (b *StaticBuilder) GetDefaultPort() int {
	return 80
}
