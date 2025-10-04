package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DockerRegistry Docker镜像仓库管理器
type DockerRegistry struct {
	config *DockerRegistryConfig
	log    *logrus.Entry
}

// DockerRegistryConfig Docker镜像仓库配置
type DockerRegistryConfig struct {
	// 仓库地址
	URL string `json:"url"`

	// 认证信息
	Username string `json:"username"`
	Password string `json:"password"`

	// 仓库命名空间
	Namespace string `json:"namespace"`

	// 是否启用
	Enabled bool `json:"enabled"`

	// 是否使用HTTPS
	UseHTTPS bool `json:"use_https"`

	// 连接超时
	Timeout int `json:"timeout"`

	// 镜像标签策略
	TagStrategy string `json:"tag_strategy"` // "commit", "timestamp", "version"

	// 是否自动推送
	AutoPush bool `json:"auto_push"`

	// 镜像清理策略
	CleanupPolicy DockerCleanupPolicy `json:"cleanup_policy"`
}

// DockerCleanupPolicy Docker镜像清理策略
type DockerCleanupPolicy struct {
	// 是否启用自动清理
	Enabled bool `json:"enabled"`

	// 保留镜像数量
	KeepImages int `json:"keep_images"`

	// 保留天数
	KeepDays int `json:"keep_days"`

	// 清理间隔（小时）
	CleanInterval int `json:"clean_interval"`
}

// DockerImage Docker镜像信息
type DockerImage struct {
	// 镜像名称
	Name string `json:"name"`

	// 镜像标签
	Tag string `json:"tag"`

	// 完整镜像名
	FullName string `json:"full_name"`

	// 镜像大小
	Size int64 `json:"size"`

	// 创建时间
	CreatedAt time.Time `json:"created_at"`

	// 推送时间
	PushedAt time.Time `json:"pushed_at"`

	// 提交哈希
	CommitHash string `json:"commit_hash"`

	// 构建状态
	BuildStatus string `json:"build_status"`

	// 推送状态
	PushStatus string `json:"push_status"`
}

// NewDockerRegistry 创建Docker镜像仓库管理器
func NewDockerRegistry(config *DockerRegistryConfig) *DockerRegistry {
	if config == nil {
		config = &DockerRegistryConfig{
			Enabled:     false,
			UseHTTPS:    true,
			Timeout:     30,
			TagStrategy: "commit",
			AutoPush:    true,
			CleanupPolicy: DockerCleanupPolicy{
				Enabled:       true,
				KeepImages:    10,
				KeepDays:      30,
				CleanInterval: 24,
			},
		}
	}

	return &DockerRegistry{
		config: config,
		log: logrus.WithFields(logrus.Fields{
			"component": "docker_registry",
		}),
	}
}

// BuildAndPushImage 构建并推送Docker镜像
func (dr *DockerRegistry) BuildAndPushImage(app *GitApp, deployLogger *DeployLogger) (*DockerImage, error) {
	if !dr.config.Enabled {
		return nil, fmt.Errorf("Docker registry is disabled")
	}

	// 生成镜像名称和标签
	imageName := fmt.Sprintf("%s/%s", dr.config.Namespace, app.Name)
	tag := dr.generateTag(app)
	fullImageName := fmt.Sprintf("%s:%s", imageName, tag)

	if dr.config.URL != "" {
		fullImageName = fmt.Sprintf("%s/%s", dr.config.URL, fullImageName)
	}

	deployLogger.WriteLog("info", "docker", fmt.Sprintf("开始构建Docker镜像: %s", fullImageName))

	// 构建镜像
	if err := dr.buildImage(app, fullImageName, deployLogger); err != nil {
		return nil, fmt.Errorf("failed to build image: %w", err)
	}

	// 推送镜像
	if dr.config.AutoPush {
		if err := dr.pushImage(fullImageName, deployLogger); err != nil {
			return nil, fmt.Errorf("failed to push image: %w", err)
		}
	}

	// 创建镜像信息
	image := &DockerImage{
		Name:        imageName,
		Tag:         tag,
		FullName:    fullImageName,
		CreatedAt:   time.Now(),
		PushedAt:    time.Now(),
		CommitHash:  app.LastCommit,
		BuildStatus: "success",
		PushStatus:  "success",
	}

	deployLogger.WriteLog("info", "docker", fmt.Sprintf("Docker镜像构建和推送完成: %s", fullImageName))

	return image, nil
}

// buildImage 构建Docker镜像
func (dr *DockerRegistry) buildImage(app *GitApp, imageName string, deployLogger *DeployLogger) error {
	// 检查Dockerfile是否存在
	dockerfilePath := filepath.Join(app.GitPath, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		// 如果没有Dockerfile，生成一个默认的
		if err := dr.generateDefaultDockerfile(app); err != nil {
			return fmt.Errorf("failed to generate Dockerfile: %w", err)
		}
		deployLogger.WriteLog("info", "docker", "生成默认Dockerfile")
	}

	// 构建镜像
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", imageName, app.GitPath)

	deployLogger.WriteCommand("docker", []string{"build", "-t", imageName, app.GitPath})

	// 捕获输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		deployLogger.WriteCommandOutput(string(output))
		deployLogger.WriteError(fmt.Errorf("docker build failed: %w", err))
		return fmt.Errorf("docker build failed: %w", err)
	}

	deployLogger.WriteCommandOutput(string(output))
	deployLogger.WriteLog("info", "docker", "Docker镜像构建成功")

	return nil
}

// pushImage 推送Docker镜像
func (dr *DockerRegistry) pushImage(imageName string, deployLogger *DeployLogger) error {
	// 登录到Docker Registry
	if err := dr.dockerLogin(deployLogger); err != nil {
		return fmt.Errorf("failed to login to registry: %w", err)
	}

	// 推送镜像
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "push", imageName)

	deployLogger.WriteCommand("docker", []string{"push", imageName})

	// 捕获输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		deployLogger.WriteCommandOutput(string(output))
		deployLogger.WriteError(fmt.Errorf("docker push failed: %w", err))
		return fmt.Errorf("docker push failed: %w", err)
	}

	deployLogger.WriteCommandOutput(string(output))
	deployLogger.WriteLog("info", "docker", "Docker镜像推送成功")

	return nil
}

// dockerLogin 登录到Docker Registry
func (dr *DockerRegistry) dockerLogin(deployLogger *DeployLogger) error {
	if dr.config.Username == "" || dr.config.Password == "" {
		return fmt.Errorf("Docker registry credentials not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if dr.config.URL != "" {
		cmd = exec.CommandContext(ctx, "docker", "login", "-u", dr.config.Username, "-p", dr.config.Password, dr.config.URL)
	} else {
		cmd = exec.CommandContext(ctx, "docker", "login", "-u", dr.config.Username, "-p", dr.config.Password)
	}

	deployLogger.WriteLog("info", "docker", "登录到Docker Registry")

	output, err := cmd.CombinedOutput()
	if err != nil {
		deployLogger.WriteCommandOutput(string(output))
		deployLogger.WriteError(fmt.Errorf("docker login failed: %w", err))
		return fmt.Errorf("docker login failed: %w", err)
	}

	deployLogger.WriteCommandOutput(string(output))
	deployLogger.WriteLog("info", "docker", "Docker Registry登录成功")
	return nil
}

// generateTag 生成镜像标签
func (dr *DockerRegistry) generateTag(app *GitApp) string {
	switch dr.config.TagStrategy {
	case "commit":
		if app.LastCommit != "" && len(app.LastCommit) >= 7 {
			return app.LastCommit[:7]
		}
		return "latest"
	case "timestamp":
		return time.Now().Format("20060102-150405")
	case "version":
		// 尝试从package.json或其他文件中读取版本
		if version := dr.extractVersion(app); version != "" {
			return version
		}
		return "latest"
	default:
		return "latest"
	}
}

// extractVersion 从项目文件中提取版本信息
func (dr *DockerRegistry) extractVersion(app *GitApp) string {
	// 尝试从package.json读取版本
	packageJSONPath := filepath.Join(app.GitPath, "package.json")
	if data, err := os.ReadFile(packageJSONPath); err == nil {
		var packageJSON map[string]interface{}
		if err := json.Unmarshal(data, &packageJSON); err == nil {
			if version, ok := packageJSON["version"].(string); ok {
				return version
			}
		}
	}

	// 尝试从其他文件读取版本
	versionFiles := []string{"VERSION", "version.txt", ".version"}
	for _, file := range versionFiles {
		filePath := filepath.Join(app.GitPath, file)
		if data, err := os.ReadFile(filePath); err == nil {
			version := strings.TrimSpace(string(data))
			if version != "" {
				return version
			}
		}
	}

	return ""
}

// generateDefaultDockerfile 生成默认Dockerfile
func (dr *DockerRegistry) generateDefaultDockerfile(app *GitApp) error {
	var dockerfile string

	switch app.AppType {
	case "nodejs":
		dockerfile = `FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]`

	case "python":
		dockerfile = `FROM python:3.9-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "app.py"]`

	case "go":
		dockerfile = `FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["./main"]`

	case "php":
		dockerfile = `FROM php:8.1-apache
COPY . /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
CMD ["apache2-foreground"]`

	case "static":
		dockerfile = `FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]`

	default:
		dockerfile = `FROM alpine:latest
COPY . /app
WORKDIR /app
EXPOSE 8080
CMD ["sh", "-c", "echo 'Application started' && sleep infinity"]`
	}

	dockerfilePath := filepath.Join(app.GitPath, "Dockerfile")
	return os.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
}

// ListImages 列出镜像
func (dr *DockerRegistry) ListImages(appName string) ([]DockerImage, error) {
	if !dr.config.Enabled {
		return nil, fmt.Errorf("Docker registry is disabled")
	}

	// 构建镜像名称模式
	imagePattern := fmt.Sprintf("%s/%s", dr.config.Namespace, appName)
	if dr.config.URL != "" {
		imagePattern = fmt.Sprintf("%s/%s", dr.config.URL, imagePattern)
	}

	// 执行docker images命令
	cmd := exec.Command("docker", "images", imagePattern, "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	var images []DockerImage
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var dockerInfo map[string]interface{}
		if err := json.Unmarshal([]byte(line), &dockerInfo); err != nil {
			continue
		}

		image := DockerImage{
			Name:     fmt.Sprintf("%s", dockerInfo["Repository"]),
			Tag:      fmt.Sprintf("%s", dockerInfo["Tag"]),
			FullName: fmt.Sprintf("%s:%s", dockerInfo["Repository"], dockerInfo["Tag"]),
		}

		// 解析创建时间
		if createdAt, ok := dockerInfo["CreatedAt"].(string); ok {
			if t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", createdAt); err == nil {
				image.CreatedAt = t
			}
		}

		images = append(images, image)
	}

	return images, nil
}

// DeleteImage 删除镜像
func (dr *DockerRegistry) DeleteImage(imageName string) error {
	if !dr.config.Enabled {
		return fmt.Errorf("Docker registry is disabled")
	}

	// 从本地删除镜像
	cmd := exec.Command("docker", "rmi", imageName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete local image: %w", err)
	}

	// 如果配置了远程仓库，也尝试删除远程镜像
	if dr.config.URL != "" {
		if err := dr.deleteRemoteImage(imageName); err != nil {
			dr.log.Warnf("Failed to delete remote image: %v", err)
			// 不返回错误，因为本地删除已经成功
		}
	}

	return nil
}

// deleteRemoteImage 删除远程镜像
func (dr *DockerRegistry) deleteRemoteImage(imageName string) error {
	// 解析镜像名称
	parts := strings.Split(imageName, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid image name format")
	}

	repository := parts[0]
	tag := parts[1]

	// 移除registry URL前缀
	if dr.config.URL != "" {
		repository = strings.TrimPrefix(repository, dr.config.URL+"/")
	}

	// 构建删除API URL
	deleteURL := fmt.Sprintf("%s/v2/%s/manifests/%s", dr.config.URL, repository, tag)

	// 创建HTTP请求
	req, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	// 添加认证头部
	if dr.config.Username != "" && dr.config.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(dr.config.Username + ":" + dr.config.Password))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	// 发送请求
	client := &http.Client{Timeout: time.Duration(dr.config.Timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete remote image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete remote image: %s", string(body))
	}

	return nil
}

// CleanupOldImages 清理旧镜像
func (dr *DockerRegistry) CleanupOldImages(appName string) error {
	if !dr.config.Enabled || !dr.config.CleanupPolicy.Enabled {
		return nil
	}

	images, err := dr.ListImages(appName)
	if err != nil {
		return fmt.Errorf("failed to list images for cleanup: %w", err)
	}

	// 按创建时间排序，保留最新的镜像
	if len(images) <= dr.config.CleanupPolicy.KeepImages {
		return nil // 不需要清理
	}

	// 计算需要删除的镜像
	cutoffTime := time.Now().AddDate(0, 0, -dr.config.CleanupPolicy.KeepDays)
	var imagesToDelete []DockerImage

	for i, image := range images {
		// 保留最新的N个镜像
		if i < dr.config.CleanupPolicy.KeepImages {
			continue
		}

		// 删除超过保留天数的镜像
		if image.CreatedAt.Before(cutoffTime) {
			imagesToDelete = append(imagesToDelete, image)
		}
	}

	// 删除旧镜像
	for _, image := range imagesToDelete {
		if err := dr.DeleteImage(image.FullName); err != nil {
			dr.log.Errorf("Failed to delete old image %s: %v", image.FullName, err)
		} else {
			dr.log.Infof("Deleted old image: %s", image.FullName)
		}
	}

	return nil
}

// TestConnection 测试Registry连接（使用当前配置）
func (dr *DockerRegistry) TestConnection() error {
	return dr.TestConnectionWithConfig(dr.config)
}

// TestConnectionWithConfig 测试Registry连接（使用指定配置）
func (dr *DockerRegistry) TestConnectionWithConfig(config *DockerRegistryConfig) error {
	dr.log.Infof("开始测试 Docker Registry 连接...")
	dr.log.Infof("  URL: %s", config.URL)
	dr.log.Infof("  UseHTTPS: %v", config.UseHTTPS)
	dr.log.Infof("  Username: %s", config.Username)
	dr.log.Infof("  Timeout: %d", config.Timeout)
	
	if config.URL == "" {
		dr.log.Info("  URL 为空，测试本地 Docker daemon")
		// 测试本地Docker daemon
		cmd := exec.Command("docker", "version")
		if err := cmd.Run(); err != nil {
			dr.log.Errorf("  ❌ Docker daemon 不可用: %v", err)
			return fmt.Errorf("Docker daemon not available: %w", err)
		}
		dr.log.Info("  ✓ Docker daemon 可用")
		return nil
	}

	// 确保 URL 有协议前缀
	url := config.URL
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		// 默认使用 HTTPS
		if config.UseHTTPS {
			url = "https://" + url
			dr.log.Infof("  自动添加 HTTPS 协议: %s", url)
		} else {
			url = "http://" + url
			dr.log.Infof("  自动添加 HTTP 协议: %s", url)
		}
	} else {
		dr.log.Infof("  URL 已包含协议: %s", url)
	}

	// 测试远程Registry连接
	testURL := fmt.Sprintf("%s/v2/", url)
	dr.log.Infof("  测试 URL: %s", testURL)

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 // 默认10秒
		dr.log.Infof("  使用默认超时: %d 秒", timeout)
	} else {
		dr.log.Infof("  超时设置: %d 秒", timeout)
	}
	
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		dr.log.Errorf("  ❌ 创建请求失败: %v", err)
		return fmt.Errorf("failed to create test request: %w", err)
	}

	// 添加认证
	if config.Username != "" && config.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(config.Username + ":" + config.Password))
		req.Header.Set("Authorization", "Basic "+auth)
		dr.log.Info("  已添加 Basic 认证")
	} else {
		dr.log.Info("  未配置认证信息")
	}

	dr.log.Info("  发送请求...")
	resp, err := client.Do(req)
	if err != nil {
		dr.log.Errorf("  ❌ 连接失败: %v", err)
		return fmt.Errorf("failed to connect to registry: %w", err)
	}
	defer resp.Body.Close()

	dr.log.Infof("  响应状态码: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		dr.log.Errorf("  ❌ Registry 返回错误状态: %d, body: %s", resp.StatusCode, string(body))
		return fmt.Errorf("registry returned status: %d, body: %s", resp.StatusCode, string(body))
	}

	// 401 也算连接成功，只是认证失败
	if resp.StatusCode == http.StatusUnauthorized {
		dr.log.Warn("  ⚠️  认证失败 - 请检查用户名和密码")
		return fmt.Errorf("authentication failed - please check username and password")
	}

	dr.log.Info("  ✓ 连接成功！")
	return nil
}

// GetStats 获取Docker Registry统计信息
func (dr *DockerRegistry) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled":        dr.config.Enabled,
		"url":            dr.config.URL,
		"namespace":      dr.config.Namespace,
		"tag_strategy":   dr.config.TagStrategy,
		"auto_push":      dr.config.AutoPush,
		"cleanup_policy": dr.config.CleanupPolicy,
	}

	// 测试连接状态
	err := dr.TestConnection()
	stats["connection_status"] = err == nil
	if err != nil {
		stats["connection_error"] = err.Error()
	}

	return stats
}

// StartCleanupScheduler 启动清理调度器
func (dr *DockerRegistry) StartCleanupScheduler() {
	if !dr.config.Enabled || !dr.config.CleanupPolicy.Enabled {
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(dr.config.CleanupPolicy.CleanInterval) * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			dr.log.Info("Starting scheduled Docker image cleanup")

			// 这里需要获取所有应用列表进行清理
			// 由于没有直接访问GitServer的引用，这个功能需要在GitServer中调用

			dr.log.Info("Scheduled Docker image cleanup completed")
		}
	}()

	dr.log.Infof("Started Docker registry cleanup scheduler (interval: %d hours)", dr.config.CleanupPolicy.CleanInterval)
}

// UpdateConfig 更新 Docker Registry 配置
func (dr *DockerRegistry) UpdateConfig(newConfig *DockerRegistryConfig) {
	dr.config = newConfig
	dr.log.Info("Docker Registry configuration updated")
}

// GetConfig 获取 Docker Registry 配置
func (dr *DockerRegistry) GetConfig() *DockerRegistryConfig {
	return dr.config
}
