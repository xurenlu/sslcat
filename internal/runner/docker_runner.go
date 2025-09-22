package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// DockerRunner Docker Runner 管理器
type DockerRunner struct {
	config *config.Config
	tasks  map[string]*config.DockerRunnerTask
	mutex  sync.RWMutex
	logger *logrus.Logger
}

// NewDockerRunner 创建新的 Docker Runner
func NewDockerRunner(cfg *config.Config) *DockerRunner {
	return &DockerRunner{
		config: cfg,
		tasks:  make(map[string]*config.DockerRunnerTask),
		logger: logrus.WithField("component", "docker_runner").Logger,
	}
}

// Start 启动 Docker Runner
func (dr *DockerRunner) Start() error {
	if !dr.config.Runners.Docker.Enabled {
		dr.logger.Info("Docker Runner 未启用")
		return nil
	}

	// 检查 Docker 是否可用
	if err := dr.checkDocker(); err != nil {
		return fmt.Errorf("Docker 不可用: %w", err)
	}

	// 创建工作目录
	if err := os.MkdirAll(dr.config.Runners.Docker.WorkDir, 0755); err != nil {
		return fmt.Errorf("创建 Docker Runner 工作目录失败: %w", err)
	}

	// 加载现有任务
	if err := dr.loadTasks(); err != nil {
		dr.logger.Warnf("加载任务失败: %v", err)
	}

	// 启动清理协程
	if dr.config.Runners.Docker.AutoCleanup {
		go dr.cleanupRoutine()
	}

	dr.logger.Info("Docker Runner 已启动")
	return nil
}

// Stop 停止 Docker Runner
func (dr *DockerRunner) Stop() {
	dr.mutex.Lock()
	defer dr.mutex.Unlock()

	// 停止所有运行中的任务
	for _, task := range dr.tasks {
		if task.Status == "running" && task.ContainerID != "" {
			dr.stopTask(task)
		}
	}

	dr.logger.Info("Docker Runner 已停止")
}

// AddTask 添加新任务
func (dr *DockerRunner) AddTask(task *config.DockerRunnerTask) error {
	dr.mutex.Lock()
	defer dr.mutex.Unlock()

	// 生成任务ID
	if task.ID == "" {
		task.ID = fmt.Sprintf("docker_task_%d", time.Now().UnixNano())
	}

	// 设置默认值
	if task.Status == "" {
		task.Status = "stopped"
	}
	if task.Env == nil {
		task.Env = make(map[string]string)
	}
	if task.GitBranch == "" {
		task.GitBranch = "main"
	}

	// 添加 PORT 环境变量
	if task.Port > 0 {
		task.Env["PORT"] = strconv.Itoa(task.Port)
	}

	dr.tasks[task.ID] = task

	// 保存任务
	if err := dr.saveTasks(); err != nil {
		return fmt.Errorf("保存任务失败: %w", err)
	}

	dr.logger.Infof("Docker 任务 %s 已添加", task.ID)
	return nil
}

// StartTask 启动任务
func (dr *DockerRunner) StartTask(taskID string) error {
	dr.mutex.Lock()
	defer dr.mutex.Unlock()

	task, exists := dr.tasks[taskID]
	if !exists {
		return fmt.Errorf("任务 %s 不存在", taskID)
	}

	if task.Status == "running" || task.Status == "building" {
		return fmt.Errorf("任务 %s 已在运行中或构建中", taskID)
	}

	// 检查并发限制
	runningCount := 0
	for _, t := range dr.tasks {
		if t.Status == "running" || t.Status == "building" {
			runningCount++
		}
	}
	if runningCount >= dr.config.Runners.Docker.MaxConcurrent {
		return fmt.Errorf("已达到最大并发运行数限制 (%d)", dr.config.Runners.Docker.MaxConcurrent)
	}

	// 启动任务
	if err := dr.startTask(task); err != nil {
		task.Status = "error"
		task.ErrorMsg = err.Error()
		dr.saveTasks()
		return err
	}

	dr.logger.Infof("Docker 任务 %s 已启动", taskID)
	return nil
}

// StopTask 停止任务
func (dr *DockerRunner) StopTask(taskID string) error {
	dr.mutex.Lock()
	defer dr.mutex.Unlock()

	task, exists := dr.tasks[taskID]
	if !exists {
		return fmt.Errorf("任务 %s 不存在", taskID)
	}

	if task.Status != "running" {
		return fmt.Errorf("任务 %s 未在运行中", taskID)
	}

	dr.stopTask(task)
	dr.logger.Infof("Docker 任务 %s 已停止", taskID)
	return nil
}

// RemoveTask 删除任务
func (dr *DockerRunner) RemoveTask(taskID string) error {
	dr.mutex.Lock()
	defer dr.mutex.Unlock()

	task, exists := dr.tasks[taskID]
	if !exists {
		return fmt.Errorf("任务 %s 不存在", taskID)
	}

	// 如果任务正在运行，先停止
	if task.Status == "running" {
		dr.stopTask(task)
	}

	// 清理容器和镜像
	dr.cleanupTask(task)

	delete(dr.tasks, taskID)

	// 保存任务
	if err := dr.saveTasks(); err != nil {
		return fmt.Errorf("保存任务失败: %w", err)
	}

	dr.logger.Infof("Docker 任务 %s 已删除", taskID)
	return nil
}

// GetTask 获取任务信息
func (dr *DockerRunner) GetTask(taskID string) (*config.DockerRunnerTask, error) {
	dr.mutex.RLock()
	defer dr.mutex.RUnlock()

	task, exists := dr.tasks[taskID]
	if !exists {
		return nil, fmt.Errorf("任务 %s 不存在", taskID)
	}

	// 返回任务副本
	taskCopy := *task
	return &taskCopy, nil
}

// ListTasks 列出所有任务
func (dr *DockerRunner) ListTasks() []*config.DockerRunnerTask {
	dr.mutex.RLock()
	defer dr.mutex.RUnlock()

	tasks := make([]*config.DockerRunnerTask, 0, len(dr.tasks))
	for _, task := range dr.tasks {
		taskCopy := *task
		tasks = append(tasks, &taskCopy)
	}

	return tasks
}

// startTask 启动单个任务
func (dr *DockerRunner) startTask(task *config.DockerRunnerTask) error {
	// 设置状态为构建中
	task.Status = "building"
	task.StartTime = time.Now().Unix()
	task.ErrorMsg = ""
	dr.saveTasks()

	// 在 goroutine 中执行构建和运行
	go func() {
		if err := dr.buildAndRunTask(task); err != nil {
			dr.mutex.Lock()
			task.Status = "error"
			task.ErrorMsg = err.Error()
			dr.saveTasks()
			dr.mutex.Unlock()
		}
	}()

	return nil
}

// buildAndRunTask 构建并运行任务
func (dr *DockerRunner) buildAndRunTask(task *config.DockerRunnerTask) error {
	// 1. 克隆 Git 仓库
	repoPath, err := dr.cloneRepository(task)
	if err != nil {
		return fmt.Errorf("克隆仓库失败: %w", err)
	}

	// 2. 检测项目类型
	projectType, hasDockerfile, hasDockerCompose, err := dr.detectProjectType(repoPath)
	if err != nil {
		return fmt.Errorf("检测项目类型失败: %w", err)
	}

	// 更新任务信息
	dr.mutex.Lock()
	task.ProjectType = projectType
	task.HasDockerfile = hasDockerfile
	task.HasDockerCompose = hasDockerCompose
	dr.saveTasks()
	dr.mutex.Unlock()

	// 3. 构建 Docker 镜像
	imageName, err := dr.buildImage(task, repoPath)
	if err != nil {
		return fmt.Errorf("构建镜像失败: %w", err)
	}

	// 4. 运行容器
	containerID, err := dr.runContainer(task, imageName)
	if err != nil {
		return fmt.Errorf("运行容器失败: %w", err)
	}

	// 更新任务状态
	dr.mutex.Lock()
	task.Status = "running"
	task.ContainerID = containerID
	task.ImageName = imageName
	dr.saveTasks()
	dr.mutex.Unlock()

	return nil
}

// cloneRepository 克隆 Git 仓库
func (dr *DockerRunner) cloneRepository(task *config.DockerRunnerTask) (string, error) {
	repoPath := filepath.Join(dr.config.Runners.Docker.WorkDir, task.ID)

	// 如果目录已存在，先删除
	if _, err := os.Stat(repoPath); err == nil {
		os.RemoveAll(repoPath)
	}

	// 克隆仓库
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(dr.config.Runners.Git.CloneTimeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "clone", "-b", task.GitBranch, task.GitURL, repoPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git clone 失败: %w", err)
	}

	return repoPath, nil
}

// detectProjectType 检测项目类型
func (dr *DockerRunner) detectProjectType(repoPath string) (string, bool, bool, error) {
	// 检查 Dockerfile
	hasDockerfile := false
	if _, err := os.Stat(filepath.Join(repoPath, "Dockerfile")); err == nil {
		hasDockerfile = true
	}

	// 检查 docker-compose 文件
	hasDockerCompose := false
	for _, composeFile := range []string{"docker-compose.yml", "docker-compose.yaml"} {
		if _, err := os.Stat(filepath.Join(repoPath, composeFile)); err == nil {
			hasDockerCompose = true
			break
		}
	}

	// 如果有 Dockerfile 或 docker-compose，优先使用
	if hasDockerfile {
		return "dockerfile", hasDockerfile, hasDockerCompose, nil
	}
	if hasDockerCompose {
		return "dockercompose", hasDockerfile, hasDockerCompose, nil
	}

	// 检测其他项目类型
	projectType := dr.detectRuntimeType(repoPath)
	return projectType, hasDockerfile, hasDockerCompose, nil
}

// detectRuntimeType 检测运行时类型
func (dr *DockerRunner) detectRuntimeType(repoPath string) string {
	// 检查 go.mod
	if _, err := os.Stat(filepath.Join(repoPath, "go.mod")); err == nil {
		return "golang"
	}

	// 检查 package.json
	if _, err := os.Stat(filepath.Join(repoPath, "package.json")); err == nil {
		// 检查是否是 Next.js
		if _, err := os.Stat(filepath.Join(repoPath, "next.config.js")); err == nil {
			return "nextjs"
		}
		return "nodejs"
	}

	// 检查 requirements.txt 或 setup.py
	if _, err := os.Stat(filepath.Join(repoPath, "requirements.txt")); err == nil {
		return "python"
	}
	if _, err := os.Stat(filepath.Join(repoPath, "setup.py")); err == nil {
		return "python"
	}

	// 检查 composer.json
	if _, err := os.Stat(filepath.Join(repoPath, "composer.json")); err == nil {
		return "php"
	}

	// 检查 Gemfile
	if _, err := os.Stat(filepath.Join(repoPath, "Gemfile")); err == nil {
		return "ruby"
	}

	return "unknown"
}

// buildImage 构建 Docker 镜像
func (dr *DockerRunner) buildImage(task *config.DockerRunnerTask, repoPath string) (string, error) {
	imageName := fmt.Sprintf("%s:%s", dr.config.Runners.Docker.ImagePrefix, task.ID)

	// 构建镜像
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(dr.config.Runners.Docker.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", imageName, repoPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker build 失败: %w", err)
	}

	return imageName, nil
}

// runContainer 运行容器
func (dr *DockerRunner) runContainer(task *config.DockerRunnerTask, imageName string) (string, error) {
	// 准备环境变量
	envVars := make([]string, 0, len(task.Env))
	for key, value := range task.Env {
		envVars = append(envVars, fmt.Sprintf("%s=%s", key, value))
	}

	// 准备端口映射
	portMapping := fmt.Sprintf("%d:%d", task.Port, task.Port)

	// 运行容器
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(dr.config.Runners.Docker.Timeout)*time.Second)
	defer cancel()

	args := []string{"run", "-d", "--name", task.ID}

	// 添加环境变量
	for _, env := range envVars {
		args = append(args, "-e", env)
	}

	// 添加端口映射
	args = append(args, "-p", portMapping)

	// 添加镜像名
	args = append(args, imageName)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker run 失败: %w", err)
	}

	containerID := strings.TrimSpace(string(output))
	return containerID, nil
}

// stopTask 停止单个任务
func (dr *DockerRunner) stopTask(task *config.DockerRunnerTask) {
	if task.ContainerID != "" {
		// 停止容器
		cmd := exec.Command("docker", "stop", task.ContainerID)
		cmd.Run()

		// 删除容器
		cmd = exec.Command("docker", "rm", task.ContainerID)
		cmd.Run()
	}

	task.Status = "stopped"
	task.ContainerID = ""
	dr.saveTasks()
}

// cleanupTask 清理任务相关资源
func (dr *DockerRunner) cleanupTask(task *config.DockerRunnerTask) {
	// 停止并删除容器
	if task.ContainerID != "" {
		exec.Command("docker", "stop", task.ContainerID).Run()
		exec.Command("docker", "rm", task.ContainerID).Run()
	}

	// 删除镜像
	if task.ImageName != "" {
		exec.Command("docker", "rmi", task.ImageName).Run()
	}

	// 删除工作目录
	workPath := filepath.Join(dr.config.Runners.Docker.WorkDir, task.ID)
	os.RemoveAll(workPath)
}

// checkDocker 检查 Docker 是否可用
func (dr *DockerRunner) checkDocker() error {
	cmd := exec.Command("docker", "version")
	return cmd.Run()
}

// cleanupRoutine 清理协程
func (dr *DockerRunner) cleanupRoutine() {
	ticker := time.NewTicker(time.Duration(dr.config.Runners.Docker.CleanupInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		dr.cleanupOldTasks()
	}
}

// cleanupOldTasks 清理旧任务
func (dr *DockerRunner) cleanupOldTasks() {
	dr.mutex.Lock()
	defer dr.mutex.Unlock()

	cutoffTime := time.Now().Add(-time.Duration(dr.config.Runners.Docker.CleanupInterval) * time.Second).Unix()

	for _, task := range dr.tasks {
		if task.Status == "stopped" && task.StartTime < cutoffTime {
			dr.cleanupTask(task)
		}
	}
}

// loadTasks 加载任务
func (dr *DockerRunner) loadTasks() error {
	tasksFile := filepath.Join(dr.config.Runners.Docker.WorkDir, "tasks.json")
	if _, err := os.Stat(tasksFile); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(tasksFile)
	if err != nil {
		return fmt.Errorf("读取任务文件失败: %w", err)
	}

	var tasks map[string]*config.DockerRunnerTask
	if err := json.Unmarshal(data, &tasks); err != nil {
		return fmt.Errorf("解析任务文件失败: %w", err)
	}

	dr.tasks = tasks

	// 检查运行中的容器是否还在运行
	for _, task := range dr.tasks {
		if task.Status == "running" && task.ContainerID != "" {
			cmd := exec.Command("docker", "inspect", task.ContainerID)
			if err := cmd.Run(); err != nil {
				// 容器不存在，更新状态
				task.Status = "stopped"
				task.ContainerID = ""
			}
		}
	}

	dr.saveTasks()
	return nil
}

// saveTasks 保存任务
func (dr *DockerRunner) saveTasks() error {
	tasksFile := filepath.Join(dr.config.Runners.Docker.WorkDir, "tasks.json")
	data, err := json.MarshalIndent(dr.tasks, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化任务失败: %w", err)
	}

	if err := os.WriteFile(tasksFile, data, 0644); err != nil {
		return fmt.Errorf("写入任务文件失败: %w", err)
	}

	return nil
}
