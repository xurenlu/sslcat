package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ContainerManager 容器管理器
type ContainerManager struct {
	timeout time.Duration
}

// NewContainerManager 创建容器管理器
func NewContainerManager(timeout time.Duration) *ContainerManager {
	return &ContainerManager{
		timeout: timeout,
	}
}

// StartContainers 启动容器
func (cm *ContainerManager) StartContainers(workDir string) error {
	// 尝试使用 docker compose (v2)，如果失败则使用 docker-compose (v1)
	cmd := exec.Command("docker", "compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "up", "-d")
	cmd.Dir = workDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果 docker compose 失败，尝试 docker-compose
		cmd2 := exec.Command("docker-compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "up", "-d")
		cmd2.Dir = workDir
		output2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			// 返回第一个错误（docker compose v2）的详细信息
			return fmt.Errorf("启动容器失败 (docker compose v2 错误: %w, output: %s; docker-compose v1 也失败: %w, output: %s)", err, string(output), err2, string(output2))
		}
		return nil
	}
	return nil
}

// WaitForHealthy 等待容器健康
func (cm *ContainerManager) WaitForHealthy(workDir string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("等待容器健康超时")
		case <-ticker.C:
			if cm.checkContainersHealthy(workDir) {
				return nil
			}
		}
	}
}

// checkContainersHealthy 检查容器是否健康
func (cm *ContainerManager) checkContainersHealthy(workDir string) bool {
	// 尝试使用 docker compose (v2)
	cmd := exec.Command("docker", "compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "ps")
	cmd.Dir = workDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果失败，尝试 docker-compose (v1)
		cmd2 := exec.Command("docker-compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "ps")
		cmd2.Dir = workDir
		output2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return false
		}
		output = output2
	}

	// 检查输出中是否有 "Up" 状态
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	
	hasUp := false
	for _, line := range lines {
		if strings.Contains(line, "Up") && !strings.Contains(line, "Exit") {
			hasUp = true
			break
		}
	}

	return hasUp
}

// StopContainers 停止并清理容器
func (cm *ContainerManager) StopContainers(workDir string) error {
	// 尝试使用 docker compose (v2)
	cmd := exec.Command("docker", "compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "down", "-v", "--remove-orphans")
	cmd.Dir = workDir
	_, err := cmd.CombinedOutput()
	if err != nil {
		// 如果失败，尝试 docker-compose (v1)
		cmd2 := exec.Command("docker-compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "down", "-v", "--remove-orphans")
		cmd2.Dir = workDir
		output2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("停止容器失败: %w, output: %s", err2, string(output2))
		}
	}
	
	// 清理临时目录
	if err := os.RemoveAll(workDir); err != nil {
		return fmt.Errorf("清理临时目录失败: %w", err)
	}

	return nil
}

// GetContainerLogs 获取容器日志
func (cm *ContainerManager) GetContainerLogs(workDir string, serviceName string, lines int) (string, error) {
	// 尝试使用 docker compose (v2)
	cmd := exec.Command("docker", "compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "logs", "--tail", fmt.Sprintf("%d", lines), serviceName)
	cmd.Dir = workDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果失败，尝试 docker-compose (v1)
		cmd2 := exec.Command("docker-compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "logs", "--tail", fmt.Sprintf("%d", lines), serviceName)
		cmd2.Dir = workDir
		output2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return "", fmt.Errorf("获取日志失败: %w", err2)
		}
		return string(output2), nil
	}
	return string(output), nil
}

// CheckContainerStatus 检查容器状态
func (cm *ContainerManager) CheckContainerStatus(workDir string) (map[string]string, error) {
	// 尝试使用 docker compose (v2)
	cmd := exec.Command("docker", "compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "ps", "--format", "json")
	cmd.Dir = workDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果失败，尝试 docker-compose (v1)
		cmd2 := exec.Command("docker-compose", "-f", fmt.Sprintf("%s/docker-compose.yml", workDir), "ps", "--format", "json")
		cmd2.Dir = workDir
		output2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return nil, fmt.Errorf("检查容器状态失败: %w", err2)
		}
		output = output2
	}

	status := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Name") && strings.Contains(line, "State") {
			// 解析 JSON 格式的输出
			// 简化处理：直接查找容器名和状态
		}
	}

	return status, nil
}

