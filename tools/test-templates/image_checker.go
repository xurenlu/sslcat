package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// ImageChecker 镜像检查器
type ImageChecker struct {
	cache map[string]bool
	mu    sync.RWMutex
}

// NewImageChecker 创建镜像检查器
func NewImageChecker() *ImageChecker {
	return &ImageChecker{
		cache: make(map[string]bool),
	}
}

// CheckImage 检查镜像是否存在
func (ic *ImageChecker) CheckImage(image string) (bool, error) {
	// 检查缓存
	ic.mu.RLock()
	if exists, found := ic.cache[image]; found {
		ic.mu.RUnlock()
		return exists, nil
	}
	ic.mu.RUnlock()

	// 执行检查
	exists, err := ic.checkImageExists(image)

	// 更新缓存
	ic.mu.Lock()
	ic.cache[image] = exists
	ic.mu.Unlock()

	return exists, err
}

// checkImageExists 实际检查镜像是否存在
func (ic *ImageChecker) checkImageExists(image string) (bool, error) {
	// 使用 docker manifest inspect 检查镜像
	cmd := exec.Command("docker", "manifest", "inspect", image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果命令失败，可能是镜像不存在或需要认证
		// 尝试使用 docker pull --dry-run（但这会实际下载，所以不使用）
		// 或者直接返回 false
		if strings.Contains(string(output), "manifest unknown") ||
			strings.Contains(string(output), "not found") ||
			strings.Contains(string(output), "unauthorized") {
			return false, nil
		}
		return false, fmt.Errorf("检查镜像失败: %w, output: %s", err, string(output))
	}

	return true, nil
}

// ExtractImages 从 ComposeFile 提取所有镜像
func ExtractImages(compose *ComposeFile) []string {
	var images []string
	seen := make(map[string]bool)

	for _, service := range compose.Services {
		if service.Image != "" && !seen[service.Image] {
			images = append(images, service.Image)
			seen[service.Image] = true
		}
	}

	return images
}

// ReplaceImageVariables 替换镜像名称中的变量
func ReplaceImageVariables(image string, variables map[string]string) string {
	result := image
	for key, value := range variables {
		placeholder := fmt.Sprintf("{{%s}}", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}
	return result
}

