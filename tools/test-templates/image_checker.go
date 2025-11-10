package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ImageChecker 镜像检查器
type ImageChecker struct {
	cache        map[string]bool
	mu           sync.RWMutex
	ghcrLoggedIn bool
	ghcrLoginMu  sync.Mutex
}

// NewImageChecker 创建镜像检查器
func NewImageChecker() *ImageChecker {
	return &ImageChecker{
		cache:        make(map[string]bool),
		ghcrLoggedIn: false,
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
	// 如果是 ghcr.io 镜像且未登录，先尝试登录
	if strings.HasPrefix(image, "ghcr.io/") {
		if err := ic.ensureGHCRLogin(); err != nil {
			// 登录失败不影响检查，继续尝试
			fmt.Printf("⚠️  GHCR 登录失败（可能不需要认证）: %v\n", err)
		}
	}

	// 使用 docker manifest inspect 检查镜像
	cmd := exec.Command("docker", "manifest", "inspect", image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		outputStr := string(output)
		// 如果是认证错误，尝试登录后重试
		if strings.Contains(outputStr, "unauthorized") ||
			strings.Contains(outputStr, "denied") ||
			strings.Contains(outputStr, "authentication required") {
			// 对于 ghcr.io，尝试登录后重试一次
			if strings.HasPrefix(image, "ghcr.io/") {
				if err := ic.loginGHCR(); err == nil {
					// 登录成功，重试检查
					cmd2 := exec.Command("docker", "manifest", "inspect", image)
					output2, err2 := cmd2.CombinedOutput()
					if err2 == nil {
						return true, nil
					}
					// 重试后仍然失败，可能是镜像不存在
					if strings.Contains(string(output2), "manifest unknown") ||
						strings.Contains(string(output2), "not found") {
						return false, nil
					}
				}
			}
			return false, nil
		}
		if strings.Contains(outputStr, "manifest unknown") ||
			strings.Contains(outputStr, "not found") {
			return false, nil
		}
		return false, fmt.Errorf("检查镜像失败: %w, output: %s", err, outputStr)
	}

	return true, nil
}

// ensureGHCRLogin 确保已登录到 GHCR
func (ic *ImageChecker) ensureGHCRLogin() error {
	ic.ghcrLoginMu.Lock()
	defer ic.ghcrLoginMu.Unlock()

	if ic.ghcrLoggedIn {
		return nil
	}

	return ic.loginGHCR()
}

// loginGHCR 登录到 GitHub Container Registry
func (ic *ImageChecker) loginGHCR() error {
	// 从环境变量获取 GitHub Personal Access Token
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		// 也支持 GITHUB_PAT 环境变量
		githubToken = os.Getenv("GITHUB_PAT")
	}

	if githubToken == "" {
		return fmt.Errorf("未设置 GITHUB_TOKEN 或 GITHUB_PAT 环境变量")
	}

	// 获取 GitHub 用户名（可选，如果未设置则使用 token 作为用户名）
	githubUsername := os.Getenv("GITHUB_USERNAME")
	if githubUsername == "" {
		// 如果没有设置用户名，使用 token 作为用户名（GitHub 允许这样做）
		githubUsername = githubToken
	}

	// 执行 docker login
	// 对于 ghcr.io，用户名可以是 GitHub 用户名，密码是 PAT
	// 或者用户名和密码都使用 PAT
	// 使用 --password-stdin 避免密码泄露到命令行
	cmd := exec.Command("docker", "login", "-u", githubUsername, "--password-stdin", "ghcr.io")
	cmd.Stdin = strings.NewReader(githubToken)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GHCR 登录失败: %w, output: %s", err, string(output))
	}

	ic.ghcrLoggedIn = true
	fmt.Printf("✅ 已登录到 GitHub Container Registry (ghcr.io)\n")
	return nil
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
