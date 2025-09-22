package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// GitServer Git 服务器管理器
type GitServer struct {
	config *config.Config
	repos  map[string]*GitRepository
	mutex  sync.RWMutex
	logger *logrus.Logger
}

// GitRepository Git 仓库信息
type GitRepository struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Branch      string    `json:"branch"`
	LocalPath   string    `json:"local_path"`
	LastUpdated time.Time `json:"last_updated"`
	Status      string    `json:"status"` // "cloned" | "updating" | "error"
	ErrorMsg    string    `json:"error_msg"`
}

// NewGitServer 创建新的 Git 服务器
func NewGitServer(cfg *config.Config) *GitServer {
	return &GitServer{
		config: cfg,
		repos:  make(map[string]*GitRepository),
		logger: logrus.WithField("component", "git_server").Logger,
	}
}

// Start 启动 Git 服务器
func (gs *GitServer) Start() error {
	if !gs.config.Runners.Git.Enabled {
		gs.logger.Info("Git 服务器未启用")
		return nil
	}

	// 检查 Git 是否可用
	if err := gs.checkGit(); err != nil {
		return fmt.Errorf("Git 不可用: %w", err)
	}

	// 创建仓库目录
	if err := os.MkdirAll(gs.config.Runners.Git.ReposDir, 0755); err != nil {
		return fmt.Errorf("创建 Git 仓库目录失败: %w", err)
	}

	// 加载现有仓库
	if err := gs.loadRepos(); err != nil {
		gs.logger.Warnf("加载仓库失败: %v", err)
	}

	// 启动清理协程
	if gs.config.Runners.Git.AutoCleanup {
		go gs.cleanupRoutine()
	}

	gs.logger.Info("Git 服务器已启动")
	return nil
}

// Stop 停止 Git 服务器
func (gs *GitServer) Stop() {
	gs.logger.Info("Git 服务器已停止")
}

// AddRepository 添加仓库
func (gs *GitServer) AddRepository(name, url, branch string) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	// 生成仓库ID
	repoID := fmt.Sprintf("repo_%d", time.Now().UnixNano())

	// 创建本地路径
	localPath := filepath.Join(gs.config.Runners.Git.ReposDir, repoID)

	repo := &GitRepository{
		ID:          repoID,
		Name:        name,
		URL:         url,
		Branch:      branch,
		LocalPath:   localPath,
		LastUpdated: time.Now(),
		Status:      "cloned",
	}

	gs.repos[repoID] = repo

	// 保存仓库信息
	if err := gs.saveRepos(); err != nil {
		return fmt.Errorf("保存仓库信息失败: %w", err)
	}

	// 在 goroutine 中克隆仓库
	go gs.cloneRepository(repo)

	gs.logger.Infof("仓库 %s 已添加", repoID)
	return nil
}

// RemoveRepository 删除仓库
func (gs *GitServer) RemoveRepository(repoID string) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	repo, exists := gs.repos[repoID]
	if !exists {
		return fmt.Errorf("仓库 %s 不存在", repoID)
	}

	// 删除本地目录
	if err := os.RemoveAll(repo.LocalPath); err != nil {
		gs.logger.Warnf("删除仓库目录失败: %v", err)
	}

	delete(gs.repos, repoID)

	// 保存仓库信息
	if err := gs.saveRepos(); err != nil {
		return fmt.Errorf("保存仓库信息失败: %w", err)
	}

	gs.logger.Infof("仓库 %s 已删除", repoID)
	return nil
}

// UpdateRepository 更新仓库
func (gs *GitServer) UpdateRepository(repoID string) error {
	gs.mutex.Lock()
	repo, exists := gs.repos[repoID]
	if !exists {
		gs.mutex.Unlock()
		return fmt.Errorf("仓库 %s 不存在", repoID)
	}
	gs.mutex.Unlock()

	// 在 goroutine 中更新仓库
	go gs.updateRepository(repo)

	gs.logger.Infof("仓库 %s 更新已启动", repoID)
	return nil
}

// GetRepository 获取仓库信息
func (gs *GitServer) GetRepository(repoID string) (*GitRepository, error) {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	repo, exists := gs.repos[repoID]
	if !exists {
		return nil, fmt.Errorf("仓库 %s 不存在", repoID)
	}

	// 返回仓库副本
	repoCopy := *repo
	return &repoCopy, nil
}

// ListRepositories 列出所有仓库
func (gs *GitServer) ListRepositories() []*GitRepository {
	gs.mutex.RLock()
	defer gs.mutex.RUnlock()

	repos := make([]*GitRepository, 0, len(gs.repos))
	for _, repo := range gs.repos {
		repoCopy := *repo
		repos = append(repos, &repoCopy)
	}

	return repos
}

// ExecuteInRepository 在仓库中执行命令
func (gs *GitServer) ExecuteInRepository(repoID string, command []string, workDir string) (*ExecutionResult, error) {
	gs.mutex.RLock()
	repo, exists := gs.repos[repoID]
	if !exists {
		gs.mutex.RUnlock()
		return nil, fmt.Errorf("仓库 %s 不存在", repoID)
	}
	gs.mutex.RUnlock()

	if repo.Status != "cloned" {
		return nil, fmt.Errorf("仓库 %s 状态异常: %s", repoID, repo.Status)
	}

	// 准备执行路径
	execPath := repo.LocalPath
	if workDir != "" {
		execPath = filepath.Join(repo.LocalPath, workDir)
	}

	// 检查执行路径是否存在
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("执行路径不存在: %s", execPath)
	}

	// 执行命令
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(gs.config.Runners.Git.CloneTimeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = execPath

	output, err := cmd.Output()
	result := &ExecutionResult{
		Command:    strings.Join(command, " "),
		Output:     string(output),
		ExitCode:   cmd.ProcessState.ExitCode(),
		Success:    err == nil,
		Error:      err,
		ExecutedAt: time.Now(),
	}

	if err != nil {
		result.ErrorMsg = err.Error()
	}

	return result, nil
}

// cloneRepository 克隆仓库
func (gs *GitServer) cloneRepository(repo *GitRepository) {
	gs.mutex.Lock()
	repo.Status = "updating"
	gs.mutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(gs.config.Runners.Git.CloneTimeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "clone", "-b", repo.Branch, repo.URL, repo.LocalPath)
	output, err := cmd.Output()

	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	if err != nil {
		repo.Status = "error"
		repo.ErrorMsg = fmt.Sprintf("克隆失败: %v, 输出: %s", err, string(output))
	} else {
		repo.Status = "cloned"
		repo.ErrorMsg = ""
		repo.LastUpdated = time.Now()
	}

	gs.saveRepos()
}

// updateRepository 更新仓库
func (gs *GitServer) updateRepository(repo *GitRepository) {
	gs.mutex.Lock()
	repo.Status = "updating"
	gs.mutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(gs.config.Runners.Git.CloneTimeout)*time.Second)
	defer cancel()

	// 切换到指定分支
	cmd := exec.CommandContext(ctx, "git", "checkout", repo.Branch)
	cmd.Dir = repo.LocalPath
	cmd.Run()

	// 拉取最新代码
	cmd = exec.CommandContext(ctx, "git", "pull", "origin", repo.Branch)
	cmd.Dir = repo.LocalPath
	output, err := cmd.Output()

	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	if err != nil {
		repo.Status = "error"
		repo.ErrorMsg = fmt.Sprintf("更新失败: %v, 输出: %s", err, string(output))
	} else {
		repo.Status = "cloned"
		repo.ErrorMsg = ""
		repo.LastUpdated = time.Now()
	}

	gs.saveRepos()
}

// checkGit 检查 Git 是否可用
func (gs *GitServer) checkGit() error {
	cmd := exec.Command("git", "version")
	return cmd.Run()
}

// cleanupRoutine 清理协程
func (gs *GitServer) cleanupRoutine() {
	ticker := time.NewTicker(time.Duration(gs.config.Runners.Git.CleanupInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		gs.cleanupOldRepos()
	}
}

// cleanupOldRepos 清理旧仓库
func (gs *GitServer) cleanupOldRepos() {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	cutoffTime := time.Now().Add(-time.Duration(gs.config.Runners.Git.CleanupInterval) * time.Second)

	for _, repo := range gs.repos {
		if repo.LastUpdated.Before(cutoffTime) {
			// 删除本地目录
			os.RemoveAll(repo.LocalPath)
			delete(gs.repos, repo.ID)
		}
	}

	gs.saveRepos()
}

// loadRepos 加载仓库
func (gs *GitServer) loadRepos() error {
	reposFile := filepath.Join(gs.config.Runners.Git.ReposDir, "repos.json")
	if _, err := os.Stat(reposFile); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(reposFile)
	if err != nil {
		return fmt.Errorf("读取仓库文件失败: %w", err)
	}

	var repos map[string]*GitRepository
	if err := json.Unmarshal(data, &repos); err != nil {
		return fmt.Errorf("解析仓库文件失败: %w", err)
	}

	gs.repos = repos

	// 检查本地目录是否存在
	for _, repo := range gs.repos {
		if _, err := os.Stat(repo.LocalPath); os.IsNotExist(err) {
			repo.Status = "error"
			repo.ErrorMsg = "本地目录不存在"
		}
	}

	gs.saveRepos()
	return nil
}

// saveRepos 保存仓库
func (gs *GitServer) saveRepos() error {
	reposFile := filepath.Join(gs.config.Runners.Git.ReposDir, "repos.json")
	data, err := json.MarshalIndent(gs.repos, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化仓库失败: %w", err)
	}

	if err := os.WriteFile(reposFile, data, 0644); err != nil {
		return fmt.Errorf("写入仓库文件失败: %w", err)
	}

	return nil
}

// ExecutionResult 执行结果
type ExecutionResult struct {
	Command    string    `json:"command"`
	Output     string    `json:"output"`
	ExitCode   int       `json:"exit_code"`
	Success    bool      `json:"success"`
	Error      error     `json:"-"`
	ErrorMsg   string    `json:"error_msg"`
	ExecutedAt time.Time `json:"executed_at"`
}
