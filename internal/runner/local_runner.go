package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// LocalRunner Local Runner 管理器
type LocalRunner struct {
	config *config.Config
	tasks  map[string]*config.LocalRunnerTask
	mutex  sync.RWMutex
	logger *logrus.Logger
}

// NewLocalRunner 创建新的 Local Runner
func NewLocalRunner(cfg *config.Config) *LocalRunner {
	return &LocalRunner{
		config: cfg,
		tasks:  make(map[string]*config.LocalRunnerTask),
		logger: logrus.WithField("component", "local_runner").Logger,
	}
}

// Start 启动 Local Runner
func (lr *LocalRunner) Start() error {
	if !lr.config.Runners.Local.Enabled {
		lr.logger.Info("Local Runner 未启用")
		return nil
	}

	// 创建工作目录
	if err := os.MkdirAll(lr.config.Runners.Local.WorkDir, 0755); err != nil {
		return fmt.Errorf("创建 Local Runner 工作目录失败: %w", err)
	}

	// 加载现有任务
	if err := lr.loadTasks(); err != nil {
		lr.logger.Warnf("加载任务失败: %v", err)
	}

	lr.logger.Info("Local Runner 已启动")
	return nil
}

// Stop 停止 Local Runner
func (lr *LocalRunner) Stop() {
	lr.mutex.Lock()
	defer lr.mutex.Unlock()

	// 停止所有运行中的任务
	for _, task := range lr.tasks {
		if task.Status == "running" && task.PID > 0 {
			lr.stopTask(task)
		}
	}

	lr.logger.Info("Local Runner 已停止")
}

// AddTask 添加新任务
func (lr *LocalRunner) AddTask(task *config.LocalRunnerTask) error {
	lr.mutex.Lock()
	defer lr.mutex.Unlock()

	// 生成任务ID
	if task.ID == "" {
		task.ID = fmt.Sprintf("task_%d", time.Now().UnixNano())
	}

	// 设置默认值
	if task.Status == "" {
		task.Status = "stopped"
	}
	if task.Env == nil {
		task.Env = make(map[string]string)
	}

	// 添加 PORT 环境变量
	if task.Port > 0 {
		task.Env["PORT"] = strconv.Itoa(task.Port)
	}

	lr.tasks[task.ID] = task

	// 保存任务
	if err := lr.saveTasks(); err != nil {
		return fmt.Errorf("保存任务失败: %w", err)
	}

	lr.logger.Infof("任务 %s 已添加", task.ID)
	return nil
}

// StartTask 启动任务
func (lr *LocalRunner) StartTask(taskID string) error {
	lr.mutex.Lock()
	defer lr.mutex.Unlock()

	task, exists := lr.tasks[taskID]
	if !exists {
		return fmt.Errorf("任务 %s 不存在", taskID)
	}

	if task.Status == "running" {
		return fmt.Errorf("任务 %s 已在运行中", taskID)
	}

	// 检查并发限制
	runningCount := 0
	for _, t := range lr.tasks {
		if t.Status == "running" {
			runningCount++
		}
	}
	if runningCount >= lr.config.Runners.Local.MaxConcurrent {
		return fmt.Errorf("已达到最大并发运行数限制 (%d)", lr.config.Runners.Local.MaxConcurrent)
	}

	// 启动任务
	if err := lr.startTask(task); err != nil {
		task.Status = "error"
		task.ErrorMsg = err.Error()
		lr.saveTasks()
		return err
	}

	lr.logger.Infof("任务 %s 已启动", taskID)
	return nil
}

// StopTask 停止任务
func (lr *LocalRunner) StopTask(taskID string) error {
	lr.mutex.Lock()
	defer lr.mutex.Unlock()

	task, exists := lr.tasks[taskID]
	if !exists {
		return fmt.Errorf("任务 %s 不存在", taskID)
	}

	if task.Status != "running" {
		return fmt.Errorf("任务 %s 未在运行中", taskID)
	}

	lr.stopTask(task)
	lr.logger.Infof("任务 %s 已停止", taskID)
	return nil
}

// RemoveTask 删除任务
func (lr *LocalRunner) RemoveTask(taskID string) error {
	lr.mutex.Lock()
	defer lr.mutex.Unlock()

	task, exists := lr.tasks[taskID]
	if !exists {
		return fmt.Errorf("任务 %s 不存在", taskID)
	}

	// 如果任务正在运行，先停止
	if task.Status == "running" {
		lr.stopTask(task)
	}

	delete(lr.tasks, taskID)

	// 保存任务
	if err := lr.saveTasks(); err != nil {
		return fmt.Errorf("保存任务失败: %w", err)
	}

	lr.logger.Infof("任务 %s 已删除", taskID)
	return nil
}

// GetTask 获取任务信息
func (lr *LocalRunner) GetTask(taskID string) (*config.LocalRunnerTask, error) {
	lr.mutex.RLock()
	defer lr.mutex.RUnlock()

	task, exists := lr.tasks[taskID]
	if !exists {
		return nil, fmt.Errorf("任务 %s 不存在", taskID)
	}

	// 返回任务副本
	taskCopy := *task
	return &taskCopy, nil
}

// ListTasks 列出所有任务
func (lr *LocalRunner) ListTasks() []*config.LocalRunnerTask {
	lr.mutex.RLock()
	defer lr.mutex.RUnlock()

	tasks := make([]*config.LocalRunnerTask, 0, len(lr.tasks))
	for _, task := range lr.tasks {
		taskCopy := *task
		tasks = append(tasks, &taskCopy)
	}

	return tasks
}

// startTask 启动单个任务
func (lr *LocalRunner) startTask(task *config.LocalRunnerTask) error {
	// 检查二进制文件是否存在
	if _, err := os.Stat(task.BinaryPath); os.IsNotExist(err) {
		return fmt.Errorf("二进制文件不存在: %s", task.BinaryPath)
	}

	// 准备命令
	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(lr.config.Runners.Local.Timeout)*time.Second)
	defer cancel()

	if task.Type == "golang" {
		// Golang 二进制程序
		cmd = exec.CommandContext(ctx, task.BinaryPath, task.Args...)
	} else if task.Type == "springboot" {
		// Spring Boot JAR 包
		args := []string{"-jar", task.BinaryPath}

		// 添加 active profile 参数
		if task.ActiveProfile != "" {
			args = append(args, "--spring.profiles.active="+task.ActiveProfile)
		}

		// 添加其他参数
		args = append(args, task.Args...)

		cmd = exec.CommandContext(ctx, "java", args...)
	} else {
		return fmt.Errorf("不支持的任务类型: %s", task.Type)
	}

	// 设置环境变量
	cmd.Env = os.Environ()
	for key, value := range task.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// 设置工作目录
	cmd.Dir = filepath.Dir(task.BinaryPath)

	// 创建日志文件
	logFile := filepath.Join(lr.config.Runners.Local.WorkDir, fmt.Sprintf("%s.log", task.ID))
	file, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("创建日志文件失败: %w", err)
	}

	// 设置输出
	cmd.Stdout = io.MultiWriter(os.Stdout, file)
	cmd.Stderr = io.MultiWriter(os.Stderr, file)

	// 启动进程
	if err := cmd.Start(); err != nil {
		file.Close()
		return fmt.Errorf("启动进程失败: %w", err)
	}

	// 更新任务状态
	task.Status = "running"
	task.PID = cmd.Process.Pid
	task.StartTime = time.Now().Unix()
	task.ErrorMsg = ""

	// 保存任务状态
	lr.saveTasks()

	// 在 goroutine 中等待进程结束
	go func() {
		err := cmd.Wait()
		file.Close()

		lr.mutex.Lock()
		defer lr.mutex.Unlock()

		if err != nil {
			task.Status = "error"
			task.ErrorMsg = err.Error()
		} else {
			task.Status = "stopped"
		}
		task.PID = 0
		lr.saveTasks()

		lr.logger.Infof("任务 %s 进程已结束", task.ID)
	}()

	return nil
}

// stopTask 停止单个任务
func (lr *LocalRunner) stopTask(task *config.LocalRunnerTask) {
	if task.PID > 0 {
		// 发送 SIGTERM 信号
		process, err := os.FindProcess(task.PID)
		if err == nil {
			process.Signal(syscall.SIGTERM)

			// 等待进程结束
			time.Sleep(2 * time.Second)

			// 如果进程还在运行，发送 SIGKILL
			if process.Signal(syscall.Signal(0)) == nil {
				process.Signal(syscall.SIGKILL)
			}
		}
	}

	task.Status = "stopped"
	task.PID = 0
	lr.saveTasks()
}

// loadTasks 加载任务
func (lr *LocalRunner) loadTasks() error {
	tasksFile := filepath.Join(lr.config.Runners.Local.WorkDir, "tasks.json")
	if _, err := os.Stat(tasksFile); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(tasksFile)
	if err != nil {
		return fmt.Errorf("读取任务文件失败: %w", err)
	}

	var tasks map[string]*config.LocalRunnerTask
	if err := json.Unmarshal(data, &tasks); err != nil {
		return fmt.Errorf("解析任务文件失败: %w", err)
	}

	lr.tasks = tasks

	// 检查运行中的任务是否还在运行
	for _, task := range lr.tasks {
		if task.Status == "running" && task.PID > 0 {
			process, err := os.FindProcess(task.PID)
			if err != nil || process.Signal(syscall.Signal(0)) != nil {
				// 进程不存在，更新状态
				task.Status = "stopped"
				task.PID = 0
			}
		}
	}

	lr.saveTasks()
	return nil
}

// saveTasks 保存任务
func (lr *LocalRunner) saveTasks() error {
	tasksFile := filepath.Join(lr.config.Runners.Local.WorkDir, "tasks.json")
	data, err := json.MarshalIndent(lr.tasks, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化任务失败: %w", err)
	}

	if err := os.WriteFile(tasksFile, data, 0644); err != nil {
		return fmt.Errorf("写入任务文件失败: %w", err)
	}

	return nil
}
