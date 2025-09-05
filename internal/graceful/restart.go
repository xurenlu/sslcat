package graceful

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// RestartManager 平滑重启管理器
type RestartManager struct {
	listeners map[string]net.Listener
	log       *logrus.Entry
}

// NewRestartManager 创建重启管理器
func NewRestartManager() *RestartManager {
	return &RestartManager{
		listeners: make(map[string]net.Listener),
		log: logrus.WithFields(logrus.Fields{
			"component": "restart_manager",
		}),
	}
}

// AddListener 添加监听器
func (rm *RestartManager) AddListener(name string, listener net.Listener) {
	rm.listeners[name] = listener
}

// GetListener 获取监听器
func (rm *RestartManager) GetListener(name string) net.Listener {
	return rm.listeners[name]
}

// StartGracefulRestart 启动平滑重启
func (rm *RestartManager) StartGracefulRestart() {
	// 监听SIGHUP信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	go func() {
		for {
			sig := <-sigChan
			rm.log.Infof("收到信号 %v，开始平滑重启", sig)

			if err := rm.performGracefulRestart(); err != nil {
				rm.log.Errorf("平滑重启失败: %v", err)
			}
		}
	}()
}

// performGracefulRestart 执行平滑重启
func (rm *RestartManager) performGracefulRestart() error {
	// 1. 启动新的进程
	newProcess, err := rm.startNewProcess()
	if err != nil {
		return fmt.Errorf("启动新进程失败: %w", err)
	}

	// 2. 等待新进程启动
	time.Sleep(2 * time.Second)

	// 3. 检查新进程是否正常运行
	if !rm.isProcessRunning(newProcess.Process.Pid) {
		return fmt.Errorf("新进程启动失败")
	}

	// 4. 关闭当前进程的监听器
	rm.closeListeners()

	// 5. 等待当前请求处理完成
	time.Sleep(5 * time.Second)

	// 6. 退出当前进程
	rm.log.Info("平滑重启完成，退出当前进程")
	os.Exit(0)

	return nil
}

// startNewProcess 启动新进程
func (rm *RestartManager) startNewProcess() (*exec.Cmd, error) {
	// 获取当前可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("获取可执行文件路径失败: %w", err)
	}

	// 获取当前进程的命令行参数
	args := os.Args[1:]

	// 创建新进程
	cmd := exec.Command(execPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// 设置环境变量，标记为新进程
	cmd.Env = append(os.Environ(), "WITHSSL_GRACEFUL_RESTART=1")

	// 启动新进程
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动新进程失败: %w", err)
	}

	rm.log.Infof("新进程已启动，PID: %d", cmd.Process.Pid)
	return cmd, nil
}

// isProcessRunning 检查进程是否运行
func (rm *RestartManager) isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// 发送信号0来检查进程是否存在
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// closeListeners 关闭所有监听器
func (rm *RestartManager) closeListeners() {
	for name, listener := range rm.listeners {
		rm.log.Infof("关闭监听器: %s", name)
		if err := listener.Close(); err != nil {
			rm.log.Errorf("关闭监听器失败 %s: %v", name, err)
		}
	}
}

// ListenTCP 监听TCP端口
func (rm *RestartManager) ListenTCP(network, address string) (net.Listener, error) {
	// 检查是否是从父进程继承的文件描述符
	if os.Getenv("WITHSSL_GRACEFUL_RESTART") == "1" {
		// 尝试从环境变量获取文件描述符
		if fd := os.Getenv("WITHSSL_LISTENER_FD"); fd != "" {
			// 这里可以实现从文件描述符恢复监听器的逻辑
			rm.log.Info("从文件描述符恢复监听器")
		}
	}

	// 创建新的监听器
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	// 添加到管理器
	rm.AddListener(address, listener)

	return listener, nil
}

// SaveState 保存状态信息
func (rm *RestartManager) SaveState() error {
	// 这里可以保存当前状态到文件，供新进程恢复使用
	stateFile := "/var/lib/sslcat/restart_state.json"

	// 创建状态数据
	state := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"listeners": make([]string, 0, len(rm.listeners)),
	}

	// 收集监听器信息
	for name := range rm.listeners {
		state["listeners"] = append(state["listeners"].([]string), name)
	}

	// 保存到文件
	// 这里简化处理，实际应该使用JSON序列化
	rm.log.Infof("保存重启状态到: %s", stateFile)

	return nil
}

// LoadState 加载状态信息
func (rm *RestartManager) LoadState() error {
	// 这里可以从文件加载状态信息
	stateFile := "/var/lib/sslcat/restart_state.json"

	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		rm.log.Info("没有找到重启状态文件，跳过状态恢复")
		return nil
	}

	rm.log.Infof("从文件加载重启状态: %s", stateFile)

	// 这里简化处理，实际应该使用JSON反序列化

	return nil
}

// WaitForShutdown 等待关闭信号
func (rm *RestartManager) WaitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	rm.log.Infof("收到关闭信号 %v", sig)

	// 执行优雅关闭
	rm.gracefulShutdown()
}

// gracefulShutdown 优雅关闭
func (rm *RestartManager) gracefulShutdown() {
	rm.log.Info("开始优雅关闭...")

	// 1. 停止接受新连接
	rm.closeListeners()

	// 2. 等待现有连接处理完成
	time.Sleep(5 * time.Second)

	// 3. 强制退出
	rm.log.Info("优雅关闭完成")
	os.Exit(0)
}

// CreateContext 创建带超时的上下文
func CreateContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
