package tunnel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type processHandle struct {
	manager       *Manager
	providerID    string
	tunnelID      string
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	logFile       *os.File
	logPath       string
	processID     string
	done          chan struct{}
	mu            sync.Mutex
	stopRequested bool
}

func (h *processHandle) appendLog(line string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.logFile == nil {
		return
	}
	fmt.Fprintf(h.logFile, "==== [%s] %s\n", time.Now().Format(time.RFC3339), line)
	_ = h.logFile.Sync()
}

func (h *processHandle) markStopRequested() {
	h.mu.Lock()
	h.stopRequested = true
	h.mu.Unlock()
}

func (h *processHandle) isStopRequested() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stopRequested
}

func (h *processHandle) stop() {
	h.mu.Lock()
	cmd := h.cmd
	cancel := h.cancel
	done := h.done
	logFile := h.logFile
	if !h.stopRequested {
		h.stopRequested = true
	}
	h.mu.Unlock()

	if cmd == nil || done == nil {
		return
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "==== [%s] 收到停止命令，正在发送 SIGTERM\n", time.Now().Format(time.RFC3339))
		_ = logFile.Sync()
	}

	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}

	select {
	case <-done:
		if cancel != nil {
			cancel()
		}
		return
	case <-time.After(8 * time.Second):
	}

	if logFile != nil {
		fmt.Fprintf(logFile, "==== [%s] SIGTERM 超时，执行强制终止\n", time.Now().Format(time.RFC3339))
		_ = logFile.Sync()
	}

	if cancel != nil {
		cancel()
	}

	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}

	<-done
}

func (h *processHandle) wait() {
	err := h.cmd.Wait()

	h.mu.Lock()
	logFile := h.logFile
	h.logFile = nil
	h.mu.Unlock()

	if logFile != nil {
		if err != nil {
			fmt.Fprintf(logFile, "==== [%s] 进程退出，错误: %v\n", time.Now().Format(time.RFC3339), err)
		} else {
			fmt.Fprintf(logFile, "==== [%s] 进程正常退出\n", time.Now().Format(time.RFC3339))
		}
		_ = logFile.Sync()
		_ = logFile.Close()
	}

	if h.isStopRequested() {
		err = nil
	}

	h.manager.onProcessExit(h, err)
	close(h.done)
}
