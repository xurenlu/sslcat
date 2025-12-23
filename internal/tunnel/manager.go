package tunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

const (
	maxRestartAttempts = 5
)

type processTarget struct {
	providerID string
	tunnelID   string
}

// Manager 负责管理隧道运行状态，包含 CLI 进程的生命周期管理
type Manager struct {
	mu         sync.RWMutex
	providers  map[string]*ProviderState
	processes  map[string]map[string]*processHandle
	adapters   map[string]ProviderAdapter
	runtimeDir string
	logDir     string
	log        *logrus.Entry
}

// NewManager 创建一个新的隧道管理器
func NewManager(cfg config.TunnelManagerConfig, dataDir string, logger *logrus.Entry) *Manager {
	if dataDir == "" {
		dataDir = "./data"
	}

	baseLogger := logger
	if baseLogger == nil {
		baseLogger = logrus.WithField("component", "tunnel_manager")
	}

	runtimeDir := filepath.Join(dataDir, "tunnels", "runtime")
	logDir := filepath.Join(dataDir, "tunnels", "logs")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		baseLogger.WithError(err).Warn("创建隧道运行目录失败")
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		baseLogger.WithError(err).Warn("创建隧道日志目录失败")
	}

	mgr := &Manager{
		providers: make(map[string]*ProviderState),
		processes: make(map[string]map[string]*processHandle),
		adapters: map[string]ProviderAdapter{
			"frp":   newFRPAdapter(baseLogger),
			"ngrok": newNgrokAdapter(baseLogger),
		},
		runtimeDir: runtimeDir,
		logDir:     logDir,
		log:        baseLogger,
	}

	mgr.SyncFromConfig(cfg)
	return mgr
}

// Stop 停止隧道管理器，关闭所有隧道
func (m *Manager) Stop() {
	m.log.Info("正在停止隧道管理器...")
	
	// 停止所有隧道
	m.mu.RLock()
	var targets []processTarget
	for providerID, tunnels := range m.processes {
		for tunnelID := range tunnels {
			targets = append(targets, processTarget{providerID: providerID, tunnelID: tunnelID})
		}
	}
	m.mu.RUnlock()
	
	// 并发停止所有隧道
	var wg sync.WaitGroup
	for _, target := range targets {
		wg.Add(1)
		go func(providerID, tunnelID string) {
			defer wg.Done()
			if _, err := m.StopTunnel(providerID, tunnelID); err != nil && err != ErrNotRunning {
				m.log.WithError(err).Warnf("停止隧道失败: %s/%s", providerID, tunnelID)
			}
		}(target.providerID, target.tunnelID)
	}
	
	// 等待所有隧道停止，最多等待 15 秒
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		m.log.Info("所有隧道已停止")
	case <-time.After(15 * time.Second):
		m.log.Warn("停止隧道超时，强制退出")
	}
}

// SyncFromConfig 根据配置同步管理器状态
func (m *Manager) SyncFromConfig(cfg config.TunnelManagerConfig) {
	m.mu.Lock()

	previous := m.providers
	m.providers = make(map[string]*ProviderState)

	var toStart []processTarget
	var toStop []processTarget

	for _, providerCfg := range cfg.Providers {
		providerID := strings.TrimSpace(providerCfg.ID)
		if providerID == "" {
			continue
		}

		state := &ProviderState{
			Config:  providerCfg,
			Tunnels: make(map[string]*TunnelRuntime),
		}

		if prevState, ok := previous[providerID]; ok {
			for id, runtime := range prevState.Tunnels {
				state.Tunnels[id] = runtime
			}
		}

		for _, tunnelCfg := range providerCfg.Tunnels {
			tunnelID := strings.TrimSpace(tunnelCfg.ID)
			if tunnelID == "" {
				continue
			}

			runtime, ok := state.Tunnels[tunnelID]
			if !ok {
				runtime = &TunnelRuntime{
					ProviderID: providerID,
					TunnelID:   tunnelID,
					Status:     StatusDisconnected,
					UpdatedAt:  time.Now(),
				}
				state.Tunnels[tunnelID] = runtime
			}

			runtime.Config = tunnelCfg
			runtime.ProviderID = providerID
			runtime.TunnelID = tunnelID

			if !providerCfg.Enabled {
				if runtime.process != nil {
					toStop = append(toStop, processTarget{providerID: providerID, tunnelID: tunnelID})
				}
				runtime.Status = StatusDisconnected
			} else if runtime.process == nil && tunnelCfg.AutoStart {
				toStart = append(toStart, processTarget{providerID: providerID, tunnelID: tunnelID})
			}
		}

		for tunnelID, runtime := range state.Tunnels {
			if !tunnelExists(providerCfg.Tunnels, tunnelID) {
				if runtime.process != nil {
					toStop = append(toStop, processTarget{providerID: providerID, tunnelID: tunnelID})
				}
				delete(state.Tunnels, tunnelID)
			}
		}

		m.providers[providerID] = state
	}

	for providerID, tunnels := range m.processes {
		state, ok := m.providers[providerID]
		for tunnelID := range tunnels {
			if !ok || state == nil || !state.Config.Enabled || !tunnelExists(state.Config.Tunnels, tunnelID) {
				toStop = append(toStop, processTarget{providerID: providerID, tunnelID: tunnelID})
			}
		}
	}

	m.mu.Unlock()

	for _, target := range dedupeTargets(toStop) {
		if _, err := m.StopTunnel(target.providerID, target.tunnelID); err != nil && err != ErrNotRunning && err != ErrTunnelNotFound && err != ErrProviderNotFound {
			m.log.WithError(err).Warnf("同步配置时停止隧道失败: %s/%s", target.providerID, target.tunnelID)
		}
	}

	for _, target := range dedupeTargets(toStart) {
		go func(providerID, tunnelID string) {
			if _, err := m.startTunnel(providerID, tunnelID, false); err != nil {
				m.log.WithError(err).Warnf("自动启动隧道失败: %s/%s", providerID, tunnelID)
			}
		}(target.providerID, target.tunnelID)
	}
}

// ListProviders 返回所有提供商的运行状态摘要
func (m *Manager) ListProviders() []ProviderSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]ProviderSummary, 0, len(m.providers))

	for _, state := range m.providers {
		summary := ProviderSummary{
			ID:          state.Config.ID,
			Name:        state.Config.Name,
			Type:        state.Config.Type,
			Enabled:     state.Config.Enabled,
			Description: state.Config.Description,
			AutoStart:   state.Config.AutoStart,
			Options:     cloneStringMap(state.Config.Options),
		}

		credentials := make([]CredentialSummary, 0, len(state.Config.Credentials))
		for key, value := range state.Config.Credentials {
			credentials = append(credentials, CredentialSummary{Key: key, HasValue: strings.TrimSpace(value) != ""})
		}
		sort.Slice(credentials, func(i, j int) bool { return credentials[i].Key < credentials[j].Key })
		summary.Credentials = credentials

		tunnels := make([]TunnelWithStatus, 0, len(state.Config.Tunnels))
		for _, tunnelCfg := range state.Config.Tunnels {
			if runtime, ok := state.Tunnels[tunnelCfg.ID]; ok {
				tunnels = append(tunnels, runtime.Clone())
			} else {
				tunnels = append(tunnels, TunnelWithStatus{
					ProviderID:     state.Config.ID,
					ID:             tunnelCfg.ID,
					Name:           tunnelCfg.Name,
					Protocol:       tunnelCfg.Protocol,
					LocalAddress:   tunnelCfg.LocalAddress,
					LocalPort:      tunnelCfg.LocalPort,
					PublicHostname: tunnelCfg.PublicHostname,
					PublicPort:     tunnelCfg.PublicPort,
					EdgeRegion:     tunnelCfg.EdgeRegion,
					AutoStart:      tunnelCfg.AutoStart,
					Metadata:       cloneStringMap(tunnelCfg.Metadata),
					Parameters:     cloneStringMap(tunnelCfg.Parameters),
					Notes:          tunnelCfg.Notes,
					Status:         StatusDisconnected,
					UpdatedAt:      time.Time{},
				})
			}
		}
		summary.Tunnels = tunnels

		result = append(result, summary)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}

// GetTunnel 返回指定隧道的快照
func (m *Manager) GetTunnel(providerID, tunnelID string) (TunnelWithStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.providers[providerID]
	if !ok {
		return TunnelWithStatus{}, ErrProviderNotFound
	}

	runtime, ok := state.Tunnels[tunnelID]
	if !ok {
		return TunnelWithStatus{}, ErrTunnelNotFound
	}

	return runtime.Clone(), nil
}

// StartTunnel 启动一个隧道
func (m *Manager) StartTunnel(providerID, tunnelID string) (TunnelWithStatus, error) {
	return m.startTunnel(providerID, tunnelID, false)
}

func (m *Manager) startTunnel(providerID, tunnelID string, auto bool) (TunnelWithStatus, error) {
	m.mu.Lock()
	state, ok := m.providers[providerID]
	if !ok {
		m.mu.Unlock()
		return TunnelWithStatus{}, ErrProviderNotFound
	}
	if !state.Config.Enabled {
		m.mu.Unlock()
		return TunnelWithStatus{}, ErrProviderDisabled
	}
	runtime, ok := state.Tunnels[tunnelID]
	if !ok {
		m.mu.Unlock()
		return TunnelWithStatus{}, ErrTunnelNotFound
	}
	if runtime.process != nil {
		snapshot := runtime.Clone()
		m.mu.Unlock()
		return snapshot, ErrAlreadyRunning
	}

	adapter, ok := m.adapters[state.Config.Type]
	if !ok {
		m.mu.Unlock()
		return TunnelWithStatus{}, fmt.Errorf("不支持的隧道服务类型: %s", state.Config.Type)
	}

	providerCfg := state.Config
	tunnelCfg := runtime.Config
	logPath := m.buildLogPath(providerID, tunnelID)

	runtime.Status = StatusConnecting
	runtime.LastError = ""
	runtime.ProcessID = ""
	runtime.PID = 0
	runtime.LogPath = logPath
	runtime.UpdatedAt = time.Now()
	if !auto {
		runtime.RestartCount = 0
	}
	m.mu.Unlock()

	runtimeDir := m.buildRuntimeDir(providerID, tunnelID)
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		errWrapped := fmt.Errorf("创建运行目录失败: %w", err)
		m.setTunnelError(providerID, tunnelID, errWrapped.Error())
		return TunnelWithStatus{}, errWrapped
	}

	spec, err := adapter.Prepare(providerCfg, tunnelCfg, runtimeDir)
	if err != nil {
		m.setTunnelError(providerID, tunnelID, err.Error())
		return TunnelWithStatus{}, err
	}
	if spec == nil || strings.TrimSpace(spec.Executable) == "" {
		err := fmt.Errorf("隧道命令配置无效")
		m.setTunnelError(providerID, tunnelID, err.Error())
		return TunnelWithStatus{}, err
	}

	if _, err := exec.LookPath(spec.Executable); err != nil {
		errMsg := fmt.Sprintf("CLI 工具 %s 不存在", spec.Executable)
		m.setTunnelError(providerID, tunnelID, errMsg)
		return TunnelWithStatus{}, ErrCLIUnavailable
	}

	logFile, err := m.openLogFile(logPath)
	if err != nil {
		errWrapped := fmt.Errorf("打开日志文件失败: %w", err)
		m.setTunnelError(providerID, tunnelID, errWrapped.Error())
		return TunnelWithStatus{}, errWrapped
	}

	fmt.Fprintf(logFile, "==== [%s] 启动隧道 %s (%s) ====\n", time.Now().Format(time.RFC3339), tunnelCfg.Name, tunnelID)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, spec.Executable, spec.Args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), spec.Env...)
	if strings.TrimSpace(spec.WorkDir) != "" {
		cmd.Dir = spec.WorkDir
	} else {
		cmd.Dir = runtimeDir
	}

	if err := cmd.Start(); err != nil {
		cancel()
		_ = logFile.Close()
		if errors.Is(err, exec.ErrNotFound) {
			err = ErrCLIUnavailable
		}
		m.setTunnelError(providerID, tunnelID, fmt.Sprintf("启动进程失败: %v", err))
		return TunnelWithStatus{}, err
	}

	handle := &processHandle{
		manager:    m,
		providerID: providerID,
		tunnelID:   tunnelID,
		cmd:        cmd,
		cancel:     cancel,
		logFile:    logFile,
		logPath:    logPath,
		processID:  GenerateProcessID(providerID, tunnelID),
		done:       make(chan struct{}),
	}

	m.mu.Lock()
	state = m.providers[providerID]
	runtime = nil
	if state != nil {
		runtime = state.Tunnels[tunnelID]
	}
	if runtime != nil {
		runtime.Status = StatusConnected
		runtime.LastError = ""
		runtime.UpdatedAt = time.Now()
		runtime.LastStartedAt = runtime.UpdatedAt
		runtime.ProcessID = handle.processID
		runtime.PID = cmd.Process.Pid
		runtime.LastStoppedAt = time.Time{}
		runtime.process = handle
	}
	if _, ok := m.processes[providerID]; !ok {
		m.processes[providerID] = make(map[string]*processHandle)
	}
	m.processes[providerID][tunnelID] = handle
	var snapshot TunnelWithStatus
	if runtime != nil {
		snapshot = runtime.Clone()
	}
	m.mu.Unlock()

	m.log.WithFields(logrus.Fields{
		"provider": providerID,
		"tunnel":   tunnelID,
		"pid":      cmd.Process.Pid,
	}).Info("隧道已启动")

	go handle.wait()

	return snapshot, nil
}

// StopTunnel 停止一个隧道
func (m *Manager) StopTunnel(providerID, tunnelID string) (TunnelWithStatus, error) {
	handle := m.getProcessHandle(providerID, tunnelID)
	if handle == nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		runtime := m.getRuntimeLocked(providerID, tunnelID)
		if runtime != nil {
			runtime.Status = StatusDisconnected
			runtime.LastError = ""
			runtime.UpdatedAt = time.Now()
			return runtime.Clone(), ErrNotRunning
		}
		return TunnelWithStatus{}, ErrNotRunning
	}

	handle.markStopRequested()
	m.log.WithFields(logrus.Fields{
		"provider": providerID,
		"tunnel":   tunnelID,
	}).Info("正在停止隧道")
	handle.stop()

	m.mu.Lock()
	defer m.mu.Unlock()
	runtime := m.getRuntimeLocked(providerID, tunnelID)
	if runtime != nil {
		return runtime.Clone(), nil
	}
	return TunnelWithStatus{
		ProviderID: providerID,
		ID:         tunnelID,
		Status:     StatusDisconnected,
		LogPath:    handle.logPath,
	}, nil
}

// MarkTunnelError 将隧道标记为错误状态
func (m *Manager) MarkTunnelError(providerID, tunnelID, errMsg string) (TunnelWithStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	runtime := m.getRuntimeLocked(providerID, tunnelID)
	if runtime == nil {
		return TunnelWithStatus{}, ErrTunnelNotFound
	}

	runtime.Status = StatusError
	runtime.LastError = errMsg
	runtime.UpdatedAt = time.Now()

	return runtime.Clone(), nil
}

func (m *Manager) onProcessExit(handle *processHandle, exitErr error) {
	m.mu.Lock()
	state := m.providers[handle.providerID]
	runtime := m.getRuntimeLocked(handle.providerID, handle.tunnelID)
	if runtime != nil && runtime.process == handle {
		runtime.process = nil
		runtime.PID = 0
		runtime.ProcessID = ""
		runtime.LastStoppedAt = time.Now()
		runtime.UpdatedAt = runtime.LastStoppedAt
		runtime.LogPath = handle.logPath
	}
	if tunnels, ok := m.processes[handle.providerID]; ok {
		if current, ok := tunnels[handle.tunnelID]; ok && current == handle {
			delete(tunnels, handle.tunnelID)
			if len(tunnels) == 0 {
				delete(m.processes, handle.providerID)
			}
		}
	}

	stopRequested := handle.isStopRequested()
	shouldRestart := false
	delay := time.Duration(0)

	if runtime != nil {
		if stopRequested {
			runtime.Status = StatusDisconnected
			runtime.LastError = ""
		} else if exitErr != nil {
			runtime.Status = StatusError
			runtime.LastError = exitErr.Error()
			runtime.RestartCount++
			if runtime.RestartCount <= maxRestartAttempts && state != nil && state.Config.Enabled {
				runtime.Status = StatusConnecting
				runtime.LastError = ""
				shouldRestart = true
				delay = computeBackoff(runtime.RestartCount)
			}
		} else {
			runtime.Status = StatusDisconnected
			runtime.LastError = ""
		}
	}

	m.mu.Unlock()

	fields := logrus.Fields{
		"provider": handle.providerID,
		"tunnel":   handle.tunnelID,
	}

	if stopRequested {
		m.log.WithFields(fields).Info("隧道进程已停止")
		return
	}

	if exitErr != nil {
		m.log.WithFields(fields).WithError(exitErr).Warn("隧道进程异常退出")
	} else {
		m.log.WithFields(fields).Info("隧道进程退出")
	}

	if shouldRestart {
		m.log.WithFields(fields).Warnf("将在 %s 后自动重启隧道", delay)
		time.AfterFunc(delay, func() {
			if _, err := m.startTunnel(handle.providerID, handle.tunnelID, true); err != nil {
				m.log.WithFields(fields).WithError(err).Error("自动重启隧道失败")
			}
		})
	}
}

func (m *Manager) setTunnelError(providerID, tunnelID, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if runtime := m.getRuntimeLocked(providerID, tunnelID); runtime != nil {
		runtime.Status = StatusError
		runtime.LastError = message
		runtime.UpdatedAt = time.Now()
	}
}

func (m *Manager) getRuntimeLocked(providerID, tunnelID string) *TunnelRuntime {
	state, ok := m.providers[providerID]
	if !ok {
		return nil
	}
	return state.Tunnels[tunnelID]
}

func (m *Manager) getProcessHandle(providerID, tunnelID string) *processHandle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if tunnels, ok := m.processes[providerID]; ok {
		return tunnels[tunnelID]
	}
	return nil
}

func (m *Manager) buildRuntimeDir(providerID, tunnelID string) string {
	return filepath.Join(m.runtimeDir, providerID, tunnelID)
}

func (m *Manager) buildLogPath(providerID, tunnelID string) string {
	return filepath.Join(m.logDir, providerID, fmt.Sprintf("%s.log", tunnelID))
}

func (m *Manager) openLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
}

func tunnelExists(tunnels []config.TunnelDefinition, tunnelID string) bool {
	for _, t := range tunnels {
		if t.ID == tunnelID {
			return true
		}
	}
	return false
}

func computeBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 6 {
		attempt = 6
	}
	delay := time.Duration(1<<uint(attempt-1)) * time.Second
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	return delay
}

func dedupeTargets(targets []processTarget) []processTarget {
	if len(targets) == 0 {
		return targets
	}
	seen := make(map[string]struct{}, len(targets))
	result := make([]processTarget, 0, len(targets))
	for _, t := range targets {
		key := t.providerID + "::" + t.tunnelID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, t)
	}
	return result
}
