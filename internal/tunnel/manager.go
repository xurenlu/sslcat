package tunnel

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// Manager 负责管理隧道运行状态，当前实现以轻量级内存状态为主
type Manager struct {
	mu        sync.RWMutex
	providers map[string]*ProviderState
}

// NewManager 创建一个新的隧道管理器
func NewManager(cfg config.TunnelManagerConfig) *Manager {
	mgr := &Manager{
		providers: make(map[string]*ProviderState),
	}
	mgr.SyncFromConfig(cfg)
	return mgr
}

// SyncFromConfig 根据配置同步管理器状态
func (m *Manager) SyncFromConfig(cfg config.TunnelManagerConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	previous := m.providers
	m.providers = make(map[string]*ProviderState)

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

			if !state.Config.Enabled {
				runtime.Status = StatusDisconnected
			}
		}

		for tunnelID := range state.Tunnels {
			if !tunnelExists(providerCfg.Tunnels, tunnelID) {
				delete(state.Tunnels, tunnelID)
			}
		}

		m.providers[providerID] = state
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

// StartTunnel 将隧道标记为已连接（占位实现）
func (m *Manager) StartTunnel(providerID, tunnelID string) (TunnelWithStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.providers[providerID]
	if !ok {
		return TunnelWithStatus{}, ErrProviderNotFound
	}
	runtime, ok := state.Tunnels[tunnelID]
	if !ok {
		return TunnelWithStatus{}, ErrTunnelNotFound
	}

	// 占位：未来版本将调用真实的 provider 适配器
	runtime.Status = StatusConnected
	runtime.LastError = ""
	runtime.UpdatedAt = time.Now()

	return runtime.Clone(), nil
}

// StopTunnel 将隧道标记为已断开
func (m *Manager) StopTunnel(providerID, tunnelID string) (TunnelWithStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.providers[providerID]
	if !ok {
		return TunnelWithStatus{}, ErrProviderNotFound
	}
	runtime, ok := state.Tunnels[tunnelID]
	if !ok {
		return TunnelWithStatus{}, ErrTunnelNotFound
	}

	runtime.Status = StatusDisconnected
	runtime.UpdatedAt = time.Now()

	return runtime.Clone(), nil
}

// MarkTunnelError 将隧道标记为错误状态
func (m *Manager) MarkTunnelError(providerID, tunnelID, errMsg string) (TunnelWithStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.providers[providerID]
	if !ok {
		return TunnelWithStatus{}, ErrProviderNotFound
	}
	runtime, ok := state.Tunnels[tunnelID]
	if !ok {
		return TunnelWithStatus{}, ErrTunnelNotFound
	}

	runtime.Status = StatusError
	runtime.LastError = errMsg
	runtime.UpdatedAt = time.Now()

	return runtime.Clone(), nil
}

func tunnelExists(tunnels []config.TunnelDefinition, tunnelID string) bool {
	for _, t := range tunnels {
		if t.ID == tunnelID {
			return true
		}
	}
	return false
}
