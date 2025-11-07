package tunnel

import (
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// Status 表示隧道运行状态
type Status string

const (
	StatusUnknown      Status = "unknown"
	StatusDisconnected Status = "disconnected"
	StatusConnecting   Status = "connecting"
	StatusConnected    Status = "connected"
	StatusError        Status = "error"
)

// ProviderState 保存单个提供商的运行时状态
type ProviderState struct {
	Config  config.TunnelProviderConfig
	Tunnels map[string]*TunnelRuntime
}

// TunnelRuntime 保存隧道的实时状态
type TunnelRuntime struct {
	ProviderID string
	TunnelID   string
	Config     config.TunnelDefinition
	Status     Status
	LastError  string
	UpdatedAt  time.Time
}

// Clone 生成隧道运行状态的快照
func (r *TunnelRuntime) Clone() TunnelWithStatus {
	if r == nil {
		return TunnelWithStatus{}
	}

	return TunnelWithStatus{
		ProviderID:     r.ProviderID,
		ID:             r.TunnelID,
		Name:           r.Config.Name,
		Protocol:       r.Config.Protocol,
		LocalAddress:   r.Config.LocalAddress,
		LocalPort:      r.Config.LocalPort,
		PublicHostname: r.Config.PublicHostname,
		PublicPort:     r.Config.PublicPort,
		EdgeRegion:     r.Config.EdgeRegion,
		AutoStart:      r.Config.AutoStart,
		Metadata:       cloneStringMap(r.Config.Metadata),
		Parameters:     cloneStringMap(r.Config.Parameters),
		Notes:          r.Config.Notes,
		Status:         r.Status,
		LastError:      r.LastError,
		UpdatedAt:      r.UpdatedAt,
	}
}

// ProviderSummary 供 API 使用的提供商汇总信息
type ProviderSummary struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Type        string              `json:"type"`
	Enabled     bool                `json:"enabled"`
	Description string              `json:"description,omitempty"`
	AutoStart   bool                `json:"auto_start"`
	Options     map[string]string   `json:"options,omitempty"`
	Credentials []CredentialSummary `json:"credentials"`
	Tunnels     []TunnelWithStatus  `json:"tunnels"`
}

// CredentialSummary 用于在 API 中返回的凭据概要信息
type CredentialSummary struct {
	Key      string `json:"key"`
	HasValue bool   `json:"has_value"`
}

// TunnelWithStatus 包含隧道配置与运行状态
type TunnelWithStatus struct {
	ProviderID     string            `json:"provider_id"`
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	LocalAddress   string            `json:"local_address"`
	LocalPort      int               `json:"local_port"`
	PublicHostname string            `json:"public_hostname,omitempty"`
	PublicPort     int               `json:"public_port,omitempty"`
	EdgeRegion     string            `json:"edge_region,omitempty"`
	AutoStart      bool              `json:"auto_start"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Parameters     map[string]string `json:"parameters,omitempty"`
	Notes          string            `json:"notes,omitempty"`
	Status         Status            `json:"status"`
	LastError      string            `json:"last_error,omitempty"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

func cloneStringMap(v map[string]string) map[string]string {
	if len(v) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(v))
	for k, val := range v {
		cloned[k] = val
	}
	return cloned
}
