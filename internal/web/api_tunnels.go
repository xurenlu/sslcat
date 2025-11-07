package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/tunnel"
)

const preserveCredentialValue = "__PRESERVE__"

var supportedTunnelProviders = []string{"cloudflare", "ngrok", "frp", "phddns"}
var supportedTunnelProtocols = []string{"http", "https", "tcp", "udp"}

// handleAPITunnelProviders 返回所有隧道提供商的概要信息
func (s *Server) handleAPITunnelProviders(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providers := s.tunnelManager.ListProviders()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":             true,
		"providers":           providers,
		"supported_providers": supportedTunnelProviders,
		"supported_protocols": supportedTunnelProtocols,
	})
}

type tunnelDefinitionRequest struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	LocalAddress   string            `json:"local_address"`
	LocalPort      int               `json:"local_port"`
	PublicHostname string            `json:"public_hostname"`
	PublicPort     int               `json:"public_port"`
	EdgeRegion     string            `json:"edge_region"`
	AutoStart      bool              `json:"auto_start"`
	Metadata       map[string]string `json:"metadata"`
	Parameters     map[string]string `json:"parameters"`
	Notes          string            `json:"notes"`
}

type tunnelProviderRequest struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Type        string                    `json:"type"`
	Enabled     bool                      `json:"enabled"`
	Description string                    `json:"description"`
	AutoStart   bool                      `json:"auto_start"`
	Credentials map[string]string         `json:"credentials"`
	Options     map[string]string         `json:"options"`
	Tunnels     []tunnelDefinitionRequest `json:"tunnels"`
}

// handleAPITunnelProvidersSave 新增或更新提供商
func (s *Server) handleAPITunnelProvidersSave(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req tunnelProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		s.writeJSONError(w, http.StatusBadRequest, "provider name is required")
		return
	}

	providerType := strings.ToLower(strings.TrimSpace(req.Type))
	if !config.IsSupportedTunnelProvider(providerType) {
		s.writeJSONError(w, http.StatusBadRequest, "unsupported provider type")
		return
	}

	providerIndex := -1
	for i, provider := range s.config.Tunnels.Providers {
		if provider.ID != "" && provider.ID == req.ID {
			providerIndex = i
			break
		}
	}

	var baseProvider config.TunnelProviderConfig
	if providerIndex >= 0 {
		baseProvider = s.config.Tunnels.Providers[providerIndex]
	}

	providerID := strings.TrimSpace(req.ID)
	if providerID == "" {
		if baseProvider.ID != "" {
			providerID = baseProvider.ID
		} else {
			providerID = tunnel.GenerateProviderID(providerType)
		}
	}

	updated := config.TunnelProviderConfig{
		ID:          providerID,
		Name:        strings.TrimSpace(req.Name),
		Type:        providerType,
		Enabled:     req.Enabled,
		Description: strings.TrimSpace(req.Description),
		AutoStart:   req.AutoStart,
	}

	updated.Options = sanitizeStringMap(req.Options)
	updated.Credentials = make(map[string]string)

	if baseProvider.Credentials != nil {
		for k, v := range baseProvider.Credentials {
			updated.Credentials[k] = v
		}
	}

	for key, value := range req.Credentials {
		if value == preserveCredentialValue {
			continue
		}
		updated.Credentials[key] = value
	}

	updated.Tunnels = make([]config.TunnelDefinition, 0, len(req.Tunnels))
	for idx, tunnelReq := range req.Tunnels {
		def, err := buildTunnelDefinition(providerID, tunnelReq)
		if err != nil {
			s.writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		updated.Tunnels = append(updated.Tunnels, def)

		// 简单校验索引
		if updated.Tunnels[idx].Name == "" {
			updated.Tunnels[idx].Name = def.Name
		}
	}

	if providerIndex >= 0 {
		s.config.Tunnels.Providers[providerIndex] = updated
	} else {
		s.config.Tunnels.Providers = append(s.config.Tunnels.Providers, updated)
	}

	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("Failed to save tunnel provider config: %v", err)
		s.writeJSONError(w, http.StatusInternalServerError, "failed to save configuration")
		return
	}

	s.tunnelManager.SyncFromConfig(s.config.Tunnels)

	providers := s.tunnelManager.ListProviders()
	var saved tunnel.ProviderSummary
	for _, summary := range providers {
		if summary.ID == providerID {
			saved = summary
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"provider": saved,
	})
}

// handleAPITunnelProvidersDelete 删除提供商
func (s *Server) handleAPITunnelProvidersDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	idx := -1
	for i, provider := range s.config.Tunnels.Providers {
		if provider.ID == req.ID {
			idx = i
			break
		}
	}

	if idx == -1 {
		s.writeJSONError(w, http.StatusNotFound, "provider not found")
		return
	}

	s.config.Tunnels.Providers = append(s.config.Tunnels.Providers[:idx], s.config.Tunnels.Providers[idx+1:]...)

	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("Failed to save config after deleting tunnel provider: %v", err)
		s.writeJSONError(w, http.StatusInternalServerError, "failed to save configuration")
		return
	}

	s.tunnelManager.SyncFromConfig(s.config.Tunnels)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// handleAPITunnelDelete 删除提供商下的某个隧道
func (s *Server) handleAPITunnelDelete(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ProviderID string `json:"provider_id"`
		TunnelID   string `json:"tunnel_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	providerIdx := -1
	for i, provider := range s.config.Tunnels.Providers {
		if provider.ID == req.ProviderID {
			providerIdx = i
			break
		}
	}

	if providerIdx == -1 {
		s.writeJSONError(w, http.StatusNotFound, "provider not found")
		return
	}

	tunnelIdx := -1
	provider := s.config.Tunnels.Providers[providerIdx]
	for i, def := range provider.Tunnels {
		if def.ID == req.TunnelID {
			tunnelIdx = i
			break
		}
	}

	if tunnelIdx == -1 {
		s.writeJSONError(w, http.StatusNotFound, "tunnel not found")
		return
	}

	provider.Tunnels = append(provider.Tunnels[:tunnelIdx], provider.Tunnels[tunnelIdx+1:]...)
	s.config.Tunnels.Providers[providerIdx] = provider

	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.log.Errorf("Failed to save config after deleting tunnel: %v", err)
		s.writeJSONError(w, http.StatusInternalServerError, "failed to save configuration")
		return
	}

	s.tunnelManager.SyncFromConfig(s.config.Tunnels)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

// handleAPITunnelStart 启动一个隧道（当前为占位逻辑）
func (s *Server) handleAPITunnelStart(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ProviderID string `json:"provider_id"`
		TunnelID   string `json:"tunnel_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	status, err := s.tunnelManager.StartTunnel(req.ProviderID, req.TunnelID)
	if err != nil {
		s.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"tunnel":  status,
	})
}

// handleAPITunnelStop 停止一个隧道
func (s *Server) handleAPITunnelStop(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ProviderID string `json:"provider_id"`
		TunnelID   string `json:"tunnel_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	status, err := s.tunnelManager.StopTunnel(req.ProviderID, req.TunnelID)
	if err != nil {
		s.writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"tunnel":  status,
	})
}

// handleAPITunnelStatus 查询隧道状态
func (s *Server) handleAPITunnelStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	providerID := r.URL.Query().Get("provider_id")
	tunnelID := r.URL.Query().Get("tunnel_id")

	if providerID != "" && tunnelID != "" {
		status, err := s.tunnelManager.GetTunnel(providerID, tunnelID)
		if err != nil {
			s.writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"tunnel":  status,
		})
		return
	}

	providers := s.tunnelManager.ListProviders()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"providers": providers,
	})
}

func buildTunnelDefinition(providerID string, req tunnelDefinitionRequest) (config.TunnelDefinition, error) {
	definition := config.TunnelDefinition{}

	definition.ID = strings.TrimSpace(req.ID)
	if definition.ID == "" {
		definition.ID = tunnel.GenerateTunnelID(providerID)
	}

	definition.Name = strings.TrimSpace(req.Name)
	if definition.Name == "" {
		definition.Name = definition.ID
	}

	definition.Protocol = config.NormalizeTunnelProtocol(req.Protocol)
	if !config.IsSupportedTunnelProtocol(definition.Protocol) {
		return config.TunnelDefinition{}, fmt.Errorf("unsupported tunnel protocol: %s", req.Protocol)
	}

	definition.LocalAddress = strings.TrimSpace(req.LocalAddress)
	if definition.LocalAddress == "" {
		definition.LocalAddress = "127.0.0.1"
	}

	definition.LocalPort = req.LocalPort
	if definition.LocalPort < 1 || definition.LocalPort > 65535 {
		return config.TunnelDefinition{}, fmt.Errorf("invalid local port: %d", definition.LocalPort)
	}
	definition.PublicHostname = strings.TrimSpace(req.PublicHostname)
	definition.PublicPort = req.PublicPort
	if definition.PublicPort < 0 || definition.PublicPort > 65535 {
		return config.TunnelDefinition{}, fmt.Errorf("invalid public port: %d", definition.PublicPort)
	}
	definition.EdgeRegion = strings.TrimSpace(req.EdgeRegion)
	definition.AutoStart = req.AutoStart
	definition.Metadata = sanitizeStringMap(req.Metadata)
	definition.Parameters = sanitizeStringMap(req.Parameters)
	definition.Notes = strings.TrimSpace(req.Notes)

	return definition, nil
}

func sanitizeStringMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		result[key] = strings.TrimSpace(v)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (s *Server) writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
