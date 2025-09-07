package cluster

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Manager 集群管理器
type Manager struct {
	config     Config
	mode       string
	nodeID     string
	nodes      map[string]*NodeInfo
	nodesMutex sync.RWMutex
	syncTicker *time.Ticker
	stopChan   chan bool
	logger     *logrus.Logger
}

// Config 集群配置接口
type Config interface {
	GetClusterMode() string
	GetNodeID() string
	GetNodeName() string
	GetMasterConfig() MasterConfig
	GetSyncConfig() SyncConfig
	GetClusterPort() int
	GetClusterAuthKey() string
	IsSlaveMode() bool
	IsMasterMode() bool
	IsStandaloneMode() bool
	GetServicePort() int
	GetCertDir() string
	GetProxyRules() []interface{}
	GetSSLDomains() []string
}

// NodeInfo 节点信息
type NodeInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Mode        string    `json:"mode"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Status      string    `json:"status"`
	LastSeen    time.Time `json:"last_seen"`
	LastSync    time.Time `json:"last_sync"`
	Version     string    `json:"version"`
	SyncEnabled bool      `json:"sync_enabled"`

	// 扩展监控信息
	IPAddress     string    `json:"ip_address"`
	ServicePort   int       `json:"service_port"`
	CertCount     int       `json:"cert_count"`
	ConfigMD5     string    `json:"config_md5"`
	ProxyRules    int       `json:"proxy_rules"`
	SSLDomains    int       `json:"ssl_domains"`
	Uptime        int64     `json:"uptime"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

// SyncRequest 同步请求
type SyncRequest struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	AuthKey   string                 `json:"auth_key"`
	NodeID    string                 `json:"node_id"`
	NodeInfo  *NodeInfo              `json:"node_info,omitempty"`
}

// SyncResponse 同步响应
type SyncResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
}

// NewManager 创建集群管理器
func NewManager(config Config, logger *logrus.Logger) *Manager {
	return &Manager{
		config:   config,
		mode:     config.GetClusterMode(),
		nodeID:   config.GetNodeID(),
		nodes:    make(map[string]*NodeInfo),
		stopChan: make(chan bool),
		logger:   logger,
	}
}

// Start 启动集群管理器
func (m *Manager) Start() error {
	m.logger.Infof("Starting cluster manager in %s mode", m.mode)

	switch m.mode {
	case "slave":
		return m.startSlaveMode()
	case "master":
		return m.startMasterMode()
	default:
		m.logger.Info("Running in standalone mode")
		return nil
	}
}

// Stop 停止集群管理器
func (m *Manager) Stop() {
	if m.syncTicker != nil {
		m.syncTicker.Stop()
	}
	close(m.stopChan)
	m.logger.Info("Cluster manager stopped")
}

// IsSlaveMode 检查是否为Slave模式
func (m *Manager) IsSlaveMode() bool {
	return m.mode == "slave"
}

// IsMasterMode 检查是否为Master模式
func (m *Manager) IsMasterMode() bool {
	return m.mode == "master"
}

// IsStandaloneMode 检查是否为独立模式
func (m *Manager) IsStandaloneMode() bool {
	return m.mode == "standalone"
}

// GetNodes 获取所有节点信息
func (m *Manager) GetNodes() map[string]interface{} {
	m.nodesMutex.RLock()
	defer m.nodesMutex.RUnlock()

	nodes := make(map[string]interface{})
	for k, v := range m.nodes {
		nodes[k] = v
	}
	return nodes
}

// startSlaveMode 启动Slave模式
func (m *Manager) startSlaveMode() error {
	masterConfig := m.config.GetMasterConfig()
	if masterConfig.Host == "" {
		return fmt.Errorf("master host not configured")
	}

	m.logger.Infof("Connecting to master at %s:%d", masterConfig.Host, masterConfig.Port)

	// 启动同步任务
	syncConfig := m.config.GetSyncConfig()
	m.syncTicker = time.NewTicker(time.Duration(syncConfig.Interval) * time.Second)

	go func() {
		for {
			select {
			case <-m.syncTicker.C:
				if err := m.syncFromMaster(); err != nil {
					m.logger.Errorf("Failed to sync from master: %v", err)
				}
			case <-m.stopChan:
				return
			}
		}
	}()

	return nil
}

// startMasterMode 启动Master模式
func (m *Manager) startMasterMode() error {
	m.logger.Info("Running as master node")

	// 定期清理过期节点
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.cleanupExpiredNodes()
			case <-m.stopChan:
				return
			}
		}
	}()

	return nil
}

// syncFromMaster 从Master同步配置
func (m *Manager) syncFromMaster() error {
	masterConfig := m.config.GetMasterConfig()

	url := fmt.Sprintf("http://%s:%d/cluster/sync", masterConfig.Host, masterConfig.Port)

	// 收集当前节点信息
	nodeInfo := m.CollectNodeInfo()

	request := SyncRequest{
		Type:      "config",
		Timestamp: time.Now(),
		AuthKey:   masterConfig.AuthKey,
		NodeID:    m.nodeID,
		NodeInfo:  nodeInfo,
	}

	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal sync request: %v", err)
	}

	client := &http.Client{
		Timeout: time.Duration(masterConfig.Timeout) * time.Second,
	}

	resp, err := client.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to connect to master: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("master returned status: %d", resp.StatusCode)
	}

	var response SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode sync response: %v", err)
	}

	if !response.Success {
		return fmt.Errorf("sync failed: %s", response.Message)
	}

	// 应用同步的配置
	return m.applySync(response.Data)
}

// applySync 应用同步的配置
func (m *Manager) applySync(data map[string]interface{}) error {
	syncConfig := m.config.GetSyncConfig()

	if syncConfig.ConfigEnabled {
		if configData, ok := data["config"]; ok {
			if err := m.applyConfigSync(configData); err != nil {
				m.logger.Errorf("Failed to apply config sync: %v", err)
				return err
			}
		}
	}

	if syncConfig.CertEnabled {
		if certData, ok := data["certs"]; ok {
			if err := m.applyCertSync(certData); err != nil {
				m.logger.Errorf("Failed to apply cert sync: %v", err)
				return err
			}
		}
	}

	return nil
}

// applyConfigSync 应用配置同步
func (m *Manager) applyConfigSync(configData interface{}) error {
	// TODO: 实现配置同步逻辑
	m.logger.Debug("Config sync applied")
	return nil
}

// applyCertSync 应用证书同步
func (m *Manager) applyCertSync(certData interface{}) error {
	// TODO: 实现证书同步逻辑
	m.logger.Debug("Certificate sync applied")
	return nil
}

// RegisterNode 注册节点
func (m *Manager) RegisterNode(nodeInfo *NodeInfo) {
	m.nodesMutex.Lock()
	defer m.nodesMutex.Unlock()

	nodeInfo.LastSeen = time.Now()
	m.nodes[nodeInfo.ID] = nodeInfo

	m.logger.Infof("Node registered: %s (%s)", nodeInfo.Name, nodeInfo.ID)
}

// cleanupExpiredNodes 清理过期节点
func (m *Manager) cleanupExpiredNodes() {
	m.nodesMutex.Lock()
	defer m.nodesMutex.Unlock()

	expireTime := time.Now().Add(-5 * time.Minute)

	for id, node := range m.nodes {
		if node.LastSeen.Before(expireTime) {
			delete(m.nodes, id)
			m.logger.Infof("Node expired: %s (%s)", node.Name, id)
		}
	}
}

// HandleSyncRequest 处理同步请求
func (m *Manager) HandleSyncRequest(w http.ResponseWriter, r *http.Request) {
	if !m.IsMasterMode() {
		http.Error(w, "Not a master node", http.StatusForbidden)
		return
	}

	var request SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 验证认证密钥
	if request.AuthKey != m.config.GetClusterAuthKey() {
		http.Error(w, "Invalid auth key", http.StatusUnauthorized)
		return
	}

	// 更新节点信息（包括详细监控数据）
	if request.NodeInfo != nil {
		m.updateNodeInfo(request.NodeID, request.NodeInfo)
	} else {
		m.updateNodeLastSeen(request.NodeID)
	}

	// 构建同步数据
	syncData := make(map[string]interface{})

	syncConfig := m.config.GetSyncConfig()
	if syncConfig.ConfigEnabled {
		// TODO: 获取配置数据
		syncData["config"] = map[string]interface{}{}
	}

	if syncConfig.CertEnabled {
		// TODO: 获取证书数据
		syncData["certs"] = map[string]interface{}{}
	}

	response := SyncResponse{
		Success: true,
		Message: "Sync successful",
		Data:    syncData,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// updateNodeLastSeen 更新节点最后见到时间
func (m *Manager) updateNodeLastSeen(nodeID string) {
	m.nodesMutex.Lock()
	defer m.nodesMutex.Unlock()

	if node, exists := m.nodes[nodeID]; exists {
		node.LastSeen = time.Now()
		node.LastHeartbeat = time.Now()
	}
}

// updateNodeInfo 更新节点完整信息
func (m *Manager) updateNodeInfo(nodeID string, nodeInfo *NodeInfo) {
	m.nodesMutex.Lock()
	defer m.nodesMutex.Unlock()

	// 更新或创建节点信息
	nodeInfo.ID = nodeID
	nodeInfo.LastSeen = time.Now()
	nodeInfo.LastHeartbeat = time.Now()
	nodeInfo.Status = "online"

	m.nodes[nodeID] = nodeInfo

	m.logger.Debugf("Updated node info: %s (%s)", nodeInfo.Name, nodeID)
}

// CollectNodeInfo 收集当前节点的监控信息
func (m *Manager) CollectNodeInfo() *NodeInfo {
	nodeInfo := &NodeInfo{
		ID:            m.nodeID,
		Name:          m.config.GetNodeName(),
		Mode:          m.mode,
		Version:       "1.0.21", // TODO: 从配置或构建信息获取
		SyncEnabled:   true,
		Status:        "online",
		LastHeartbeat: time.Now(),
	}

	// 获取本机IP地址
	if ip := getLocalIP(); ip != "" {
		nodeInfo.IPAddress = ip
	}

	// 获取服务端口
	nodeInfo.ServicePort = getServicePort(m.config)

	// 获取证书数量
	nodeInfo.CertCount = getCertCount(m.config)

	// 计算配置MD5
	nodeInfo.ConfigMD5 = getConfigMD5(m.config)

	// 获取代理规则数量
	nodeInfo.ProxyRules = getProxyRulesCount(m.config)

	// 获取SSL域名数量
	nodeInfo.SSLDomains = getSSLDomainsCount(m.config)

	// 计算运行时间（秒）
	nodeInfo.Uptime = int64(time.Since(time.Now().Add(-time.Hour)).Seconds()) // TODO: 从实际启动时间计算

	return nodeInfo
}

// getLocalIP 获取本机IP地址
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return ""
}

// getServicePort 获取服务端口
func getServicePort(config Config) int {
	return config.GetServicePort()
}

// getCertCount 获取证书数量
func getCertCount(config Config) int {
	certDir := config.GetCertDir()
	count := 0

	if entries, err := os.ReadDir(certDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".crt") || strings.HasSuffix(entry.Name(), ".pem")) {
				count++
			}
		}
	}

	return count
}

// getConfigMD5 计算配置的MD5值
func getConfigMD5(config Config) string {
	// 获取配置的JSON表示
	configData, err := json.Marshal(config)
	if err != nil {
		return ""
	}

	// 计算MD5
	hash := md5.Sum(configData)
	return hex.EncodeToString(hash[:])
}

// getProxyRulesCount 获取代理规则数量
func getProxyRulesCount(config Config) int {
	rules := config.GetProxyRules()
	return len(rules)
}

// getSSLDomainsCount 获取SSL域名数量
func getSSLDomainsCount(config Config) int {
	domains := config.GetSSLDomains()
	return len(domains)
}

// SetSlaveMode 设置为Slave模式
func (m *Manager) SetSlaveMode(masterHost string, masterPort int, authKey string) error {
	// TODO: 实现切换到Slave模式的逻辑
	m.mode = "slave"
	m.logger.Infof("Switched to slave mode, master: %s:%d", masterHost, masterPort)
	return nil
}

// SetStandaloneMode 设置为独立模式
func (m *Manager) SetStandaloneMode() error {
	if m.syncTicker != nil {
		m.syncTicker.Stop()
		m.syncTicker = nil
	}

	m.mode = "standalone"
	m.logger.Info("Switched to standalone mode")
	return nil
}

// generateNodeID 生成节点ID
func generateNodeID() string {
	data := make([]byte, 16)
	rand.Read(data)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:8])
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
