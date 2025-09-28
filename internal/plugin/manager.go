package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"plugin"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Manager 插件管理器
type Manager struct {
	// 插件存储
	plugins     map[string]Plugin
	pluginPaths map[string]string // 插件ID -> 文件路径

	// 分类插件
	middlewarePlugins   []MiddlewarePlugin
	securityPlugins     []SecurityPlugin
	analyticsPlugins    []AnalyticsPlugin
	storagePlugins      []StoragePlugin
	notificationPlugins []NotificationPlugin
	authPlugins         []AuthPlugin

	// 配置和状态
	config  *ManagerConfig
	enabled bool
	mutex   sync.RWMutex
	log     *logrus.Entry

	// 插件加载器
	loader *PluginLoader

	// 事件系统
	eventBus *EventBus

	// 健康检查
	healthChecker *HealthChecker

	// 依赖管理
	dependencyResolver *DependencyResolver
}

// ManagerConfig 管理器配置
type ManagerConfig struct {
	PluginsDir          string                 `json:"plugins_dir"`
	ConfigDir           string                 `json:"config_dir"`
	Enabled             bool                   `json:"enabled"`
	AutoLoad            bool                   `json:"auto_load"`
	HotReload           bool                   `json:"hot_reload"`
	MaxPlugins          int                    `json:"max_plugins"`
	LoadTimeout         time.Duration          `json:"load_timeout"`
	HealthCheckInterval time.Duration          `json:"health_check_interval"`
	DefaultConfig       map[string]interface{} `json:"default_config"`
	TrustedSources      []string               `json:"trusted_sources"`
}

// PluginLoader 插件加载器
type PluginLoader struct {
	loadedPlugins map[string]*plugin.Plugin
	mutex         sync.RWMutex
}

// EventBus 事件总线
type EventBus struct {
	subscribers map[string][]EventHandler
	mutex       sync.RWMutex
}

// EventHandler 事件处理器
type EventHandler func(event *Event) error

// Event 事件
type Event struct {
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// HealthChecker 健康检查器
type HealthChecker struct {
	manager  *Manager
	interval time.Duration
	stopChan chan struct{}
}

// DependencyResolver 依赖解析器
type DependencyResolver struct {
	dependencies map[string][]string
	resolved     map[string]bool
}

// NewManager 创建插件管理器
func NewManager(config *ManagerConfig) *Manager {
	if config == nil {
		config = &ManagerConfig{
			PluginsDir:          "./plugins",
			ConfigDir:           "./config/plugins",
			Enabled:             true,
			AutoLoad:            true,
			HotReload:           false,
			MaxPlugins:          100,
			LoadTimeout:         30 * time.Second,
			HealthCheckInterval: 5 * time.Minute,
			DefaultConfig:       make(map[string]interface{}),
			TrustedSources:      []string{},
		}
	}

	manager := &Manager{
		plugins:             make(map[string]Plugin),
		pluginPaths:         make(map[string]string),
		middlewarePlugins:   make([]MiddlewarePlugin, 0),
		securityPlugins:     make([]SecurityPlugin, 0),
		analyticsPlugins:    make([]AnalyticsPlugin, 0),
		storagePlugins:      make([]StoragePlugin, 0),
		notificationPlugins: make([]NotificationPlugin, 0),
		authPlugins:         make([]AuthPlugin, 0),
		config:              config,
		enabled:             config.Enabled,
		log: logrus.WithFields(logrus.Fields{
			"component": "plugin_manager",
		}),
		loader: &PluginLoader{
			loadedPlugins: make(map[string]*plugin.Plugin),
		},
		eventBus: &EventBus{
			subscribers: make(map[string][]EventHandler),
		},
		dependencyResolver: &DependencyResolver{
			dependencies: make(map[string][]string),
			resolved:     make(map[string]bool),
		},
	}

	// 初始化健康检查器
	manager.healthChecker = &HealthChecker{
		manager:  manager,
		interval: config.HealthCheckInterval,
		stopChan: make(chan struct{}),
	}

	return manager
}

// Start 启动插件管理器
func (m *Manager) Start(ctx context.Context) error {
	if !m.enabled {
		m.log.Info("Plugin manager is disabled")
		return nil
	}

	m.log.Info("Starting plugin manager")

	// 创建必要的目录
	if err := os.MkdirAll(m.config.PluginsDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugins directory: %w", err)
	}

	if err := os.MkdirAll(m.config.ConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// 自动加载插件
	if m.config.AutoLoad {
		if err := m.LoadAllPlugins(ctx); err != nil {
			m.log.Errorf("Failed to auto-load plugins: %v", err)
		}
	}

	// 启动健康检查
	go m.healthChecker.Start()

	// 启动热重载监视器
	if m.config.HotReload {
		go m.startHotReloadWatcher()
	}

	m.log.Infof("Plugin manager started with %d plugins", len(m.plugins))
	return nil
}

// Stop 停止插件管理器
func (m *Manager) Stop(ctx context.Context) error {
	m.log.Info("Stopping plugin manager")

	// 停止健康检查
	close(m.healthChecker.stopChan)

	// 停止所有插件
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for id, plugin := range m.plugins {
		if err := plugin.Stop(ctx); err != nil {
			m.log.Errorf("Failed to stop plugin %s: %v", id, err)
		}
	}

	m.log.Info("Plugin manager stopped")
	return nil
}

// LoadAllPlugins 加载所有插件
func (m *Manager) LoadAllPlugins(ctx context.Context) error {
	pluginFiles, err := m.findPluginFiles()
	if err != nil {
		return fmt.Errorf("failed to find plugin files: %w", err)
	}

	m.log.Infof("Found %d plugin files", len(pluginFiles))

	// 按依赖顺序加载
	for _, file := range pluginFiles {
		if err := m.LoadPlugin(ctx, file); err != nil {
			m.log.Errorf("Failed to load plugin %s: %v", file, err)
		}
	}

	return nil
}

// LoadPlugin 加载单个插件
func (m *Manager) LoadPlugin(ctx context.Context, path string) error {
	if !m.enabled {
		return fmt.Errorf("plugin manager is disabled")
	}

	if len(m.plugins) >= m.config.MaxPlugins {
		return fmt.Errorf("maximum number of plugins (%d) reached", m.config.MaxPlugins)
	}

	m.log.Infof("Loading plugin from: %s", path)

	// 加载插件文件
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	// 查找插件符号
	symbol, err := p.Lookup("NewPlugin")
	if err != nil {
		return fmt.Errorf("plugin does not export NewPlugin function: %w", err)
	}

	// 类型断言
	newPluginFunc, ok := symbol.(func() Plugin)
	if !ok {
		return fmt.Errorf("NewPlugin is not a valid function")
	}

	// 创建插件实例
	pluginInstance := newPluginFunc()
	if pluginInstance == nil {
		return fmt.Errorf("plugin creation returned nil")
	}

	info := pluginInstance.GetInfo()
	if info == nil {
		return fmt.Errorf("plugin info is nil")
	}

	// 检查插件是否已存在
	m.mutex.Lock()
	if _, exists := m.plugins[info.ID]; exists {
		m.mutex.Unlock()
		return fmt.Errorf("plugin %s already exists", info.ID)
	}
	m.mutex.Unlock()

	// 加载插件配置
	config, err := m.loadPluginConfig(info.ID)
	if err != nil {
		m.log.Warnf("Failed to load config for plugin %s: %v", info.ID, err)
		config = make(map[string]interface{})
	}

	// 初始化插件
	if err := pluginInstance.Initialize(config); err != nil {
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}

	// 启动插件
	if err := pluginInstance.Start(ctx); err != nil {
		return fmt.Errorf("failed to start plugin: %w", err)
	}

	// 注册插件
	m.mutex.Lock()
	m.plugins[info.ID] = pluginInstance
	m.pluginPaths[info.ID] = path

	// 按接口类型分类
	m.categorizePlugin(pluginInstance)
	m.mutex.Unlock()

	// 存储加载的插件引用
	m.loader.mutex.Lock()
	m.loader.loadedPlugins[info.ID] = p
	m.loader.mutex.Unlock()

	// 发送插件加载事件
	m.eventBus.Publish(&Event{
		Type:   "plugin_loaded",
		Source: "plugin_manager",
		Data: map[string]interface{}{
			"plugin_id":      info.ID,
			"plugin_name":    info.Name,
			"plugin_version": info.Version,
		},
		Timestamp: time.Now(),
	})

	m.log.Infof("Successfully loaded plugin: %s v%s", info.Name, info.Version)
	return nil
}

// UnloadPlugin 卸载插件
func (m *Manager) UnloadPlugin(ctx context.Context, pluginID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	plugin, exists := m.plugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginID)
	}

	// 停止插件
	if err := plugin.Stop(ctx); err != nil {
		m.log.Errorf("Error stopping plugin %s: %v", pluginID, err)
	}

	// 从分类中移除
	m.uncategorizePlugin(plugin)

	// 从主映射中移除
	delete(m.plugins, pluginID)
	delete(m.pluginPaths, pluginID)

	// 从加载器中移除
	m.loader.mutex.Lock()
	delete(m.loader.loadedPlugins, pluginID)
	m.loader.mutex.Unlock()

	// 发送插件卸载事件
	m.eventBus.Publish(&Event{
		Type:   "plugin_unloaded",
		Source: "plugin_manager",
		Data: map[string]interface{}{
			"plugin_id": pluginID,
		},
		Timestamp: time.Now(),
	})

	m.log.Infof("Successfully unloaded plugin: %s", pluginID)
	return nil
}

// ReloadPlugin 重新加载插件
func (m *Manager) ReloadPlugin(ctx context.Context, pluginID string) error {
	path, exists := m.pluginPaths[pluginID]
	if !exists {
		return fmt.Errorf("plugin path not found for %s", pluginID)
	}

	// 卸载现有插件
	if err := m.UnloadPlugin(ctx, pluginID); err != nil {
		return fmt.Errorf("failed to unload plugin: %w", err)
	}

	// 重新加载插件
	if err := m.LoadPlugin(ctx, path); err != nil {
		return fmt.Errorf("failed to reload plugin: %w", err)
	}

	return nil
}

// GetPlugin 获取插件
func (m *Manager) GetPlugin(pluginID string) (Plugin, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	plugin, exists := m.plugins[pluginID]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginID)
	}

	return plugin, nil
}

// GetPlugins 获取所有插件
func (m *Manager) GetPlugins() map[string]Plugin {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	result := make(map[string]Plugin)
	for id, plugin := range m.plugins {
		result[id] = plugin
	}

	return result
}

// GetMiddlewarePlugins 获取中间件插件（按优先级排序）
func (m *Manager) GetMiddlewarePlugins() []MiddlewarePlugin {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 创建副本并排序
	plugins := make([]MiddlewarePlugin, len(m.middlewarePlugins))
	copy(plugins, m.middlewarePlugins)

	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].GetPriority() < plugins[j].GetPriority()
	})

	return plugins
}

// GetSecurityPlugins 获取安全插件
func (m *Manager) GetSecurityPlugins() []SecurityPlugin {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	plugins := make([]SecurityPlugin, len(m.securityPlugins))
	copy(plugins, m.securityPlugins)
	return plugins
}

// GetAnalyticsPlugins 获取分析插件
func (m *Manager) GetAnalyticsPlugins() []AnalyticsPlugin {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	plugins := make([]AnalyticsPlugin, len(m.analyticsPlugins))
	copy(plugins, m.analyticsPlugins)
	return plugins
}

// categorizePlugin 分类插件
func (m *Manager) categorizePlugin(plugin Plugin) {
	if middleware, ok := plugin.(MiddlewarePlugin); ok {
		m.middlewarePlugins = append(m.middlewarePlugins, middleware)
	}

	if security, ok := plugin.(SecurityPlugin); ok {
		m.securityPlugins = append(m.securityPlugins, security)
	}

	if analytics, ok := plugin.(AnalyticsPlugin); ok {
		m.analyticsPlugins = append(m.analyticsPlugins, analytics)
	}

	if storage, ok := plugin.(StoragePlugin); ok {
		m.storagePlugins = append(m.storagePlugins, storage)
	}

	if notification, ok := plugin.(NotificationPlugin); ok {
		m.notificationPlugins = append(m.notificationPlugins, notification)
	}

	if auth, ok := plugin.(AuthPlugin); ok {
		m.authPlugins = append(m.authPlugins, auth)
	}
}

// uncategorizePlugin 从分类中移除插件
func (m *Manager) uncategorizePlugin(plugin Plugin) {
	if _, ok := plugin.(MiddlewarePlugin); ok {
		m.middlewarePlugins = removeMiddlewarePlugin(m.middlewarePlugins, plugin)
	}

	if _, ok := plugin.(SecurityPlugin); ok {
		m.securityPlugins = removeSecurityPlugin(m.securityPlugins, plugin)
	}

	if _, ok := plugin.(AnalyticsPlugin); ok {
		m.analyticsPlugins = removeAnalyticsPlugin(m.analyticsPlugins, plugin)
	}

	// ... 其他类型的移除逻辑
}

// findPluginFiles 查找插件文件
func (m *Manager) findPluginFiles() ([]string, error) {
	var files []string

	err := filepath.WalkDir(m.config.PluginsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && strings.HasSuffix(path, ".so") {
			files = append(files, path)
		}

		return nil
	})

	return files, err
}

// loadPluginConfig 加载插件配置
func (m *Manager) loadPluginConfig(pluginID string) (map[string]interface{}, error) {
	configPath := filepath.Join(m.config.ConfigDir, pluginID+".json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return m.config.DefaultConfig, nil
		}
		return nil, err
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return config, nil
}

// startHotReloadWatcher 启动热重载监视器
func (m *Manager) startHotReloadWatcher() {
	// 这里可以实现文件系统监视器
	// 当插件文件发生变化时自动重新加载
	m.log.Info("Hot reload watcher started (placeholder implementation)")
}

// 辅助函数：从切片中移除插件
func removeMiddlewarePlugin(slice []MiddlewarePlugin, plugin Plugin) []MiddlewarePlugin {
	for i, p := range slice {
		if p.GetInfo().ID == plugin.GetInfo().ID {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func removeSecurityPlugin(slice []SecurityPlugin, plugin Plugin) []SecurityPlugin {
	for i, p := range slice {
		if p.GetInfo().ID == plugin.GetInfo().ID {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func removeAnalyticsPlugin(slice []AnalyticsPlugin, plugin Plugin) []AnalyticsPlugin {
	for i, p := range slice {
		if p.GetInfo().ID == plugin.GetInfo().ID {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// Subscribe 订阅事件
func (eb *EventBus) Subscribe(eventType string, handler EventHandler) {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()

	eb.subscribers[eventType] = append(eb.subscribers[eventType], handler)
}

// Publish 发布事件
func (eb *EventBus) Publish(event *Event) {
	eb.mutex.RLock()
	handlers, exists := eb.subscribers[event.Type]
	eb.mutex.RUnlock()

	if !exists {
		return
	}

	for _, handler := range handlers {
		go func(h EventHandler) {
			if err := h(event); err != nil {
				logrus.Errorf("Event handler error: %v", err)
			}
		}(handler)
	}
}

// Start 启动健康检查
func (hc *HealthChecker) Start() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.checkAllPlugins()
		case <-hc.stopChan:
			return
		}
	}
}

// checkAllPlugins 检查所有插件健康状态
func (hc *HealthChecker) checkAllPlugins() {
	hc.manager.mutex.RLock()
	plugins := make(map[string]Plugin)
	for id, plugin := range hc.manager.plugins {
		plugins[id] = plugin
	}
	hc.manager.mutex.RUnlock()

	for id, plugin := range plugins {
		health := plugin.GetHealth()
		if health.Status != "healthy" {
			hc.manager.log.Warnf("Plugin %s health check failed: %s", id, health.Message)

			// 发送健康检查失败事件
			hc.manager.eventBus.Publish(&Event{
				Type:   "plugin_health_check_failed",
				Source: "health_checker",
				Data: map[string]interface{}{
					"plugin_id": id,
					"status":    health.Status,
					"message":   health.Message,
				},
				Timestamp: time.Now(),
			})
		}
	}
}
