package config

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

// ConfigWatcher 配置文件监听器
type ConfigWatcher struct {
	configFile string
	config     *Config
	lastHash   string
	mutex      sync.RWMutex
	log        *logrus.Entry

	// 文件系统监听器
	watcher *fsnotify.Watcher

	// 控制监听器的停止
	ctx    context.Context
	cancel context.CancelFunc

	// 回调函数
	onConfigChange  func(*Config, *Config) error // (oldConfig, newConfig) -> error
	onConfigApply   func(*Config, *Config) (*Config, error)
	onReloadStart   func()
	onReloadSuccess func(*Config)
	onReloadError   func(error)

	// 防抖配置
	debounceInterval time.Duration
	lastChangeTime   time.Time
	debounceTimer    *time.Timer
	debounceMutex    sync.Mutex

	// reloadMutex 串行化并发重载（事件防抖 timer 与 ForceReload 可能同时触发）
	reloadMutex sync.Mutex
}

// NewConfigWatcher 创建配置监听器
func NewConfigWatcher(configFile string, config *Config) (*ConfigWatcher, error) {
	ctx, cancel := context.WithCancel(context.Background())

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	// 计算初始配置哈希
	initialHash, err := calculateConfigHash(configFile)
	if err != nil {
		watcher.Close()
		cancel()
		return nil, fmt.Errorf("failed to calculate initial config hash: %w", err)
	}

	cw := &ConfigWatcher{
		configFile:       configFile,
		config:           config,
		lastHash:         initialHash,
		watcher:          watcher,
		ctx:              ctx,
		cancel:           cancel,
		debounceInterval: 1 * time.Second, // 默认1秒防抖
		log: logrus.WithFields(logrus.Fields{
			"component":   "config_watcher",
			"config_file": configFile,
		}),
	}

	return cw, nil
}

// Start 开始监听配置文件变化
func (cw *ConfigWatcher) Start() error {
	// 添加配置文件到监听列表
	configDir := filepath.Dir(cw.configFile)
	if err := cw.watcher.Add(configDir); err != nil {
		return fmt.Errorf("failed to watch config directory: %w", err)
	}

	cw.log.Infof("Started watching config file: %s", cw.configFile)

	// 启动监听协程
	go cw.watchLoop()

	return nil
}

// Stop 停止监听
func (cw *ConfigWatcher) Stop() {
	cw.log.Info("Stopping config watcher")

	if cw.watcher != nil {
		cw.watcher.Close()
	}

	if cw.cancel != nil {
		cw.cancel()
	}
}

// watchLoop 监听循环
func (cw *ConfigWatcher) watchLoop() {
	defer cw.watcher.Close()

	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				cw.log.Warn("Config watcher events channel closed")
				return
			}

			cw.handleFileEvent(event)

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				cw.log.Warn("Config watcher errors channel closed")
				return
			}

			cw.log.Errorf("Config watcher error: %v", err)

		case <-cw.ctx.Done():
			cw.log.Info("Config watcher context cancelled")
			return
		}
	}
}

// handleFileEvent 处理文件事件
func (cw *ConfigWatcher) handleFileEvent(event fsnotify.Event) {
	// 只关心配置文件的写入和创建事件
	if event.Name != cw.configFile {
		return
	}

	if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
		cw.log.Debugf("Config file changed: %s (op: %v)", event.Name, event.Op)

		// 防抖处理：避免短时间内多次重载
		// 使用 Timer 复用，避免每次都创建新 goroutine
		cw.debounceMutex.Lock()
		if cw.debounceTimer != nil {
			cw.debounceTimer.Stop()
		}
		cw.debounceTimer = time.AfterFunc(cw.debounceInterval, func() {
			select {
			case <-cw.ctx.Done():
				// 监听器已停止，取消处理
				return
			default:
				cw.reloadConfig()
			}
		})
		cw.debounceMutex.Unlock()
	}
}

// reloadConfig 重载配置，返回真实错误。
// 并发重载通过 reloadMutex 串行化；失败时不更新 config 与 lastHash，
// 保留旧配置及哈希直到配置变化回调成功后才提交新配置。
func (cw *ConfigWatcher) reloadConfig() error {
	// 串行化并发重载，避免事件防抖 timer 与 ForceReload 交错执行
	cw.reloadMutex.Lock()
	defer cw.reloadMutex.Unlock()

	cw.log.Info("Reloading configuration...")

	// 触发重载开始回调
	if cw.onReloadStart != nil {
		cw.onReloadStart()
	}

	// 计算新配置哈希
	newHash, err := calculateConfigHash(cw.configFile)
	if err != nil {
		reloadErr := fmt.Errorf("failed to calculate config hash: %w", err)
		cw.log.Errorf("%v", reloadErr)
		if cw.onReloadError != nil {
			cw.onReloadError(reloadErr)
		}
		return reloadErr
	}

	// 检查配置是否真的没有变化。无变化视为成功，保留旧配置与哈希。
	if newHash == cw.GetLastHash() {
		cw.log.Debug("Config hash unchanged, skipping reload")
		return nil
	}

	// 加载新配置
	newConfig, err := Load(cw.configFile)
	if err != nil {
		reloadErr := fmt.Errorf("failed to load new config: %w", err)
		cw.log.Errorf("%v", reloadErr)
		if cw.onReloadError != nil {
			cw.onReloadError(reloadErr)
		}
		return reloadErr
	}

	// 验证新配置
	if err := cw.validateConfig(newConfig); err != nil {
		reloadErr := fmt.Errorf("config validation failed: %w", err)
		cw.log.Errorf("%v", reloadErr)
		if cw.onReloadError != nil {
			cw.onReloadError(reloadErr)
		}
		return reloadErr
	}

	// 获取旧配置副本
	cw.mutex.RLock()
	oldConfig := cw.config
	cw.mutex.RUnlock()

	// 应用回调可返回保留启动时字段的运行配置，磁盘哈希仍对应请求配置。
	if cw.onConfigApply != nil {
		newConfig, err = cw.onConfigApply(oldConfig, newConfig)
		if err == nil && newConfig == nil {
			err = fmt.Errorf("config apply callback returned nil configuration")
		}
	} else if cw.onConfigChange != nil {
		err = cw.onConfigChange(oldConfig, newConfig)
	}
	if err != nil {
		reloadErr := fmt.Errorf("config change callback failed: %w", err)
		cw.log.Errorf("%v", reloadErr)
		if cw.onReloadError != nil {
			cw.onReloadError(reloadErr)
		}
		return reloadErr
	}

	// 更新配置与哈希（callback 成功后才提交新配置）
	cw.mutex.Lock()
	cw.config = newConfig
	cw.lastHash = newHash
	cw.mutex.Unlock()

	cw.log.Info("Configuration reloaded successfully")

	// 触发重载成功回调
	if cw.onReloadSuccess != nil {
		cw.onReloadSuccess(newConfig)
	}

	return nil
}

// validateConfig 验证配置（委托给公共函数）
func (cw *ConfigWatcher) validateConfig(config *Config) error {
	return ValidateConfigWithLoopDetection(config)
}

// GetConfig 获取当前配置（线程安全）
func (cw *ConfigWatcher) GetConfig() *Config {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()
	return cw.config
}

// SetConfig 设置配置（线程安全）
func (cw *ConfigWatcher) SetConfig(config *Config) {
	cw.mutex.Lock()
	defer cw.mutex.Unlock()
	cw.config = config
}

// OnConfigChange 设置配置变化回调
func (cw *ConfigWatcher) OnConfigChange(callback func(*Config, *Config) error) {
	cw.onConfigChange = callback
}

// OnConfigApply 设置返回实际运行配置的应用回调；优先于 OnConfigChange。
func (cw *ConfigWatcher) OnConfigApply(callback func(*Config, *Config) (*Config, error)) {
	cw.onConfigApply = callback
}

// OnReloadStart 设置重载开始回调
func (cw *ConfigWatcher) OnReloadStart(callback func()) {
	cw.onReloadStart = callback
}

// OnReloadSuccess 设置重载成功回调
func (cw *ConfigWatcher) OnReloadSuccess(callback func(*Config)) {
	cw.onReloadSuccess = callback
}

// OnReloadError 设置重载错误回调
func (cw *ConfigWatcher) OnReloadError(callback func(error)) {
	cw.onReloadError = callback
}

// SetDebounceInterval 设置防抖间隔
func (cw *ConfigWatcher) SetDebounceInterval(interval time.Duration) {
	cw.debounceInterval = interval
}

// ForceReload 强制重载配置，返回真实错误。
func (cw *ConfigWatcher) ForceReload() error {
	cw.log.Info("Force reloading configuration...")
	return cw.reloadConfig()
}

// GetLastHash 获取最后的配置哈希
func (cw *ConfigWatcher) GetLastHash() string {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()
	return cw.lastHash
}

// calculateConfigHash 计算配置文件哈希
func calculateConfigHash(configFile string) (string, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return "", fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// GetConfigFileInfo 获取配置文件信息
func (cw *ConfigWatcher) GetConfigFileInfo() (map[string]interface{}, error) {
	stat, err := os.Stat(cw.configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get config file info: %w", err)
	}

	hash, err := calculateConfigHash(cw.configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate config hash: %w", err)
	}

	return map[string]interface{}{
		"file_path":   cw.configFile,
		"size":        stat.Size(),
		"mod_time":    stat.ModTime(),
		"hash":        hash,
		"last_hash":   cw.GetLastHash(),
		"is_watching": true,
		"debounce_ms": cw.debounceInterval.Milliseconds(),
	}, nil
}

// 以下兼容包装方法仅用于复用现有测试与旧调用方。
func (cw *ConfigWatcher) detectProxyLoop(config *Config, rule *ProxyRule) error {
	return detectProxyLoop(config, rule, getListeningPorts(config))
}

func (cw *ConfigWatcher) detectBackendLoop(config *Config, rule *ProxyRule, backend *ProxyBackend) error {
	return detectBackendLoop(config, rule, backend, getListeningPorts(config))
}

func (cw *ConfigWatcher) isLocalhost(host string) bool {
	return isLocalhost(host)
}

func (cw *ConfigWatcher) getListeningPorts(config *Config) []int {
	return getListeningPorts(config)
}
