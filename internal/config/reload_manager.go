package config

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ReloadableComponent 可重载组件接口
type ReloadableComponent interface {
	// GetName 获取组件名称
	GetName() string

	// Reload 重载组件配置
	Reload(newConfig *Config) error

	// Validate 验证配置是否适用于此组件
	Validate(newConfig *Config) error
}

// ReloadManager 重载管理器
type ReloadManager struct {
	components    []ReloadableComponent
	mutex         sync.RWMutex
	reloadMutex   sync.Mutex
	log           *logrus.Entry
	restartFields []string

	// 重载统计
	reloadCount    int64
	lastReloadTime time.Time
	successCount   int64
	errorCount     int64
}

func (rm *ReloadManager) snapshotComponents() []ReloadableComponent {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	components := make([]ReloadableComponent, len(rm.components))
	copy(components, rm.components)
	return components
}

// NewReloadManager 创建重载管理器
func NewReloadManager() *ReloadManager {
	return &ReloadManager{
		components: make([]ReloadableComponent, 0),
		log: logrus.WithFields(logrus.Fields{
			"component": "reload_manager",
		}),
	}
}

// RegisterComponent 注册可重载组件
func (rm *ReloadManager) RegisterComponent(component ReloadableComponent) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rm.components = append(rm.components, component)
	rm.log.Infof("Registered reloadable component: %s", component.GetName())
}

// UnregisterComponent 注销组件
func (rm *ReloadManager) UnregisterComponent(componentName string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	for i, component := range rm.components {
		if component.GetName() == componentName {
			rm.components = append(rm.components[:i], rm.components[i+1:]...)
			rm.log.Infof("Unregistered component: %s", componentName)
			return
		}
	}
}

// ReloadAll 重载所有组件（增强版：智能变更检测）
func (rm *ReloadManager) ReloadAll(oldConfig, newConfig *Config) error {
	_, err := rm.ReloadEffective(oldConfig, newConfig)
	return err
}

// ReloadEffective 返回实际应用的配置；启动时字段保持旧值，磁盘配置留待重启生效。
func (rm *ReloadManager) ReloadEffective(oldConfig, newConfig *Config) (*Config, error) {
	rm.reloadMutex.Lock()
	defer rm.reloadMutex.Unlock()
	if oldConfig == nil || newConfig == nil {
		return nil, fmt.Errorf("old and new configurations are required")
	}
	startTime := time.Now()
	components := rm.snapshotComponents()

	rm.mutex.Lock()
	rm.reloadCount++
	rm.lastReloadTime = startTime
	rm.mutex.Unlock()

	// 第一阶段：检测配置变更级别
	detector := NewChangeDetector()
	changes := detector.DetectChanges(oldConfig, newConfig)
	maxLevel := detector.GetMaxChangeLevel()

	rm.log.Infof("Configuration changes detected: %d changes, max level: %s", len(changes), maxLevel)

	// 记录所有变更。只记录字段名、级别与描述，绝不打印旧/新配置值，
	// 避免 Admin/Cluster/SSL 等配置段中的密码、TOTP、密钥等凭据泄露到日志。
	for _, change := range changes {
		rm.log.Infof("Config change: %s [%s] - %s",
			change.Field, change.Level, change.Description)
	}

	// 第二阶段：根据变更级别决定是否需要重载
	if maxLevel == NoReloadNeeded {
		rm.log.Info("No reload needed, only logging configuration changes")
		return newConfig, nil
	}

	// 第三阶段：验证配置
	if errs := ValidateConfig(newConfig); len(errs) > 0 {
		rm.mutex.Lock()
		rm.errorCount++
		rm.mutex.Unlock()
		return nil, fmt.Errorf("configuration validation failed: %v", errs)
	}

	activeConfig, err := runtimeReloadConfig(oldConfig, newConfig, changes)
	if err == nil {
		if errs := ValidateConfig(activeConfig); len(errs) > 0 {
			err = fmt.Errorf("active configuration validation failed: %v", errs)
		}
	}
	if err != nil {
		rm.mutex.Lock()
		rm.errorCount++
		rm.mutex.Unlock()
		return nil, err
	}
	rm.log.Infof("Starting reload of %d components (level: %s)", len(components), maxLevel)

	// 第四阶段：验证所有组件
	for _, component := range components {
		if err := component.Validate(activeConfig); err != nil {
			rm.mutex.Lock()
			rm.errorCount++
			rm.mutex.Unlock()
			return nil, fmt.Errorf("component %s validation failed: %w", component.GetName(), err)
		}
	}

	rm.log.Info("All components validated successfully")

	for i, component := range components {
		if err := component.Reload(activeConfig); err != nil {
			reloadErr := fmt.Errorf("component %s reload failed: %w", component.GetName(), err)
			// 失败组件也可能已修改内部状态，因此一并尝试回滚。
			for j := i; j >= 0; j-- {
				if rollbackErr := components[j].Reload(oldConfig); rollbackErr != nil {
					reloadErr = errors.Join(reloadErr, fmt.Errorf("component %s rollback failed: %w", components[j].GetName(), rollbackErr))
				}
			}
			rm.mutex.Lock()
			rm.errorCount++
			rm.mutex.Unlock()
			return nil, reloadErr
		}
		rm.log.Infof("Successfully reloaded component: %s", component.GetName())
	}

	duration := time.Since(startTime)

	rm.mutex.Lock()
	rm.successCount++
	for _, change := range changes {
		if change.Level != HardReload {
			continue
		}
		found := false
		for _, field := range rm.restartFields {
			if field == change.Field {
				found = true
				break
			}
		}
		if !found {
			rm.restartFields = append(rm.restartFields, change.Field)
		}
	}
	restartFields := append([]string(nil), rm.restartFields...)
	rm.mutex.Unlock()
	if len(restartFields) > 0 {
		rm.log.Warnf("Restart required to activate configuration fields: %v", restartFields)
	}
	rm.log.Infof("Successfully reloaded all %d components in %v", len(components), duration)

	return activeConfig, nil
}

// GetStats 获取重载统计信息
func (rm *ReloadManager) GetStats() map[string]interface{} {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	return map[string]interface{}{
		"component_count":  len(rm.components),
		"reload_count":     rm.reloadCount,
		"success_count":    rm.successCount,
		"error_count":      rm.errorCount,
		"last_reload_time": rm.lastReloadTime,
		"component_names":  rm.getComponentNames(),
		"restart_required": len(rm.restartFields) > 0,
		"restart_fields":   append([]string{}, rm.restartFields...),
	}
}

// getComponentNames 获取组件名称列表
func (rm *ReloadManager) getComponentNames() []string {
	var names []string
	for _, component := range rm.components {
		names = append(names, component.GetName())
	}
	return names
}

// GetComponents 获取所有注册的组件
func (rm *ReloadManager) GetComponents() []ReloadableComponent {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	components := make([]ReloadableComponent, len(rm.components))
	copy(components, rm.components)
	return components
}

// ValidateAllComponents 验证所有组件是否支持新配置
func (rm *ReloadManager) ValidateAllComponents(newConfig *Config) error {
	for _, component := range rm.snapshotComponents() {
		if err := component.Validate(newConfig); err != nil {
			return fmt.Errorf("component %s validation failed: %w", component.GetName(), err)
		}
	}

	return nil
}

// ReloadComponent 重载指定组件
func (rm *ReloadManager) ReloadComponent(componentName string, newConfig *Config) error {
	rm.reloadMutex.Lock()
	defer rm.reloadMutex.Unlock()
	for _, component := range rm.snapshotComponents() {
		if component.GetName() == componentName {
			// 先验证
			if err := component.Validate(newConfig); err != nil {
				return fmt.Errorf("component validation failed: %w", err)
			}

			// 再重载
			if err := component.Reload(newConfig); err != nil {
				return fmt.Errorf("component reload failed: %w", err)
			}

			rm.log.Infof("Successfully reloaded component: %s", componentName)
			return nil
		}
	}

	return fmt.Errorf("component not found: %s", componentName)
}

// IsComponentRegistered 检查组件是否已注册
func (rm *ReloadManager) IsComponentRegistered(componentName string) bool {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	for _, component := range rm.components {
		if component.GetName() == componentName {
			return true
		}
	}

	return false
}
