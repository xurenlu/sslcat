package config

import (
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
	components []ReloadableComponent
	mutex      sync.RWMutex
	log        *logrus.Entry

	// 重载统计
	reloadCount    int64
	lastReloadTime time.Time
	successCount   int64
	errorCount     int64
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

// ReloadAll 重载所有组件
func (rm *ReloadManager) ReloadAll(oldConfig, newConfig *Config) error {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	startTime := time.Now()
	rm.reloadCount++
	rm.lastReloadTime = startTime

	rm.log.Infof("Starting reload of %d components", len(rm.components))

	// 第一阶段：验证所有组件
	for _, component := range rm.components {
		if err := component.Validate(newConfig); err != nil {
			rm.errorCount++
			return fmt.Errorf("component %s validation failed: %w", component.GetName(), err)
		}
	}

	rm.log.Info("All components validated successfully")

	// 第二阶段：重载所有组件
	var failedComponents []string
	for _, component := range rm.components {
		if err := component.Reload(newConfig); err != nil {
			rm.log.Errorf("Failed to reload component %s: %v", component.GetName(), err)
			failedComponents = append(failedComponents, component.GetName())
		} else {
			rm.log.Infof("Successfully reloaded component: %s", component.GetName())
		}
	}

	duration := time.Since(startTime)

	if len(failedComponents) > 0 {
		rm.errorCount++
		return fmt.Errorf("failed to reload components: %v", failedComponents)
	}

	rm.successCount++
	rm.log.Infof("Successfully reloaded all %d components in %v", len(rm.components), duration)

	return nil
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
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	for _, component := range rm.components {
		if err := component.Validate(newConfig); err != nil {
			return fmt.Errorf("component %s validation failed: %w", component.GetName(), err)
		}
	}

	return nil
}

// ReloadComponent 重载指定组件
func (rm *ReloadManager) ReloadComponent(componentName string, newConfig *Config) error {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	for _, component := range rm.components {
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
