package config

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ConfigVersion 配置版本信息
type ConfigVersion struct {
	ID          string    `json:"id"`             // 版本唯一ID
	Version     int       `json:"version"`        // 版本号
	Timestamp   time.Time `json:"timestamp"`      // 创建时间
	Hash        string    `json:"hash"`           // 配置文件MD5哈希
	FilePath    string    `json:"file_path"`      // 备份文件路径
	Size        int64     `json:"size"`           // 文件大小
	Author      string    `json:"author"`         // 作者（谁创建的备份）
	Description string    `json:"description"`    // 版本描述/注释
	IsAuto      bool      `json:"is_auto"`        // 是否为自动备份
	IsDaily     bool      `json:"is_daily"`       // 是否为按天备份
	Date        string    `json:"date,omitempty"` // 日期（用于按天备份，格式：2006-01-02）
}

// VersionManager 版本管理器
type VersionManager struct {
	configFile string
	configDir  string
	configBase string
	versions   []*ConfigVersion
	versionMap map[string]*ConfigVersion // id -> version
	mutex      sync.RWMutex
	log        *logrus.Entry

	// 配置
	maxVersions     int  // 最多保留的版本数
	maxDailyBackups int  // 最多保留的按天备份数
	autoBackup      bool // 是否自动备份
}

// NewVersionManager 创建版本管理器
func NewVersionManager(configFile string) *VersionManager {
	configDir := filepath.Dir(configFile)
	configBase := filepath.Base(configFile)

	return &VersionManager{
		configFile:      configFile,
		configDir:       configDir,
		configBase:      configBase,
		versions:        make([]*ConfigVersion, 0),
		versionMap:      make(map[string]*ConfigVersion),
		maxVersions:     10, // 默认保留10个版本
		maxDailyBackups: 10, // 默认保留10个按天备份
		autoBackup:      true,
		log: logrus.WithFields(logrus.Fields{
			"component": "config_version",
		}),
	}
}

// LoadVersions 加载所有版本信息
func (vm *VersionManager) LoadVersions() error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// 清空现有数据
	vm.versions = make([]*ConfigVersion, 0)
	vm.versionMap = make(map[string]*ConfigVersion)

	// 加载版本备份
	if err := vm.loadVersionBackups(); err != nil {
		vm.log.Errorf("Failed to load version backups: %v", err)
	}

	// 加载按天备份
	if err := vm.loadDailyBackups(); err != nil {
		vm.log.Errorf("Failed to load daily backups: %v", err)
	}

	// 按时间排序（最新的在前）
	vm.sortVersions()

	vm.log.Infof("Loaded %d config versions", len(vm.versions))
	return nil
}

// loadVersionBackups 加载版本备份
func (vm *VersionManager) loadVersionBackups() error {
	pattern := filepath.Join(vm.configDir, vm.configBase+".backup.v*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob backup files: %w", err)
	}

	for _, file := range files {
		base := filepath.Base(file)
		var version int
		if _, err := fmt.Sscanf(base, vm.configBase+".backup.v%d", &version); err != nil {
			continue
		}

		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		// 计算哈希
		hash, err := vm.calculateFileHash(file)
		if err != nil {
			vm.log.Warnf("Failed to calculate hash for %s: %v", file, err)
			hash = ""
		}

		cv := &ConfigVersion{
			ID:        vm.generateID("v", version),
			Version:   version,
			Timestamp: info.ModTime(),
			Hash:      hash,
			FilePath:  file,
			Size:      info.Size(),
			IsAuto:    true,
			IsDaily:   false,
		}

		vm.versions = append(vm.versions, cv)
		vm.versionMap[cv.ID] = cv
	}

	return nil
}

// loadDailyBackups 加载按天备份
func (vm *VersionManager) loadDailyBackups() error {
	pattern := filepath.Join(vm.configDir, vm.configBase+".backup.????-??-??")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob daily backup files: %w", err)
	}

	for _, file := range files {
		base := filepath.Base(file)
		var dateStr string
		if _, err := fmt.Sscanf(base, vm.configBase+".backup.%s", &dateStr); err != nil {
			continue
		}

		// 解析日期
		_, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}

		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		// 计算哈希
		hash, err := vm.calculateFileHash(file)
		if err != nil {
			vm.log.Warnf("Failed to calculate hash for %s: %v", file, err)
			hash = ""
		}

		cv := &ConfigVersion{
			ID:        fmt.Sprintf("daily-%s", dateStr),
			Version:   -1, // 按天备份没有版本号
			Timestamp: info.ModTime(),
			Hash:      hash,
			FilePath:  file,
			Size:      info.Size(),
			IsAuto:    true,
			IsDaily:   true,
			Date:      dateStr,
		}

		vm.versions = append(vm.versions, cv)
		vm.versionMap[cv.ID] = cv
	}

	return nil
}

// sortVersions 按时间排序版本（最新的在前）
func (vm *VersionManager) sortVersions() {
	sort.Slice(vm.versions, func(i, j int) bool {
		return vm.versions[i].Timestamp.After(vm.versions[j].Timestamp)
	})
}

// GetVersions 获取所有版本
func (vm *VersionManager) GetVersions() []*ConfigVersion {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	// 返回副本
	result := make([]*ConfigVersion, len(vm.versions))
	copy(result, vm.versions)
	return result
}

// GetVersion 获取指定版本
func (vm *VersionManager) GetVersion(id string) *ConfigVersion {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	return vm.versionMap[id]
}

// GetVersionContent 获取版本内容
func (vm *VersionManager) GetVersionContent(id string) (map[string]interface{}, error) {
	vm.mutex.RLock()
	version := vm.versionMap[id]
	vm.mutex.RUnlock()

	if version == nil {
		return nil, fmt.Errorf("version not found: %s", id)
	}

	// 读取备份文件
	data, err := os.ReadFile(version.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file: %w", err)
	}

	// 解析JSON
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
}

// CreateVersion 创建新版本（手动备份）
func (vm *VersionManager) CreateVersion(author, description string) (*ConfigVersion, error) {
	// 读取当前配置文件
	data, err := os.ReadFile(vm.configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("config file is empty")
	}

	// 计算哈希
	hash := vm.calculateHash(data)

	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// 找到最大版本号
	maxVersion := 0
	for _, v := range vm.versions {
		if v.Version > maxVersion {
			maxVersion = v.Version
		}
	}

	// 创建新版本
	newVersion := maxVersion + 1
	versionID := vm.generateID("v", newVersion)
	backupFile := filepath.Join(vm.configDir, fmt.Sprintf("%s.backup.v%d", vm.configBase, newVersion))

	// 写入备份文件
	if err := writeFileAtomically(backupFile, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write backup file: %w", err)
	}

	info, _ := os.Stat(backupFile)
	cv := &ConfigVersion{
		ID:          versionID,
		Version:     newVersion,
		Timestamp:   time.Now(),
		Hash:        hash,
		FilePath:    backupFile,
		Size:        info.Size(),
		Author:      author,
		Description: description,
		IsAuto:      false,
		IsDaily:     false,
	}

	vm.versions = append([]*ConfigVersion{cv}, vm.versions...)
	vm.versionMap[cv.ID] = cv

	// 清理旧版本
	vm.cleanupOldVersions()

	vm.log.Infof("Created config version %d by %s: %s", newVersion, author, description)
	return cv, nil
}

// RollbackToVersion 回滚到指定版本
func (vm *VersionManager) RollbackToVersion(id string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	version := vm.versionMap[id]
	if version == nil {
		return fmt.Errorf("version not found: %s", id)
	}

	// 先备份当前配置
	if err := vm.backupCurrentConfig("auto-rollback", "Automatic backup before rollback"); err != nil {
		vm.log.Warnf("Failed to backup current config before rollback: %v", err)
	}

	// 读取备份文件
	data, err := os.ReadFile(version.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// 写入到配置文件
	if err := writeFileAtomically(vm.configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	vm.log.Infof("Rolled back to version %d (%s)", version.Version, version.Timestamp.Format(time.RFC3339))
	return nil
}

// CompareVersions 比较两个版本的内容差异
func (vm *VersionManager) CompareVersions(id1, id2 string) (map[string]DiffChange, error) {
	// 读取两个版本的内容
	config1, err := vm.GetVersionContent(id1)
	if err != nil {
		return nil, fmt.Errorf("failed to get version %s content: %w", id1, err)
	}

	config2, err := vm.GetVersionContent(id2)
	if err != nil {
		return nil, fmt.Errorf("failed to get version %s content: %w", id2, err)
	}

	// 计算差异
	changes := make(map[string]DiffChange)
	vm.compareMaps(config1, config2, "", changes)

	return changes, nil
}

// DiffChange 差异变更（用于版本比较）
type DiffChange struct {
	Path       string      `json:"path"`
	OldValue   interface{} `json:"old_value,omitempty"`
	NewValue   interface{} `json:"new_value,omitempty"`
	ChangeType string      `json:"change_type"` // added, removed, modified
}

// compareMaps 递归比较两个map
func (vm *VersionManager) compareMaps(m1, m2 map[string]interface{}, prefix string, changes map[string]DiffChange) {
	// 检查所有键
	allKeys := make(map[string]bool)
	for k := range m1 {
		allKeys[k] = true
	}
	for k := range m2 {
		allKeys[k] = true
	}

	for key := range allKeys {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		v1, ok1 := m1[key]
		v2, ok2 := m2[key]

		if !ok1 {
			// 新增
			changes[path] = DiffChange{
				Path:       path,
				NewValue:   v2,
				ChangeType: "added",
			}
		} else if !ok2 {
			// 删除
			changes[path] = DiffChange{
				Path:       path,
				OldValue:   v1,
				ChangeType: "removed",
			}
		} else {
			// 比较值
			if vm.isEqual(v1, v2) {
				continue
			}

			// 检查是否都是map
			map1, ok1Map := v1.(map[string]interface{})
			map2, ok2Map := v2.(map[string]interface{})

			if ok1Map && ok2Map {
				// 递归比较
				vm.compareMaps(map1, map2, path, changes)
			} else {
				// 值不同
				changes[path] = DiffChange{
					Path:       path,
					OldValue:   v1,
					NewValue:   v2,
					ChangeType: "modified",
				}
			}
		}
	}
}

// isEqual 检查两个值是否相等
func (vm *VersionManager) isEqual(v1, v2 interface{}) bool {
	// JSON序列化后比较
	j1, err1 := json.Marshal(v1)
	j2, err2 := json.Marshal(v2)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(j1) == string(j2)
}

// backupCurrentConfig 备份当前配置
func (vm *VersionManager) backupCurrentConfig(author, description string) error {
	data, err := os.ReadFile(vm.configFile)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	// 找到最大版本号
	maxVersion := 0
	for _, v := range vm.versions {
		if v.Version > maxVersion {
			maxVersion = v.Version
		}
	}

	// 创建备份
	newVersion := maxVersion + 1
	versionID := vm.generateID("v", newVersion)
	backupFile := filepath.Join(vm.configDir, fmt.Sprintf("%s.backup.v%d", vm.configBase, newVersion))

	if err := writeFileAtomically(backupFile, data, 0644); err != nil {
		return err
	}

	info, _ := os.Stat(backupFile)
	cv := &ConfigVersion{
		ID:          versionID,
		Version:     newVersion,
		Timestamp:   time.Now(),
		Hash:        vm.calculateHash(data),
		FilePath:    backupFile,
		Size:        info.Size(),
		Author:      author,
		Description: description,
		IsAuto:      true,
		IsDaily:     false,
	}

	vm.versions = append([]*ConfigVersion{cv}, vm.versions...)
	vm.versionMap[cv.ID] = cv

	return nil
}

// cleanupOldVersions 清理旧版本
func (vm *VersionManager) cleanupOldVersions() {
	// 统计版本备份和按天备份
	versionBackups := make([]*ConfigVersion, 0)
	dailyBackups := make([]*ConfigVersion, 0)

	for _, v := range vm.versions {
		if v.IsDaily {
			dailyBackups = append(dailyBackups, v)
		} else {
			versionBackups = append(versionBackups, v)
		}
	}

	// 清理版本备份（保留手动创建的）
	if len(versionBackups) > vm.maxVersions {
		// 保留手动创建的版本
		manualVersions := make([]*ConfigVersion, 0)
		autoVersions := make([]*ConfigVersion, 0)

		for _, v := range versionBackups {
			if !v.IsAuto {
				manualVersions = append(manualVersions, v)
			} else {
				autoVersions = append(autoVersions, v)
			}
		}

		// 如果超过限制，删除最旧的自动版本
		maxAutoVersions := vm.maxVersions - len(manualVersions)
		if len(autoVersions) > maxAutoVersions && maxAutoVersions > 0 {
			for i := maxAutoVersions; i < len(autoVersions); i++ {
				if err := os.Remove(autoVersions[i].FilePath); err != nil && !os.IsNotExist(err) {
					vm.log.Warnf("Failed to remove old version backup: %v", err)
				}
				delete(vm.versionMap, autoVersions[i].ID)
			}
			autoVersions = autoVersions[:maxAutoVersions]
		}

		// 重新组合
		versionBackups = append(manualVersions, autoVersions...)
	}

	// 清理按天备份
	if len(dailyBackups) > vm.maxDailyBackups {
		for i := vm.maxDailyBackups; i < len(dailyBackups); i++ {
			if err := os.Remove(dailyBackups[i].FilePath); err != nil && !os.IsNotExist(err) {
				vm.log.Warnf("Failed to remove old daily backup: %v", err)
			}
			delete(vm.versionMap, dailyBackups[i].ID)
		}
		dailyBackups = dailyBackups[:vm.maxDailyBackups]
	}

	// 重新组合并排序
	vm.versions = append(versionBackups, dailyBackups...)
	vm.sortVersions()
}

// calculateHash 计算数据哈希
func (vm *VersionManager) calculateHash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// calculateFileHash 计算文件哈希
func (vm *VersionManager) calculateFileHash(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return vm.calculateHash(data), nil
}

// generateID 生成版本ID
func (vm *VersionManager) generateID(prefix string, value int) string {
	if prefix == "d" {
		// 按天备份使用日期字符串作为value
		return fmt.Sprintf("daily-%s", time.Now().Format("2006-01-02"))
	}
	return fmt.Sprintf("%s%d-%d", prefix, value, time.Now().Unix())
}

// GetCurrentHash 获取当前配置文件的哈希
func (vm *VersionManager) GetCurrentHash() (string, error) {
	data, err := os.ReadFile(vm.configFile)
	if err != nil {
		return "", err
	}
	return vm.calculateHash(data), nil
}

// DeleteVersion 删除指定版本
func (vm *VersionManager) DeleteVersion(id string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	version := vm.versionMap[id]
	if version == nil {
		return fmt.Errorf("version not found: %s", id)
	}

	// 不允许删除当前正在使用的配置
	currentHash, err := vm.GetCurrentHash()
	if err == nil && currentHash == version.Hash {
		return fmt.Errorf("cannot delete current active version")
	}

	// 删除文件
	if err := os.Remove(version.FilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete backup file: %w", err)
	}

	// 从内存中删除
	delete(vm.versionMap, id)
	for i, v := range vm.versions {
		if v.ID == id {
			vm.versions = append(vm.versions[:i], vm.versions[i+1:]...)
			break
		}
	}

	vm.log.Infof("Deleted config version %s", id)
	return nil
}

// UpdateVersionDescription 更新版本描述
func (vm *VersionManager) UpdateVersionDescription(id, description string) error {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	version := vm.versionMap[id]
	if version == nil {
		return fmt.Errorf("version not found: %s", id)
	}

	version.Description = description
	return nil
}

// ExportVersion 导出版本到指定路径
func (vm *VersionManager) ExportVersion(id, exportPath string) error {
	vm.mutex.RLock()
	version := vm.versionMap[id]
	vm.mutex.RUnlock()

	if version == nil {
		return fmt.Errorf("version not found: %s", id)
	}

	// 读取备份文件
	data, err := os.ReadFile(version.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// 写入到导出路径
	if err := writeFileAtomically(exportPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	vm.log.Infof("Exported version %s to %s", id, exportPath)
	return nil
}

// ImportVersion 从文件导入版本
func (vm *VersionManager) ImportVersion(importPath, author, description string) (*ConfigVersion, error) {
	// 读取导入文件
	data, err := os.ReadFile(importPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read import file: %w", err)
	}

	// 验证配置格式
	var testConfig map[string]interface{}
	if err := json.Unmarshal(data, &testConfig); err != nil {
		return nil, fmt.Errorf("invalid config format: %w", err)
	}

	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	// 找到最大版本号
	maxVersion := 0
	for _, v := range vm.versions {
		if v.Version > maxVersion {
			maxVersion = v.Version
		}
	}

	// 创建新版本
	newVersion := maxVersion + 1
	versionID := fmt.Sprintf("imported-v%d-%d", newVersion, time.Now().Unix())
	backupFile := filepath.Join(vm.configDir, fmt.Sprintf("%s.backup.v%d", vm.configBase, newVersion))

	// 写入备份文件
	if err := writeFileAtomically(backupFile, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write backup file: %w", err)
	}

	info, _ := os.Stat(backupFile)
	cv := &ConfigVersion{
		ID:          versionID,
		Version:     newVersion,
		Timestamp:   time.Now(),
		Hash:        vm.calculateHash(data),
		FilePath:    backupFile,
		Size:        info.Size(),
		Author:      author,
		Description: fmt.Sprintf("[IMPORT] %s", description),
		IsAuto:      false,
		IsDaily:     false,
	}

	vm.versions = append([]*ConfigVersion{cv}, vm.versions...)
	vm.versionMap[cv.ID] = cv

	vm.log.Infof("Imported config version %d from %s", newVersion, importPath)
	return cv, nil
}

// GetStats 获取版本统计信息
func (vm *VersionManager) GetStats() map[string]interface{} {
	vm.mutex.RLock()
	defer vm.mutex.RUnlock()

	manualCount := 0
	autoCount := 0
	dailyCount := 0
	totalSize := int64(0)

	for _, v := range vm.versions {
		if v.IsDaily {
			dailyCount++
		} else if v.IsAuto {
			autoCount++
		} else {
			manualCount++
		}
		totalSize += v.Size
	}

	return map[string]interface{}{
		"total_versions":  len(vm.versions),
		"manual_versions": manualCount,
		"auto_versions":   autoCount,
		"daily_versions":  dailyCount,
		"total_size":      totalSize,
		"max_versions":    vm.maxVersions,
		"config_file":     vm.configFile,
	}
}
