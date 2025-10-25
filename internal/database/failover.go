package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FailoverManager 数据库故障转移管理器
type FailoverManager struct {
	dataDir      string
	logger       *log.Logger
	backupDir    string
	lastBackup   time.Time
	maxBackups   int           // 最多保留多少个备份
	maxBackupAge time.Duration // 最多保留多久的备份
}

// NewFailoverManager 创建故障转移管理器
func NewFailoverManager(dataDir string) *FailoverManager {
	backupDir := filepath.Join(dataDir, "backups")

	return &FailoverManager{
		dataDir:      dataDir,
		backupDir:    backupDir,
		logger:       log.New(os.Stdout, "[DB-FAILOVER] ", log.LstdFlags),
		maxBackups:   30,                  // 最多保留30个备份
		maxBackupAge: 90 * 24 * time.Hour, // 最多保留90天
	}
}

// CheckDatabaseIntegrity 检查数据库完整性
func (fm *FailoverManager) CheckDatabaseIntegrity() error {
	databases := []string{
		"users.db",
		"git_deploy.db",
		"deployments.db",
		"threat_intel.db",
	}

	var errors []error

	for _, dbName := range databases {
		dbPath := filepath.Join(fm.dataDir, dbName)
		if err := fm.checkSingleDatabase(dbPath); err != nil {
			fm.logger.Printf("数据库完整性检查失败: %s - %v", dbName, err)
			errors = append(errors, fmt.Errorf("%s: %w", dbName, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("数据库完整性检查失败: %v", errors)
	}

	return nil
}

// checkSingleDatabase 检查单个数据库
func (fm *FailoverManager) checkSingleDatabase(dbPath string) error {
	// 检查文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("数据库文件不存在: %s", dbPath)
	}

	// 检查文件是否可读
	file, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("无法打开数据库文件: %w", err)
	}
	defer file.Close()

	// 检查文件大小（至少应该有头部信息）
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("无法获取文件信息: %w", err)
	}

	if stat.Size() < 1024 { // SQLite 文件至少应该有 1KB
		return fmt.Errorf("数据库文件大小异常: %d bytes", stat.Size())
	}

	return nil
}

// CreateBackup 创建数据库备份
func (fm *FailoverManager) CreateBackup() error {
	// 确保备份目录存在
	if err := os.MkdirAll(fm.backupDir, 0755); err != nil {
		return fmt.Errorf("创建备份目录失败: %w", err)
	}

	// 创建时间戳
	timestamp := time.Now().Format("2006-01-02_15-04-05")

	databases := []string{
		"users.db",
		"git_deploy.db",
		"deployments.db",
		"threat_intel.db",
	}

	for _, dbName := range databases {
		sourcePath := filepath.Join(fm.dataDir, dbName)
		backupPath := filepath.Join(fm.backupDir, fmt.Sprintf("%s_%s", dbName, timestamp))

		// 检查源文件是否存在
		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			fm.logger.Printf("跳过不存在的数据库: %s", dbName)
			continue
		}

		// 复制文件
		if err := fm.copyFile(sourcePath, backupPath); err != nil {
			fm.logger.Printf("备份数据库失败: %s - %v", dbName, err)
			continue
		}

		fm.logger.Printf("成功备份数据库: %s -> %s", dbName, backupPath)
	}

	fm.lastBackup = time.Now()

	// 自动清理旧备份
	if err := fm.CleanupBackups(); err != nil {
		fm.logger.Printf("清理旧备份失败: %v", err)
	}

	return nil
}

// RestoreFromBackup 从备份恢复数据库
func (fm *FailoverManager) RestoreFromBackup() error {
	// 查找最新的备份
	backups, err := fm.findLatestBackups()
	if err != nil {
		return fmt.Errorf("查找备份失败: %w", err)
	}

	if len(backups) == 0 {
		return fmt.Errorf("没有找到可用的备份")
	}

	fm.logger.Printf("开始从备份恢复数据库...")

	for dbName, backupPath := range backups {
		targetPath := filepath.Join(fm.dataDir, dbName)

		// 备份当前文件（如果存在）
		if _, err := os.Stat(targetPath); err == nil {
			corruptedPath := targetPath + ".corrupted"
			if err := fm.copyFile(targetPath, corruptedPath); err != nil {
				fm.logger.Printf("备份损坏的数据库失败: %s - %v", dbName, err)
			}
		}

		// 恢复数据库
		if err := fm.copyFile(backupPath, targetPath); err != nil {
			fm.logger.Printf("恢复数据库失败: %s - %v", dbName, err)
			continue
		}

		fm.logger.Printf("成功恢复数据库: %s", dbName)
	}

	return nil
}

// findLatestBackups 查找最新的备份文件
func (fm *FailoverManager) findLatestBackups() (map[string]string, error) {
	entries, err := os.ReadDir(fm.backupDir)
	if err != nil {
		return nil, err
	}

	// 按数据库名称分组，找到最新的备份
	latestBackups := make(map[string]string)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()

		// 解析文件名格式: dbname_timestamp
		for _, dbName := range []string{"users.db", "git_deploy.db", "deployments.db", "threat_intel.db"} {
			if strings.HasPrefix(name, dbName+"_") {
				backupPath := filepath.Join(fm.backupDir, name)

				// 检查是否比当前备份更新
				if currentBackup, exists := latestBackups[dbName]; !exists {
					latestBackups[dbName] = backupPath
				} else {
					// 比较时间戳
					if fm.isNewerBackup(backupPath, currentBackup) {
						latestBackups[dbName] = backupPath
					}
				}
			}
		}
	}

	return latestBackups, nil
}

// isNewerBackup 判断备份文件是否更新
func (fm *FailoverManager) isNewerBackup(path1, path2 string) bool {
	stat1, err1 := os.Stat(path1)
	stat2, err2 := os.Stat(path2)

	if err1 != nil || err2 != nil {
		return false
	}

	return stat1.ModTime().After(stat2.ModTime())
}

// copyFile 复制文件
func (fm *FailoverManager) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = destFile.ReadFrom(sourceFile)
	return err
}

// AutoBackup 自动备份（定期执行）
func (fm *FailoverManager) AutoBackup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := fm.CreateBackup(); err != nil {
			fm.logger.Printf("自动备份失败: %v", err)
		}
	}
}

// CleanOldBackups 清理旧备份（按时间）
func (fm *FailoverManager) CleanOldBackups(keepDays int) error {
	entries, err := os.ReadDir(fm.backupDir)
	if err != nil {
		return err
	}

	cutoffTime := time.Now().AddDate(0, 0, -keepDays)
	deletedCount := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// 获取文件信息以检查修改时间
		fileInfo, err := entry.Info()
		if err != nil {
			fm.logger.Printf("获取文件信息失败: %s - %v", entry.Name(), err)
			continue
		}

		if fileInfo.ModTime().Before(cutoffTime) {
			backupPath := filepath.Join(fm.backupDir, entry.Name())
			if err := os.Remove(backupPath); err != nil {
				fm.logger.Printf("删除旧备份失败: %s - %v", entry.Name(), err)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		fm.logger.Printf("按时间清理: 删除了 %d 个旧备份（超过 %d 天）", deletedCount, keepDays)
	}

	return nil
}

// CleanupBackups 清理备份（按数量和时间）
func (fm *FailoverManager) CleanupBackups() error {
	entries, err := os.ReadDir(fm.backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 备份目录不存在，无需清理
		}
		return err
	}

	// 收集所有备份文件
	type backupFileInfo struct {
		path    string
		modTime time.Time
	}

	var backupFiles []backupFileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fileInfo, err := entry.Info()
		if err != nil {
			continue
		}

		backupFiles = append(backupFiles, backupFileInfo{
			path:    filepath.Join(fm.backupDir, entry.Name()),
			modTime: fileInfo.ModTime(),
		})
	}

	if len(backupFiles) == 0 {
		return nil
	}

	// 按修改时间排序（最新的在前）- 使用标准库排序
	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].modTime.After(backupFiles[j].modTime)
	})

	cutoffTime := time.Now().Add(-fm.maxBackupAge)
	deletedCount := 0

	// 清理策略：
	// 1. 保留最近 maxBackups 个文件
	// 2. 删除超过 maxBackupAge 的文件
	for i, backup := range backupFiles {
		shouldDelete := false

		// 超过数量限制
		if i >= fm.maxBackups {
			shouldDelete = true
		}

		// 超过时间限制
		if backup.modTime.Before(cutoffTime) {
			shouldDelete = true
		}

		if shouldDelete {
			if err := os.Remove(backup.path); err != nil {
				fm.logger.Printf("删除备份失败: %s - %v", backup.path, err)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		fm.logger.Printf("清理了 %d 个旧备份（保留 %d 个，最多 %d 天）",
			deletedCount, len(backupFiles)-deletedCount, int(fm.maxBackupAge.Hours()/24))
	}

	return nil
}
