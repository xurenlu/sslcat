package threatintel

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

// ThreatIntelDB 威胁情报数据库
type ThreatIntelDB struct {
	db       *sql.DB
	log      *logrus.Entry
	stopChan chan struct{} // 停止清理任务
}

// NewThreatIntelDB 创建威胁情报数据库
func NewThreatIntelDB(dbPath string) (*ThreatIntelDB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// 创建表
	if err := createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create tables: %v", err)
	}

	tidb := &ThreatIntelDB{
		db: db,
		log: logrus.WithFields(logrus.Fields{
			"component": "threat_intel_db",
		}),
		stopChan: make(chan struct{}),
	}

	// 启动自动清理任务
	go tidb.startCleanupTask()

	return tidb, nil
}

// createTables 创建数据库表
func createTables(db *sql.DB) error {
	// 创建IOC表
	createIOCTable := `
	CREATE TABLE IF NOT EXISTS iocs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		value TEXT NOT NULL,
		type TEXT NOT NULL,
		threat_level INTEGER NOT NULL,
		source TEXT NOT NULL,
		description TEXT,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		tags TEXT,
		confidence REAL NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(value, type)
	)`

	// 创建威胁情报源表
	createSourceTable := `
	CREATE TABLE IF NOT EXISTS threat_sources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		url TEXT NOT NULL,
		api_key TEXT,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		update_freq INTEGER NOT NULL,
		last_update DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	// 创建更新日志表
	createUpdateLogTable := `
	CREATE TABLE IF NOT EXISTS update_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		source_name TEXT NOT NULL,
		status TEXT NOT NULL,
		message TEXT,
		iocs_added INTEGER DEFAULT 0,
		iocs_updated INTEGER DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	// 创建索引
	createIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)",
		"CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)",
		"CREATE INDEX IF NOT EXISTS idx_iocs_threat_level ON iocs(threat_level)",
		"CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source)",
		"CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen)",
		"CREATE INDEX IF NOT EXISTS idx_sources_name ON threat_sources(name)",
		"CREATE INDEX IF NOT EXISTS idx_update_logs_source ON update_logs(source_name)",
	}

	// 执行创建表语句
	if _, err := db.Exec(createIOCTable); err != nil {
		return fmt.Errorf("failed to create iocs table: %v", err)
	}

	if _, err := db.Exec(createSourceTable); err != nil {
		return fmt.Errorf("failed to create threat_sources table: %v", err)
	}

	if _, err := db.Exec(createUpdateLogTable); err != nil {
		return fmt.Errorf("failed to create update_logs table: %v", err)
	}

	// 创建索引
	for _, indexSQL := range createIndexes {
		if _, err := db.Exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create index: %v", err)
		}
	}

	return nil
}

// Close 关闭数据库连接
func (tidb *ThreatIntelDB) Close() error {
	if tidb.stopChan != nil {
		close(tidb.stopChan)
	}
	return tidb.db.Close()
}

// startCleanupTask 启动清理任务
func (tidb *ThreatIntelDB) startCleanupTask() {
	ticker := time.NewTicker(59 * time.Minute) // 使用质数间隔避免与其他定时器同时触发
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 清理30天前的数据
			if err := tidb.CleanupOldData(30 * 24 * time.Hour); err != nil {
				tidb.log.Errorf("Failed to cleanup old data: %v", err)
			}
			// 限制数据库大小
			if err := tidb.LimitDatabaseSize(); err != nil {
				tidb.log.Errorf("Failed to limit database size: %v", err)
			}
		case <-tidb.stopChan:
			tidb.log.Info("Threat intel database cleanup task stopped")
			return
		}
	}
}

// SaveIOC 保存IOC到数据库
func (tidb *ThreatIntelDB) SaveIOC(ioc *IOC) error {
	// 将tags转换为JSON字符串
	tagsJSON, err := json.Marshal(ioc.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %v", err)
	}

	query := `
	INSERT OR REPLACE INTO iocs 
	(value, type, threat_level, source, description, first_seen, last_seen, tags, confidence, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	_, err = tidb.db.Exec(query,
		ioc.Value,
		ioc.Type,
		int(ioc.ThreatLevel),
		ioc.Source,
		ioc.Description,
		ioc.FirstSeen,
		ioc.LastSeen,
		string(tagsJSON),
		ioc.Confidence,
	)

	if err != nil {
		return fmt.Errorf("failed to save IOC: %v", err)
	}

	return nil
}

// GetIOC 获取IOC
func (tidb *ThreatIntelDB) GetIOC(value, iocType string) (*IOC, error) {
	query := `
	SELECT value, type, threat_level, source, description, first_seen, last_seen, tags, confidence
	FROM iocs 
	WHERE value = ? AND type = ?`

	row := tidb.db.QueryRow(query, value, iocType)

	var ioc IOC
	var tagsJSON string
	var threatLevel int

	err := row.Scan(
		&ioc.Value,
		&ioc.Type,
		&threatLevel,
		&ioc.Source,
		&ioc.Description,
		&ioc.FirstSeen,
		&ioc.LastSeen,
		&tagsJSON,
		&ioc.Confidence,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get IOC: %v", err)
	}

	// 转换威胁级别
	ioc.ThreatLevel = ThreatLevel(threatLevel)

	// 解析tags
	if err := json.Unmarshal([]byte(tagsJSON), &ioc.Tags); err != nil {
		tidb.log.Warnf("Failed to unmarshal tags: %v", err)
		ioc.Tags = []string{}
	}

	return &ioc, nil
}

// SaveSource 保存威胁情报源
func (tidb *ThreatIntelDB) SaveSource(source *ThreatIntelSource) error {
	query := `
	INSERT OR REPLACE INTO threat_sources 
	(name, url, api_key, enabled, update_freq, last_update, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	_, err := tidb.db.Exec(query,
		source.Name,
		source.URL,
		source.APIKey,
		source.Enabled,
		int(source.UpdateFreq.Seconds()),
		source.LastUpdate,
	)

	if err != nil {
		return fmt.Errorf("failed to save source: %v", err)
	}

	return nil
}

// GetSource 获取威胁情报源
func (tidb *ThreatIntelDB) GetSource(name string) (*ThreatIntelSource, error) {
	query := `
	SELECT name, url, api_key, enabled, update_freq, last_update
	FROM threat_sources 
	WHERE name = ?`

	row := tidb.db.QueryRow(query, name)

	var source ThreatIntelSource
	var updateFreqSeconds int
	var lastUpdate sql.NullTime

	err := row.Scan(
		&source.Name,
		&source.URL,
		&source.APIKey,
		&source.Enabled,
		&updateFreqSeconds,
		&lastUpdate,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get source: %v", err)
	}

	// 转换时间
	source.UpdateFreq = time.Duration(updateFreqSeconds) * time.Second
	if lastUpdate.Valid {
		source.LastUpdate = lastUpdate.Time
	}
	source.IOCs = make(map[string]*IOC)

	return &source, nil
}

// LogUpdate 记录更新日志
func (tidb *ThreatIntelDB) LogUpdate(sourceName, status, message string, iocsAdded, iocsUpdated int) error {
	query := `
	INSERT INTO update_logs 
	(source_name, status, status, message, iocs_added, iocs_updated, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`

	_, err := tidb.db.Exec(query, sourceName, status, message, iocsAdded, iocsUpdated)
	if err != nil {
		return fmt.Errorf("failed to log update: %v", err)
	}

	return nil
}

// GetThreatStats 获取威胁统计
func (tidb *ThreatIntelDB) GetThreatStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// 总IOC数量
	var totalIOCs int
	query := "SELECT COUNT(*) FROM iocs"
	if err := tidb.db.QueryRow(query).Scan(&totalIOCs); err != nil {
		tidb.log.Errorf("Failed to get total IOCs: %v", err)
	}
	stats["total_iocs"] = totalIOCs

	// 按类型统计
	typeStats := make(map[string]int)
	query = "SELECT type, COUNT(*) FROM iocs GROUP BY type"
	rows, err := tidb.db.Query(query)
	if err != nil {
		tidb.log.Errorf("Failed to get type stats: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var iocType string
			var count int
			if err := rows.Scan(&iocType, &count); err == nil {
				typeStats[iocType] = count
			}
		}
	}
	stats["by_type"] = typeStats

	// 按威胁级别统计
	levelStats := make(map[string]int)
	query = "SELECT threat_level, COUNT(*) FROM iocs GROUP BY threat_level"
	rows, err = tidb.db.Query(query)
	if err != nil {
		tidb.log.Errorf("Failed to get level stats: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var level int
			var count int
			if err := rows.Scan(&level, &count); err == nil {
				levelStats[fmt.Sprintf("level_%d", level)] = count
			}
		}
	}
	stats["by_level"] = levelStats

	// 按来源统计
	sourceStats := make(map[string]int)
	query = "SELECT source, COUNT(*) FROM iocs GROUP BY source"
	rows, err = tidb.db.Query(query)
	if err != nil {
		tidb.log.Errorf("Failed to get source stats: %v", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var source string
			var count int
			if err := rows.Scan(&source, &count); err == nil {
				sourceStats[source] = count
			}
		}
	}
	stats["by_source"] = sourceStats

	return stats
}

// CleanupOldData 清理过期数据
func (tidb *ThreatIntelDB) CleanupOldData(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge)

	// 删除过期的IOC
	query := "DELETE FROM iocs WHERE last_seen < ?"
	result, err := tidb.db.Exec(query, cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup old IOCs: %v", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		tidb.log.Infof("Cleaned up %d old IOCs", rowsAffected)
	}

	// 删除过期的更新日志
	query = "DELETE FROM update_logs WHERE updated_at < ?"
	result, err = tidb.db.Exec(query, cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup old logs: %v", err)
	}

	rowsAffected, _ = result.RowsAffected()
	if rowsAffected > 0 {
		tidb.log.Infof("Cleaned up %d old update logs", rowsAffected)
	}

	return nil
}

// LimitDatabaseSize 限制数据库大小
func (tidb *ThreatIntelDB) LimitDatabaseSize() error {
	maxIOCs := 100000      // 最多保留10万条IOC
	maxUpdateLogs := 10000 // 最多保留1万条更新日志

	// 检查IOC数量
	var iocCount int
	query := "SELECT COUNT(*) FROM iocs"
	if err := tidb.db.QueryRow(query).Scan(&iocCount); err != nil {
		return fmt.Errorf("failed to count IOCs: %v", err)
	}

	// 如果超过限制，删除最旧的
	if iocCount > maxIOCs {
		deleteCount := iocCount - maxIOCs
		query = `DELETE FROM iocs WHERE id IN (
			SELECT id FROM iocs ORDER BY last_seen ASC LIMIT ?
		)`
		result, err := tidb.db.Exec(query, deleteCount)
		if err != nil {
			return fmt.Errorf("failed to limit IOCs: %v", err)
		}
		rowsAffected, _ := result.RowsAffected()
		tidb.log.Warnf("Limited IOC database size: deleted %d oldest entries (total: %d → %d)",
			rowsAffected, iocCount, iocCount-int(rowsAffected))
	}

	// 检查更新日志数量
	var logCount int
	query = "SELECT COUNT(*) FROM update_logs"
	if err := tidb.db.QueryRow(query).Scan(&logCount); err != nil {
		return fmt.Errorf("failed to count update logs: %v", err)
	}

	// 如果超过限制，删除最旧的
	if logCount > maxUpdateLogs {
		deleteCount := logCount - maxUpdateLogs
		query = `DELETE FROM update_logs WHERE id IN (
			SELECT id FROM update_logs ORDER BY updated_at ASC LIMIT ?
		)`
		result, err := tidb.db.Exec(query, deleteCount)
		if err != nil {
			return fmt.Errorf("failed to limit update logs: %v", err)
		}
		rowsAffected, _ := result.RowsAffected()
		tidb.log.Warnf("Limited update log size: deleted %d oldest entries (total: %d → %d)",
			rowsAffected, logCount, logCount-int(rowsAffected))
	}

	return nil
}
