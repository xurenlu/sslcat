package runner

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

// DeployDatabase Git部署数据库管理器
type DeployDatabase struct {
	db     *sql.DB
	dbPath string
	logger *logrus.Entry
}

// ContainerVersion 容器版本信息
type ContainerVersion struct {
	ID          int64     `json:"id"`
	AppName     string    `json:"app_name"`
	ContainerID string    `json:"container_id"`
	ImageName   string    `json:"image_name"`
	Port        int       `json:"port"`
	Status      string    `json:"status"` // "active" | "pending" | "stopping" | "stopped"
	CommitHash  string    `json:"commit_hash"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at"`
	StoppedAt   *time.Time `json:"stopped_at,omitempty"`
	HealthCheck bool      `json:"health_check"`
}

// NewDeployDatabase 创建部署数据库管理器
func NewDeployDatabase(dataDir string) (*DeployDatabase, error) {
	dbPath := filepath.Join(dataDir, "git_deploy.db")

	// 确保数据目录存在
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %v", err)
	}

	// 配置SQLite连接参数
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000&_timeout=30000&_busy_timeout=30000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %v", err)
	}

	// 配置连接池
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	deployDB := &DeployDatabase{
		db:     db,
		dbPath: dbPath,
		logger: logrus.WithField("component", "deploy_database"),
	}

	// 初始化数据库表
	if err := deployDB.initDatabase(); err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %v", err)
	}

	return deployDB, nil
}

// initDatabase 初始化数据库表
func (ddb *DeployDatabase) initDatabase() error {
	// 创建容器版本表
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS container_versions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		app_name TEXT NOT NULL,
		container_id TEXT NOT NULL,
		image_name TEXT NOT NULL,
		port INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		commit_hash TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		started_at DATETIME,
		stopped_at DATETIME,
		health_check BOOLEAN DEFAULT 0
	);
	`

	if _, err := ddb.db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("创建容器版本表失败: %v", err)
	}

	// 创建部署事件表
	createDeployEventsSQL := `
	CREATE TABLE IF NOT EXISTS deploy_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		app_name TEXT NOT NULL,
		deploy_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		old_container_id TEXT,
		new_container_id TEXT,
		old_port INTEGER,
		new_port INTEGER,
		status TEXT NOT NULL,
		message TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	if _, err := ddb.db.Exec(createDeployEventsSQL); err != nil {
		return fmt.Errorf("创建部署事件表失败: %v", err)
	}

	// 创建索引
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_cv_app_name ON container_versions(app_name);",
		"CREATE INDEX IF NOT EXISTS idx_cv_status ON container_versions(status);",
		"CREATE INDEX IF NOT EXISTS idx_cv_container_id ON container_versions(container_id);",
		"CREATE INDEX IF NOT EXISTS idx_de_app_name ON deploy_events(app_name);",
		"CREATE INDEX IF NOT EXISTS idx_de_deploy_id ON deploy_events(deploy_id);",
		"CREATE INDEX IF NOT EXISTS idx_de_created_at ON deploy_events(created_at);",
	}

	for _, indexSQL := range indexes {
		if _, err := ddb.db.Exec(indexSQL); err != nil {
			ddb.logger.Warnf("创建索引失败: %v", err)
		}
	}

	return nil
}

// AddContainerVersion 添加容器版本
func (ddb *DeployDatabase) AddContainerVersion(version *ContainerVersion) (int64, error) {
	result, err := ddb.db.Exec(`
		INSERT INTO container_versions 
		(app_name, container_id, image_name, port, status, commit_hash, started_at, health_check)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, version.AppName, version.ContainerID, version.ImageName, version.Port, 
	   version.Status, version.CommitHash, version.StartedAt, version.HealthCheck)

	if err != nil {
		return 0, fmt.Errorf("添加容器版本失败: %v", err)
	}

	return result.LastInsertId()
}

// GetActiveContainer 获取应用的活跃容器
func (ddb *DeployDatabase) GetActiveContainer(appName string) (*ContainerVersion, error) {
	var version ContainerVersion
	var stoppedAt sql.NullTime

	err := ddb.db.QueryRow(`
		SELECT id, app_name, container_id, image_name, port, status, 
		       COALESCE(commit_hash, ''), created_at, started_at, stopped_at, health_check
		FROM container_versions
		WHERE app_name = ? AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`, appName).Scan(
		&version.ID, &version.AppName, &version.ContainerID, &version.ImageName,
		&version.Port, &version.Status, &version.CommitHash, &version.CreatedAt,
		&version.StartedAt, &stoppedAt, &version.HealthCheck,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查询活跃容器失败: %v", err)
	}

	if stoppedAt.Valid {
		version.StoppedAt = &stoppedAt.Time
	}

	return &version, nil
}

// UpdateContainerStatus 更新容器状态
func (ddb *DeployDatabase) UpdateContainerStatus(containerID, status string) error {
	_, err := ddb.db.Exec(`
		UPDATE container_versions
		SET status = ?, stopped_at = CASE WHEN ? IN ('stopping', 'stopped') THEN CURRENT_TIMESTAMP ELSE stopped_at END
		WHERE container_id = ?
	`, status, status, containerID)

	if err != nil {
		return fmt.Errorf("更新容器状态失败: %v", err)
	}

	return nil
}

// UpdateContainerHealthCheck 更新容器健康检查状态
func (ddb *DeployDatabase) UpdateContainerHealthCheck(containerID string, healthy bool) error {
	_, err := ddb.db.Exec(`
		UPDATE container_versions
		SET health_check = ?
		WHERE container_id = ?
	`, healthy, containerID)

	if err != nil {
		return fmt.Errorf("更新容器健康检查状态失败: %v", err)
	}

	return nil
}

// AddDeployEvent 添加部署事件
func (ddb *DeployDatabase) AddDeployEvent(appName, deployID, eventType, oldContainerID, newContainerID string, oldPort, newPort int, status, message string) error {
	_, err := ddb.db.Exec(`
		INSERT INTO deploy_events 
		(app_name, deploy_id, event_type, old_container_id, new_container_id, old_port, new_port, status, message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, appName, deployID, eventType, oldContainerID, newContainerID, oldPort, newPort, status, message)

	if err != nil {
		return fmt.Errorf("添加部署事件失败: %v", err)
	}

	return nil
}

// GetContainerHistory 获取应用的容器历史
func (ddb *DeployDatabase) GetContainerHistory(appName string, limit int) ([]ContainerVersion, error) {
	rows, err := ddb.db.Query(`
		SELECT id, app_name, container_id, image_name, port, status, 
		       COALESCE(commit_hash, ''), created_at, started_at, stopped_at, health_check
		FROM container_versions
		WHERE app_name = ?
		ORDER BY created_at DESC
		LIMIT ?
	`, appName, limit)

	if err != nil {
		return nil, fmt.Errorf("查询容器历史失败: %v", err)
	}
	defer rows.Close()

	var versions []ContainerVersion
	for rows.Next() {
		var version ContainerVersion
		var stoppedAt sql.NullTime

		if err := rows.Scan(
			&version.ID, &version.AppName, &version.ContainerID, &version.ImageName,
			&version.Port, &version.Status, &version.CommitHash, &version.CreatedAt,
			&version.StartedAt, &stoppedAt, &version.HealthCheck,
		); err != nil {
			return nil, fmt.Errorf("扫描容器版本失败: %v", err)
		}

		if stoppedAt.Valid {
			version.StoppedAt = &stoppedAt.Time
		}

		versions = append(versions, version)
	}

	return versions, nil
}

// CleanupOldContainers 清理旧容器记录（保留最近N个）
func (ddb *DeployDatabase) CleanupOldContainers(appName string, keepCount int) error {
	_, err := ddb.db.Exec(`
		DELETE FROM container_versions
		WHERE app_name = ? AND id NOT IN (
			SELECT id FROM container_versions
			WHERE app_name = ?
			ORDER BY created_at DESC
			LIMIT ?
		)
	`, appName, appName, keepCount)

	if err != nil {
		return fmt.Errorf("清理旧容器记录失败: %v", err)
	}

	return nil
}

// Close 关闭数据库连接
func (ddb *DeployDatabase) Close() error {
	if ddb.db != nil {
		return ddb.db.Close()
	}
	return nil
}

// GetDeployEvents 获取部署事件
func (ddb *DeployDatabase) GetDeployEvents(appName string, limit int) ([]map[string]interface{}, error) {
	rows, err := ddb.db.Query(`
		SELECT id, app_name, deploy_id, event_type, old_container_id, new_container_id,
		       old_port, new_port, status, message, created_at
		FROM deploy_events
		WHERE app_name = ?
		ORDER BY created_at DESC
		LIMIT ?
	`, appName, limit)

	if err != nil {
		return nil, fmt.Errorf("查询部署事件失败: %v", err)
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var (
			id                                         int64
			appName, deployID, eventType, status, msg  string
			oldContainerID, newContainerID             sql.NullString
			oldPort, newPort                           sql.NullInt64
			createdAt                                  time.Time
		)

		if err := rows.Scan(
			&id, &appName, &deployID, &eventType, &oldContainerID, &newContainerID,
			&oldPort, &newPort, &status, &msg, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("扫描部署事件失败: %v", err)
		}

		event := map[string]interface{}{
			"id":          id,
			"app_name":    appName,
			"deploy_id":   deployID,
			"event_type":  eventType,
			"status":      status,
			"message":     msg,
			"created_at":  createdAt,
		}

		if oldContainerID.Valid {
			event["old_container_id"] = oldContainerID.String
		}
		if newContainerID.Valid {
			event["new_container_id"] = newContainerID.String
		}
		if oldPort.Valid {
			event["old_port"] = oldPort.Int64
		}
		if newPort.Valid {
			event["new_port"] = newPort.Int64
		}

		events = append(events, event)
	}

	return events, nil
}

