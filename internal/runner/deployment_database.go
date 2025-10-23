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

// DeploymentDatabase 发布数据库管理器
type DeploymentDatabase struct {
	db     *sql.DB
	dbPath string
	logger *logrus.Entry
}

// Deployment 发布记录
type Deployment struct {
	ID             int64      `json:"id"`
	UUID           string     `json:"uuid"`
	AppName        string     `json:"app_name"`
	CommitSHA      string     `json:"commit_sha"`
	Branch         string     `json:"branch"`
	Version        string     `json:"version"`
	Status         string     `json:"status"` // pending, building, success, failed
	StartedAt      time.Time  `json:"started_at"`
	CompletedAt    *time.Time `json:"completed_at"`
	BuildDuration  *int64     `json:"build_duration"` // 毫秒
	Deployer       string     `json:"deployer"`
	Message        string     `json:"message"`
	CreatedAt      time.Time  `json:"created_at"`
}

// DeploymentLog 发布日志
type DeploymentLog struct {
	ID             int64     `json:"id"`
	DeploymentUUID string    `json:"deployment_uuid"`
	Level          string    `json:"level"`  // error, warn, info, debug
	Source         string    `json:"source"` // git, build, deploy, etc.
	Message        string    `json:"message"`
	Timestamp      time.Time `json:"timestamp"`
	Metadata       string    `json:"metadata"` // JSON 格式的额外信息
}

// DeploymentStatus 发布状态
type DeploymentStatus struct {
	ID             int64     `json:"id"`
	DeploymentUUID string    `json:"deployment_uuid"`
	Status         string    `json:"status"`
	Progress       int       `json:"progress"` // 0-100
	Message        string    `json:"message"`
	Timestamp      time.Time `json:"timestamp"`
}

// NewDeploymentDatabase 创建发布数据库管理器
func NewDeploymentDatabase(dataDir string) (*DeploymentDatabase, error) {
	dbPath := filepath.Join(dataDir, "deployments.db")

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
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(10 * time.Minute)

	deployDB := &DeploymentDatabase{
		db:     db,
		dbPath: dbPath,
		logger: logrus.WithField("component", "deployment_database"),
	}

	// 初始化数据库表
	if err := deployDB.initDatabase(); err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %v", err)
	}

	return deployDB, nil
}

// initDatabase 初始化数据库表
func (ddb *DeploymentDatabase) initDatabase() error {
	// 创建发布记录表
	createDeploymentsTable := `
	CREATE TABLE IF NOT EXISTS deployments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uuid TEXT UNIQUE NOT NULL,
		app_name TEXT NOT NULL,
		commit_sha TEXT NOT NULL,
		branch TEXT NOT NULL,
		version TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		started_at DATETIME NOT NULL,
		completed_at DATETIME,
		build_duration INTEGER,
		deployer TEXT DEFAULT 'system',
		message TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	// 创建发布日志表
	createDeploymentLogsTable := `
	CREATE TABLE IF NOT EXISTS deployment_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		deployment_uuid TEXT NOT NULL,
		level TEXT NOT NULL,
		source TEXT NOT NULL,
		message TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		metadata TEXT,
		FOREIGN KEY (deployment_uuid) REFERENCES deployments(uuid)
	)`

	// 创建发布状态表
	createDeploymentStatusTable := `
	CREATE TABLE IF NOT EXISTS deployment_status (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		deployment_uuid TEXT NOT NULL,
		status TEXT NOT NULL,
		progress INTEGER DEFAULT 0,
		message TEXT,
		timestamp DATETIME NOT NULL,
		FOREIGN KEY (deployment_uuid) REFERENCES deployments(uuid)
	)`

	// 创建索引
	createIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_deployments_uuid ON deployments(uuid)",
		"CREATE INDEX IF NOT EXISTS idx_deployments_app_name ON deployments(app_name)",
		"CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status)",
		"CREATE INDEX IF NOT EXISTS idx_deployments_started_at ON deployments(started_at)",
		"CREATE INDEX IF NOT EXISTS idx_deployment_logs_uuid ON deployment_logs(deployment_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_deployment_logs_timestamp ON deployment_logs(timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_deployment_status_uuid ON deployment_status(deployment_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_deployment_status_timestamp ON deployment_status(timestamp)",
	}

	// 执行创建表语句
	tables := []string{
		createDeploymentsTable,
		createDeploymentLogsTable,
		createDeploymentStatusTable,
	}

	for _, table := range tables {
		if _, err := ddb.db.Exec(table); err != nil {
			return fmt.Errorf("创建表失败: %v", err)
		}
	}

	// 创建索引
	for _, index := range createIndexes {
		if _, err := ddb.db.Exec(index); err != nil {
			ddb.logger.Warnf("创建索引失败: %v", err)
		}
	}

	ddb.logger.Info("发布数据库表初始化完成")
	return nil
}

// CreateDeployment 创建新的发布记录
func (ddb *DeploymentDatabase) CreateDeployment(deployment *Deployment) error {
	query := `
		INSERT INTO deployments (uuid, app_name, commit_sha, branch, version, status, started_at, deployer, message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := ddb.db.Exec(query,
		deployment.UUID,
		deployment.AppName,
		deployment.CommitSHA,
		deployment.Branch,
		deployment.Version,
		deployment.Status,
		deployment.StartedAt,
		deployment.Deployer,
		deployment.Message,
	)

	if err != nil {
		return fmt.Errorf("创建发布记录失败: %v", err)
	}

	ddb.logger.Infof("创建发布记录: %s (%s)", deployment.UUID, deployment.AppName)
	return nil
}

// UpdateDeploymentStatus 更新发布状态
func (ddb *DeploymentDatabase) UpdateDeploymentStatus(uuid, status string, progress int, message string) error {
	// 更新发布记录状态
	updateQuery := `
		UPDATE deployments 
		SET status = ?
		WHERE uuid = ?
	`

	if status == "success" || status == "failed" {
		// 如果发布完成，设置完成时间
		updateQuery = `
			UPDATE deployments 
			SET status = ?, completed_at = CURRENT_TIMESTAMP,
			    build_duration = (julianday(CURRENT_TIMESTAMP) - julianday(started_at)) * 86400000
			WHERE uuid = ?
		`
	}

	_, err := ddb.db.Exec(updateQuery, status, uuid)
	if err != nil {
		return fmt.Errorf("更新发布状态失败: %v", err)
	}

	// 插入状态记录
	statusQuery := `
		INSERT INTO deployment_status (deployment_uuid, status, progress, message, timestamp)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err = ddb.db.Exec(statusQuery, uuid, status, progress, message, time.Now())
	if err != nil {
		ddb.logger.Warnf("插入状态记录失败: %v", err)
	}

	return nil
}

// AddDeploymentLog 添加发布日志
func (ddb *DeploymentDatabase) AddDeploymentLog(log *DeploymentLog) error {
	query := `
		INSERT INTO deployment_logs (deployment_uuid, level, source, message, timestamp, metadata)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := ddb.db.Exec(query,
		log.DeploymentUUID,
		log.Level,
		log.Source,
		log.Message,
		log.Timestamp,
		log.Metadata,
	)

	if err != nil {
		return fmt.Errorf("添加发布日志失败: %v", err)
	}

	return nil
}

// GetDeployments 获取发布列表
func (ddb *DeploymentDatabase) GetDeployments(appName string, limit, offset int) ([]*Deployment, error) {
	var query string
	var args []interface{}

	if appName != "" {
		query = `
			SELECT id, uuid, app_name, commit_sha, branch, version, status, 
			       started_at, completed_at, build_duration, deployer, message, created_at
			FROM deployments 
			WHERE app_name = ?
			ORDER BY started_at DESC 
			LIMIT ? OFFSET ?
		`
		args = []interface{}{appName, limit, offset}
	} else {
		query = `
			SELECT id, uuid, app_name, commit_sha, branch, version, status, 
			       started_at, completed_at, build_duration, deployer, message, created_at
			FROM deployments 
			ORDER BY started_at DESC 
			LIMIT ? OFFSET ?
		`
		args = []interface{}{limit, offset}
	}

	rows, err := ddb.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("查询发布列表失败: %v", err)
	}
	defer rows.Close()

	var deployments []*Deployment
	for rows.Next() {
		var deployment Deployment
		err := rows.Scan(
			&deployment.ID,
			&deployment.UUID,
			&deployment.AppName,
			&deployment.CommitSHA,
			&deployment.Branch,
			&deployment.Version,
			&deployment.Status,
			&deployment.StartedAt,
			&deployment.CompletedAt,
			&deployment.BuildDuration,
			&deployment.Deployer,
			&deployment.Message,
			&deployment.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("扫描发布记录失败: %v", err)
		}
		deployments = append(deployments, &deployment)
	}

	return deployments, nil
}

// GetDeploymentByUUID 根据UUID获取发布记录
func (ddb *DeploymentDatabase) GetDeploymentByUUID(uuid string) (*Deployment, error) {
	query := `
		SELECT id, uuid, app_name, commit_sha, branch, version, status, 
		       started_at, completed_at, build_duration, deployer, message, created_at
		FROM deployments 
		WHERE uuid = ?
	`

	var deployment Deployment
	err := ddb.db.QueryRow(query, uuid).Scan(
		&deployment.ID,
		&deployment.UUID,
		&deployment.AppName,
		&deployment.CommitSHA,
		&deployment.Branch,
		&deployment.Version,
		&deployment.Status,
		&deployment.StartedAt,
		&deployment.CompletedAt,
		&deployment.BuildDuration,
		&deployment.Deployer,
		&deployment.Message,
		&deployment.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("发布记录不存在: %s", uuid)
		}
		return nil, fmt.Errorf("查询发布记录失败: %v", err)
	}

	return &deployment, nil
}

// GetDeploymentLogs 获取发布日志
func (ddb *DeploymentDatabase) GetDeploymentLogs(uuid string, limit, offset int) ([]*DeploymentLog, error) {
	query := `
		SELECT id, deployment_uuid, level, source, message, timestamp, metadata
		FROM deployment_logs 
		WHERE deployment_uuid = ?
		ORDER BY timestamp ASC 
		LIMIT ? OFFSET ?
	`

	rows, err := ddb.db.Query(query, uuid, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("查询发布日志失败: %v", err)
	}
	defer rows.Close()

	var logs []*DeploymentLog
	for rows.Next() {
		var log DeploymentLog
		err := rows.Scan(
			&log.ID,
			&log.DeploymentUUID,
			&log.Level,
			&log.Source,
			&log.Message,
			&log.Timestamp,
			&log.Metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("扫描发布日志失败: %v", err)
		}
		logs = append(logs, &log)
	}

	return logs, nil
}

// GetDeploymentStatus 获取发布状态历史
func (ddb *DeploymentDatabase) GetDeploymentStatus(uuid string) ([]*DeploymentStatus, error) {
	query := `
		SELECT id, deployment_uuid, status, progress, message, timestamp
		FROM deployment_status 
		WHERE deployment_uuid = ?
		ORDER BY timestamp ASC
	`

	rows, err := ddb.db.Query(query, uuid)
	if err != nil {
		return nil, fmt.Errorf("查询发布状态失败: %v", err)
	}
	defer rows.Close()

	var statuses []*DeploymentStatus
	for rows.Next() {
		var status DeploymentStatus
		err := rows.Scan(
			&status.ID,
			&status.DeploymentUUID,
			&status.Status,
			&status.Progress,
			&status.Message,
			&status.Timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("扫描发布状态失败: %v", err)
		}
		statuses = append(statuses, &status)
	}

	return statuses, nil
}

// Close 关闭数据库连接
func (ddb *DeploymentDatabase) Close() error {
	if ddb.db != nil {
		return ddb.db.Close()
	}
	return nil
}
