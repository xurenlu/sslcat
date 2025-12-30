package bot

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// WhitelistStorage 白名单存储
type WhitelistStorage struct {
	db *sql.DB
}

// NewWhitelistStorage 创建白名单存储
func NewWhitelistStorage(dbPath string) (*WhitelistStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &WhitelistStorage{db: db}

	// 初始化数据库表
	if err := storage.initTables(); err != nil {
		db.Close()
		return nil, err
	}

	return storage, nil
}

// initTables 初始化数据库表
func (s *WhitelistStorage) initTables() error {
	// 创建白名单表
	whitelistTable := `
	CREATE TABLE IF NOT EXISTS bot_whitelist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		token_hash TEXT NOT NULL,
		added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL,
		verified_count INTEGER DEFAULT 1,
		last_verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		user_agent_hash TEXT,
		UNIQUE(ip, domain)
	);
	`

	if _, err := s.db.Exec(whitelistTable); err != nil {
		return fmt.Errorf("failed to create bot_whitelist table: %w", err)
	}

	// 创建索引
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_bot_whitelist_ip_domain ON bot_whitelist(ip, domain);",
		"CREATE INDEX IF NOT EXISTS idx_bot_whitelist_expires ON bot_whitelist(expires_at);",
	}

	for _, idx := range indexes {
		if _, err := s.db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	// 创建检测日志表
	logsTable := `
	CREATE TABLE IF NOT EXISTS bot_detection_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		user_agent TEXT,
		risk_score INTEGER NOT NULL,
		action TEXT NOT NULL,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		request_path TEXT,
		verified BOOLEAN DEFAULT 0
	);
	`

	if _, err := s.db.Exec(logsTable); err != nil {
		return fmt.Errorf("failed to create bot_detection_logs table: %w", err)
	}

	// 创建日志索引
	logIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_bot_logs_timestamp ON bot_detection_logs(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_bot_logs_ip ON bot_detection_logs(ip);",
	}

	for _, idx := range logIndexes {
		if _, err := s.db.Exec(idx); err != nil {
			return fmt.Errorf("failed to create log index: %w", err)
		}
	}

	return nil
}

// Add 添加白名单条目
func (s *WhitelistStorage) Add(entry *WhitelistEntry) error {
	query := `
	INSERT INTO bot_whitelist (ip, domain, token_hash, added_at, expires_at, verified_count, last_verified_at, user_agent_hash)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(ip, domain) DO UPDATE SET
		token_hash = excluded.token_hash,
		expires_at = excluded.expires_at,
		verified_count = verified_count + 1,
		last_verified_at = excluded.last_verified_at
	`

	_, err := s.db.Exec(query,
		entry.IP,
		entry.Domain,
		entry.TokenHash,
		entry.AddedAt,
		entry.ExpiresAt,
		entry.VerifiedCount,
		entry.LastVerifiedAt,
		entry.UserAgentHash,
	)

	return err
}

// Remove 移除白名单条目
func (s *WhitelistStorage) Remove(ip, domain string) error {
	query := "DELETE FROM bot_whitelist WHERE ip = ? AND domain = ?"
	_, err := s.db.Exec(query, ip, domain)
	return err
}

// Get 获取白名单条目
func (s *WhitelistStorage) Get(ip, domain string) (*WhitelistEntry, error) {
	query := `
	SELECT id, ip, domain, token_hash, added_at, expires_at, verified_count, last_verified_at, user_agent_hash
	FROM bot_whitelist
	WHERE ip = ? AND domain = ?
	`

	entry := &WhitelistEntry{}
	err := s.db.QueryRow(query, ip, domain).Scan(
		&entry.ID,
		&entry.IP,
		&entry.Domain,
		&entry.TokenHash,
		&entry.AddedAt,
		&entry.ExpiresAt,
		&entry.VerifiedCount,
		&entry.LastVerifiedAt,
		&entry.UserAgentHash,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return entry, nil
}

// List 列出所有白名单条目
func (s *WhitelistStorage) List() ([]*WhitelistEntry, error) {
	query := `
	SELECT id, ip, domain, token_hash, added_at, expires_at, verified_count, last_verified_at, user_agent_hash
	FROM bot_whitelist
	ORDER BY added_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []*WhitelistEntry{}

	for rows.Next() {
		entry := &WhitelistEntry{}
		err := rows.Scan(
			&entry.ID,
			&entry.IP,
			&entry.Domain,
			&entry.TokenHash,
			&entry.AddedAt,
			&entry.ExpiresAt,
			&entry.VerifiedCount,
			&entry.LastVerifiedAt,
			&entry.UserAgentHash,
		)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// UpdateVerification 更新验证信息
func (s *WhitelistStorage) UpdateVerification(ip, domain string) error {
	query := `
	UPDATE bot_whitelist
	SET verified_count = verified_count + 1, last_verified_at = ?
	WHERE ip = ? AND domain = ?
	`

	_, err := s.db.Exec(query, time.Now(), ip, domain)
	return err
}

// CleanupExpired 清理过期条目
func (s *WhitelistStorage) CleanupExpired() error {
	query := "DELETE FROM bot_whitelist WHERE expires_at < ?"
	_, err := s.db.Exec(query, time.Now())
	return err
}

// LogDetection 记录检测日志
func (s *WhitelistStorage) LogDetection(ip, domain, userAgent, action, requestPath string, riskScore int, verified bool) error {
	query := `
	INSERT INTO bot_detection_logs (ip, domain, user_agent, risk_score, action, request_path, verified)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.db.Exec(query, ip, domain, userAgent, riskScore, action, requestPath, verified)
	return err
}

// GetDetectionLogs 获取检测日志
func (s *WhitelistStorage) GetDetectionLogs(limit int) ([]map[string]interface{}, error) {
	query := `
	SELECT id, ip, domain, user_agent, risk_score, action, timestamp, request_path, verified
	FROM bot_detection_logs
	ORDER BY timestamp DESC
	LIMIT ?
	`

	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	logs := []map[string]interface{}{}

	for rows.Next() {
		var id, riskScore int
		var ip, domain, userAgent, action, requestPath string
		var timestamp time.Time
		var verified bool

		err := rows.Scan(&id, &ip, &domain, &userAgent, &riskScore, &action, &timestamp, &requestPath, &verified)
		if err != nil {
			return nil, err
		}

		logs = append(logs, map[string]interface{}{
			"id":           id,
			"ip":           ip,
			"domain":       domain,
			"user_agent":   userAgent,
			"risk_score":   riskScore,
			"action":       action,
			"timestamp":    timestamp,
			"request_path": requestPath,
			"verified":     verified,
		})
	}

	return logs, rows.Err()
}

// GetStats 获取统计信息
func (s *WhitelistStorage) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 白名单总数
	var whitelistCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM bot_whitelist WHERE expires_at > ?", time.Now()).Scan(&whitelistCount)
	if err != nil {
		return nil, err
	}
	stats["whitelist_count"] = whitelistCount

	// 今日检测数
	var todayDetections int
	today := time.Now().Truncate(24 * time.Hour)
	err = s.db.QueryRow("SELECT COUNT(*) FROM bot_detection_logs WHERE timestamp >= ?", today).Scan(&todayDetections)
	if err != nil {
		return nil, err
	}
	stats["today_detections"] = todayDetections

	// 今日阻止数
	var todayBlocked int
	err = s.db.QueryRow("SELECT COUNT(*) FROM bot_detection_logs WHERE timestamp >= ? AND action = 'challenge'", today).Scan(&todayBlocked)
	if err != nil {
		return nil, err
	}
	stats["today_blocked"] = todayBlocked

	// 今日验证通过数
	var todayVerified int
	err = s.db.QueryRow("SELECT COUNT(*) FROM bot_detection_logs WHERE timestamp >= ? AND verified = 1", today).Scan(&todayVerified)
	if err != nil {
		return nil, err
	}
	stats["today_verified"] = todayVerified

	return stats, nil
}

// CleanupOldLogs 清理旧日志
func (s *WhitelistStorage) CleanupOldLogs(days int) error {
	cutoff := time.Now().AddDate(0, 0, -days)
	query := "DELETE FROM bot_detection_logs WHERE timestamp < ?"
	_, err := s.db.Exec(query, cutoff)
	return err
}

// Close 关闭数据库连接
func (s *WhitelistStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

