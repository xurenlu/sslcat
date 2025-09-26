package web

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// User 用户结构
type User struct {
	ID          int       `json:"id"`
	Username    string    `json:"username"`
	Password    string    `json:"-"` // 不序列化密码
	Role        string    `json:"role"`
	Email       string    `json:"email"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	LastLoginAt time.Time `json:"last_login_at"`
	CreatedBy   string    `json:"created_by"`
}

// UserRole 用户角色
const (
	RoleSuperAdmin = "super_admin" // 超级管理员
	RoleAdmin      = "admin"       // 管理员
	RoleOperator   = "operator"    // 操作员
	RoleViewer     = "viewer"      // 只读用户
)

// UserManager 用户管理器
type UserManager struct {
	db     *sql.DB
	log    UserLogger
	dbPath string
}

// UserLogger 用户管理器日志接口
type UserLogger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// NewUserManager 创建用户管理器
func NewUserManager(log UserLogger, dataDir string) (*UserManager, error) {
	dbPath := filepath.Join(dataDir, "users.db")

	// 确保数据目录存在
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %v", err)
	}

	// 配置SQLite连接参数，启用WAL模式提高并发性能
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000&_timeout=30000&_busy_timeout=30000", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %v", err)
	}

	// 配置连接池参数
	db.SetMaxOpenConns(10)                 // 最大打开连接数
	db.SetMaxIdleConns(5)                  // 最大空闲连接数
	db.SetConnMaxLifetime(5 * time.Minute) // 连接最大生存时间

	manager := &UserManager{
		db:     db,
		log:    log,
		dbPath: dbPath,
	}

	// 初始化数据库表
	if err := manager.initDatabase(); err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %v", err)
	}

	return manager, nil
}

// initDatabase 初始化数据库表
func (um *UserManager) initDatabase() error {
	// 创建用户表
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'viewer',
		email TEXT,
		is_active BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login_at DATETIME,
		created_by TEXT DEFAULT 'system'
	);
	`

	if _, err := um.db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("创建用户表失败: %v", err)
	}

	// 创建操作日志表
	createLogTableSQL := `
	CREATE TABLE IF NOT EXISTS user_audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		action TEXT NOT NULL,
		resource TEXT,
		details TEXT,
		ip_address TEXT,
		user_agent TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	if _, err := um.db.Exec(createLogTableSQL); err != nil {
		return fmt.Errorf("创建审计日志表失败: %v", err)
	}

	// 创建索引
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
		"CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);",
		"CREATE INDEX IF NOT EXISTS idx_audit_username ON user_audit_logs(username);",
		"CREATE INDEX IF NOT EXISTS idx_audit_created_at ON user_audit_logs(created_at);",
	}

	for _, indexSQL := range indexes {
		if _, err := um.db.Exec(indexSQL); err != nil {
			um.log.Warnf("创建索引失败: %v", err)
		}
	}

	return nil
}

// CreateUser 创建用户
func (um *UserManager) CreateUser(username, password, role, email, createdBy string) error {
	// 验证用户名
	if username == "" || len(username) < 3 {
		return fmt.Errorf("用户名长度至少3个字符")
	}

	// 验证角色
	validRoles := []string{RoleSuperAdmin, RoleAdmin, RoleOperator, RoleViewer}
	validRole := false
	for _, r := range validRoles {
		if role == r {
			validRole = true
			break
		}
	}
	if !validRole {
		return fmt.Errorf("无效的角色: %s", role)
	}

	// 检查用户名是否已存在
	if um.UserExists(username) {
		return fmt.Errorf("用户名已存在: %s", username)
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码加密失败: %v", err)
	}

	// 插入用户
	insertSQL := `
	INSERT INTO users (username, password, role, email, created_by)
	VALUES (?, ?, ?, ?, ?)
	`

	_, err = um.db.Exec(insertSQL, username, string(hashedPassword), role, email, createdBy)
	if err != nil {
		return fmt.Errorf("创建用户失败: %v", err)
	}

	um.log.Infof("用户创建成功: %s (角色: %s)", username, role)
	return nil
}

// AuthenticateUser 验证用户
func (um *UserManager) AuthenticateUser(username, password string) (*User, error) {
	user, err := um.GetUserByUsername(username)
	if err != nil {
		return nil, fmt.Errorf("用户不存在: %s", username)
	}

	if !user.IsActive {
		return nil, fmt.Errorf("用户已被禁用")
	}

	// 验证密码
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("密码错误")
	}

	// 更新最后登录时间
	um.updateLastLogin(username)

	return user, nil
}

// GetUserByUsername 根据用户名获取用户
func (um *UserManager) GetUserByUsername(username string) (*User, error) {
	querySQL := `
	SELECT id, username, password, role, email, is_active, created_at, last_login_at, created_by
	FROM users WHERE username = ?
	`

	row := um.db.QueryRow(querySQL, username)
	user := &User{}

	err := row.Scan(
		&user.ID, &user.Username, &user.Password, &user.Role,
		&user.Email, &user.IsActive, &user.CreatedAt, &user.LastLoginAt, &user.CreatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("用户不存在")
		}
		return nil, fmt.Errorf("查询用户失败: %v", err)
	}

	return user, nil
}

// GetAllUsers 获取所有用户
func (um *UserManager) GetAllUsers() ([]*User, error) {
	querySQL := `
	SELECT id, username, role, email, is_active, created_at, last_login_at, created_by
	FROM users ORDER BY created_at DESC
	`

	rows, err := um.db.Query(querySQL)
	if err != nil {
		return nil, fmt.Errorf("查询用户列表失败: %v", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		err := rows.Scan(
			&user.ID, &user.Username, &user.Role, &user.Email,
			&user.IsActive, &user.CreatedAt, &user.LastLoginAt, &user.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("扫描用户数据失败: %v", err)
		}
		users = append(users, user)
	}

	return users, nil
}

// UpdateUser 更新用户信息
func (um *UserManager) UpdateUser(username, newPassword, newRole, newEmail string, isActive bool) error {
	user, err := um.GetUserByUsername(username)
	if err != nil {
		return err
	}

	// 更新密码（如果提供）
	if newPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("密码加密失败: %v", err)
		}
		user.Password = string(hashedPassword)
	}

	// 更新角色（如果提供）
	if newRole != "" {
		user.Role = newRole
	}

	// 更新邮箱（如果提供）
	if newEmail != "" {
		user.Email = newEmail
	}

	// 更新状态
	user.IsActive = isActive

	updateSQL := `
	UPDATE users 
	SET password = ?, role = ?, email = ?, is_active = ?
	WHERE username = ?
	`

	_, err = um.db.Exec(updateSQL, user.Password, user.Role, user.Email, user.IsActive, username)
	if err != nil {
		return fmt.Errorf("更新用户失败: %v", err)
	}

	um.log.Infof("用户信息更新成功: %s", username)
	return nil
}

// DeleteUser 删除用户
func (um *UserManager) DeleteUser(username string) error {
	// 检查是否是最后一个超级管理员
	superAdminCount, err := um.getSuperAdminCount()
	if err != nil {
		return fmt.Errorf("检查超级管理员数量失败: %v", err)
	}

	user, err := um.GetUserByUsername(username)
	if err != nil {
		return err
	}

	if user.Role == RoleSuperAdmin && superAdminCount <= 1 {
		return fmt.Errorf("不能删除最后一个超级管理员")
	}

	deleteSQL := `DELETE FROM users WHERE username = ?`
	_, err = um.db.Exec(deleteSQL, username)
	if err != nil {
		return fmt.Errorf("删除用户失败: %v", err)
	}

	um.log.Infof("用户删除成功: %s", username)
	return nil
}

// UserExists 检查用户是否存在
func (um *UserManager) UserExists(username string) bool {
	querySQL := `SELECT COUNT(*) FROM users WHERE username = ?`
	var count int
	err := um.db.QueryRow(querySQL, username).Scan(&count)
	return err == nil && count > 0
}

// updateLastLogin 更新最后登录时间
func (um *UserManager) updateLastLogin(username string) {
	updateSQL := `UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE username = ?`
	_, err := um.db.Exec(updateSQL, username)
	if err != nil {
		um.log.Warnf("更新最后登录时间失败: %v", err)
	}
}

// getSuperAdminCount 获取超级管理员数量
func (um *UserManager) getSuperAdminCount() (int, error) {
	querySQL := `SELECT COUNT(*) FROM users WHERE role = ? AND is_active = 1`
	var count int
	err := um.db.QueryRow(querySQL, RoleSuperAdmin).Scan(&count)
	return count, err
}

// LogUserAction 记录用户操作
func (um *UserManager) LogUserAction(username, action, resource, details, ipAddress, userAgent string) {
	insertSQL := `
	INSERT INTO user_audit_logs (username, action, resource, details, ip_address, user_agent)
	VALUES (?, ?, ?, ?, ?, ?)
	`

	// 使用重试机制处理数据库锁定问题
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		_, err := um.db.Exec(insertSQL, username, action, resource, details, ipAddress, userAgent)
		if err == nil {
			return // 成功，退出重试循环
		}

		// 检查是否是SQLite_BUSY错误
		if err.Error() == "database is locked" ||
			err.Error() == "database is locked (5)" ||
			err.Error() == "SQLITE_BUSY" {
			um.log.Debugf("数据库锁定，重试 %d/%d: %v", i+1, maxRetries, err)
			// 指数退避重试
			time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
			continue
		}

		// 其他错误直接记录并退出
		um.log.Warnf("记录用户操作日志失败: %v", err)
		return
	}

	// 所有重试都失败了
	um.log.Warnf("记录用户操作日志失败，已重试 %d 次", maxRetries)
}

// GetUserAuditLogs 获取用户操作日志
func (um *UserManager) GetUserAuditLogs(username string, limit int) ([]map[string]interface{}, error) {
	querySQL := `
	SELECT username, action, resource, details, ip_address, user_agent, created_at
	FROM user_audit_logs
	WHERE username = ?
	ORDER BY created_at DESC
	LIMIT ?
	`

	rows, err := um.db.Query(querySQL, username, limit)
	if err != nil {
		return nil, fmt.Errorf("查询用户操作日志失败: %v", err)
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var username, action, resource, details, ipAddress, userAgent string
		var createdAt time.Time

		err := rows.Scan(&username, &action, &resource, &details, &ipAddress, &userAgent, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("扫描日志数据失败: %v", err)
		}

		log := map[string]interface{}{
			"username":   username,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"ip_address": ipAddress,
			"user_agent": userAgent,
			"created_at": createdAt,
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// GetAllAuditLogs 获取所有操作日志
func (um *UserManager) GetAllAuditLogs(limit int) ([]map[string]interface{}, error) {
	querySQL := `
	SELECT username, action, resource, details, ip_address, user_agent, created_at
	FROM user_audit_logs
	ORDER BY created_at DESC
	LIMIT ?
	`

	rows, err := um.db.Query(querySQL, limit)
	if err != nil {
		return nil, fmt.Errorf("查询操作日志失败: %v", err)
	}
	defer rows.Close()

	var logs []map[string]interface{}
	for rows.Next() {
		var username, action, resource, details, ipAddress, userAgent string
		var createdAt time.Time

		err := rows.Scan(&username, &action, &resource, &details, &ipAddress, &userAgent, &createdAt)
		if err != nil {
			return nil, fmt.Errorf("扫描日志数据失败: %v", err)
		}

		log := map[string]interface{}{
			"username":   username,
			"action":     action,
			"resource":   resource,
			"details":    details,
			"ip_address": ipAddress,
			"user_agent": userAgent,
			"created_at": createdAt,
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// generateSessionID 生成会话ID
func (um *UserManager) generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// CheckDatabaseHealth 检查数据库健康状态
func (um *UserManager) CheckDatabaseHealth() error {
	// 执行简单的查询来检查数据库连接
	_, err := um.db.Exec("SELECT 1")
	if err != nil {
		um.log.Errorf("数据库健康检查失败: %v", err)
		return err
	}
	return nil
}

// GetDatabaseStats 获取数据库统计信息
func (um *UserManager) GetDatabaseStats() map[string]interface{} {
	stats := um.db.Stats()
	return map[string]interface{}{
		"open_connections":     stats.OpenConnections,
		"in_use":               stats.InUse,
		"idle":                 stats.Idle,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}
}

// Close 关闭数据库连接
func (um *UserManager) Close() error {
	return um.db.Close()
}
