package web

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/mattn/go-sqlite3"
)

// WebAuthnCredential WebAuthn 凭证结构
type WebAuthnCredential struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	Username        string    `json:"username"`
	CredentialID    []byte    `json:"credential_id"`
	PublicKey       []byte    `json:"public_key"`
	Counter         uint32    `json:"counter"`
	DeviceName      string    `json:"device_name"`      // 设备名称（如 "Chrome on MacBook"）
	CreatedAt       time.Time `json:"created_at"`
	LastUsedAt      time.Time `json:"last_used_at"`
	IsActive        bool      `json:"is_active"`
}

// WebAuthnUser WebAuthn 用户接口实现
type WebAuthnUser struct {
	ID          string
	Username    string
	Credentials []webauthn.Credential
}

// WebAuthnID 返回用户 ID
func (u *WebAuthnUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

// WebAuthnName 返回用户名
func (u *WebAuthnUser) WebAuthnName() string {
	return u.Username
}

// WebAuthnDisplayName 返回显示名称
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.Username
}

// WebAuthnIcon 返回用户图标（可选）
func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials 返回用户的凭证列表
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// WebAuthnManager WebAuthn 管理器
type WebAuthnManager struct {
	db       *sql.DB
	webauthn *webauthn.WebAuthn
	dbPath   string
	rpID     string
	rpOrigin string
	log      WebAuthnLogger
}

// WebAuthnLogger WebAuthn 日志接口
type WebAuthnLogger interface {
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// NewWebAuthnManager 创建 WebAuthn 管理器
func NewWebAuthnManager(log WebAuthnLogger, dataDir string, rpID string, rpOrigin string) (*WebAuthnManager, error) {
	dbPath := filepath.Join(dataDir, "webauthn.db")

	// 确保数据目录存在
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %v", err)
	}

	// 配置SQLite连接
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000&_timeout=30000&_busy_timeout=30000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %v", err)
	}

	// 配置连接池
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	manager := &WebAuthnManager{
		db:       db,
		dbPath:   dbPath,
		rpID:     rpID,
		rpOrigin: rpOrigin,
		log:      log,
	}

	// 初始化数据库表
	if err := manager.initDatabase(); err != nil {
		return nil, fmt.Errorf("初始化数据库失败: %v", err)
	}

	// 初始化 WebAuthn
	wconfig := &webauthn.Config{
		RPDisplayName: "SSLcat",
		RPID:          rpID,
		RPOrigin:      rpOrigin,
		// 使用默认的挑战超时时间（5分钟）
		Timeout: 300000, // 毫秒
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("初始化 WebAuthn 失败: %v", err)
	}

	manager.webauthn = wa

	return manager, nil
}

// RPID 返回当前 WebAuthn 凭证绑定的 relying party ID。
func (wm *WebAuthnManager) RPID() string {
	return wm.rpID
}

// RPOrigin 返回当前 WebAuthn 凭证绑定的访问来源。
func (wm *WebAuthnManager) RPOrigin() string {
	return wm.rpOrigin
}

// initDatabase 初始化数据库表
func (wm *WebAuthnManager) initDatabase() error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		username TEXT NOT NULL,
		credential_id TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL,
		counter INTEGER DEFAULT 0,
		device_name TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_used_at DATETIME,
		is_active BOOLEAN DEFAULT 1
	);
	`

	if _, err := wm.db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("创建 WebAuthn 凭证表失败: %v", err)
	}

	// 创建索引
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_webauthn_user_id ON webauthn_credentials(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_username ON webauthn_credentials(username);",
		"CREATE INDEX IF NOT EXISTS idx_webauthn_credential_id ON webauthn_credentials(credential_id);",
	}

	for _, indexSQL := range indexes {
		if _, err := wm.db.Exec(indexSQL); err != nil {
			wm.log.Warnf("创建索引失败: %v", err)
		}
	}

	return nil
}

// SaveCredential 保存凭证
func (wm *WebAuthnManager) SaveCredential(userID, username string, credential *webauthn.Credential, deviceName string) error {
	credentialIDBase64 := base64.RawURLEncoding.EncodeToString(credential.ID)
	// PublicKey 已经是 []byte，直接转换为字符串存储
	publicKeyJSON := string(credential.PublicKey)

	insertSQL := `
	INSERT INTO webauthn_credentials (id, user_id, username, credential_id, public_key, counter, device_name, created_at, last_used_at, is_active)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	credentialIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	_, err := wm.db.Exec(insertSQL,
		credentialIDStr, // 使用 base64 编码的 ID 作为主键
		userID,
		username,
		credentialIDBase64,
		publicKeyJSON,
		credential.Authenticator.SignCount,
		deviceName,
		now,
		now,
		true,
	)

	if err != nil {
		return fmt.Errorf("保存凭证失败: %v", err)
	}

	wm.log.Infof("WebAuthn 凭证保存成功: user=%s, device=%s", username, deviceName)
	return nil
}

// GetCredentials 获取用户的所有凭证
func (wm *WebAuthnManager) GetCredentials(username string) ([]WebAuthnCredential, error) {
	querySQL := `
	SELECT id, user_id, username, credential_id, public_key, counter, device_name, created_at, last_used_at, is_active
	FROM webauthn_credentials
	WHERE username = ? AND is_active = 1
	ORDER BY last_used_at DESC
	`

	rows, err := wm.db.Query(querySQL, username)
	if err != nil {
		return nil, fmt.Errorf("查询凭证失败: %v", err)
	}
	defer rows.Close()

	var credentials []WebAuthnCredential
	for rows.Next() {
		var cred WebAuthnCredential
		var credentialIDBase64 string
		var publicKeyJSON string

		err := rows.Scan(
			&cred.ID,
			&cred.UserID,
			&cred.Username,
			&credentialIDBase64,
			&publicKeyJSON,
			&cred.Counter,
			&cred.DeviceName,
			&cred.CreatedAt,
			&cred.LastUsedAt,
			&cred.IsActive,
		)
		if err != nil {
			continue
		}

		// 解码 credential ID
		cred.CredentialID, err = base64.RawURLEncoding.DecodeString(credentialIDBase64)
		if err != nil {
			continue
		}

		// 解析公钥
		cred.PublicKey = []byte(publicKeyJSON)

		credentials = append(credentials, cred)
	}

	return credentials, nil
}

// DeleteCredential 删除凭证
func (wm *WebAuthnManager) DeleteCredential(credentialID string, username string) error {
	deleteSQL := `
	UPDATE webauthn_credentials
	SET is_active = 0
	WHERE credential_id = ? AND username = ?
	`

	result, err := wm.db.Exec(deleteSQL, credentialID, username)
	if err != nil {
		return fmt.Errorf("删除凭证失败: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("获取影响行数失败: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("凭证不存在或不属于该用户")
	}

	wm.log.Infof("WebAuthn 凭证已删除: username=%s, credential_id=%s", username, credentialID)
	return nil
}

// UpdateCredentialCounter 更新凭证计数器
func (wm *WebAuthnManager) UpdateCredentialCounter(credentialID string, counter uint32) error {
	updateSQL := `
	UPDATE webauthn_credentials
	SET counter = ?, last_used_at = ?
	WHERE credential_id = ?
	`

	_, err := wm.db.Exec(updateSQL, counter, time.Now(), credentialID)
	if err != nil {
		return fmt.Errorf("更新凭证计数器失败: %v", err)
	}

	return nil
}

// GetUser 获取 WebAuthn 用户
func (wm *WebAuthnManager) GetUser(username string) (*WebAuthnUser, error) {
	credentials, err := wm.GetCredentials(username)
	if err != nil {
		return nil, err
	}

	// 转换为 webauthn.Credential
	webauthnCreds := make([]webauthn.Credential, 0, len(credentials))
	for _, cred := range credentials {
		// PublicKey 已经是 []byte，直接使用
		webauthnCred := webauthn.Credential{
			ID:        cred.CredentialID,
			PublicKey: cred.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: cred.Counter,
			},
		}
		webauthnCreds = append(webauthnCreds, webauthnCred)
	}

	return &WebAuthnUser{
		ID:          username, // 使用用户名作为 ID
		Username:    username,
		Credentials: webauthnCreds,
	}, nil
}
