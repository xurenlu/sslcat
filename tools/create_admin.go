package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("用法: go run create_admin.go <用户名> <密码>")
		fmt.Println("示例: go run create_admin.go admin admin123456")
		os.Exit(1)
	}

	username := os.Args[1]
	password := os.Args[2]

	// 数据库路径
	dataDir := "./data"
	if envDataDir := os.Getenv("SSLcat_DATA_DIR"); envDataDir != "" {
		dataDir = envDataDir
	}
	dbPath := filepath.Join(dataDir, "users.db")

	// 打开数据库
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("打开数据库失败: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// 检查用户是否已存在
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		fmt.Printf("查询用户失败: %v\n", err)
		os.Exit(1)
	}

	if count > 0 {
		fmt.Printf("用户 '%s' 已存在\n", username)
		os.Exit(1)
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("密码加密失败: %v\n", err)
		os.Exit(1)
	}

	// 创建超级管理员用户
	insertSQL := `
	INSERT INTO users (username, password, role, email, is_active, created_by)
	VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err = db.Exec(insertSQL, username, string(hashedPassword), "super_admin", "admin@sslcat.com", true, "system")
	if err != nil {
		fmt.Printf("创建用户失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("超级管理员用户 '%s' 创建成功！\n", username)
	fmt.Printf("现在可以使用以下信息登录:\n")
	fmt.Printf("用户名: %s\n", username)
	fmt.Printf("密码: %s\n", password)
}
