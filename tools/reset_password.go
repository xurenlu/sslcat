package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("用法: go run reset_password.go <用户名> <新密码>")
		fmt.Println("示例: go run reset_password.go admin newpassword123")
		os.Exit(1)
	}

	username := os.Args[1]
	newPassword := os.Args[2]

	// 数据库路径
	dataDir := "./data"
	if envDataDir := os.Getenv("SSLcat_DATA_DIR"); envDataDir != "" {
		dataDir = envDataDir
	}
	dbPath := filepath.Join(dataDir, "users.db")

	// 打开数据库
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		fmt.Printf("打开数据库失败: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// 检查用户是否存在
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		fmt.Printf("查询用户失败: %v\n", err)
		os.Exit(1)
	}

	if count == 0 {
		fmt.Printf("用户 '%s' 不存在\n", username)
		os.Exit(1)
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("密码加密失败: %v\n", err)
		os.Exit(1)
	}

	// 更新密码
	_, err = db.Exec("UPDATE users SET password = ? WHERE username = ?", string(hashedPassword), username)
	if err != nil {
		fmt.Printf("更新密码失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("用户 '%s' 的密码已成功重置！\n", username)
}
