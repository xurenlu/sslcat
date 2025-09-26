package main

// This is a standalone tool for listing users

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
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

	// 查询所有用户
	rows, err := db.Query("SELECT username, role, email, is_active, created_at FROM users ORDER BY created_at")
	if err != nil {
		fmt.Printf("查询用户失败: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	fmt.Println("数据库中的用户列表:")
	fmt.Println("用户名\t\t角色\t\t邮箱\t\t状态\t\t创建时间")
	fmt.Println("------------------------------------------------------------")

	for rows.Next() {
		var username, role, email string
		var isActive bool
		var createdAt string

		err := rows.Scan(&username, &role, &email, &isActive, &createdAt)
		if err != nil {
			fmt.Printf("扫描数据失败: %v\n", err)
			continue
		}

		status := "禁用"
		if isActive {
			status = "启用"
		}

		fmt.Printf("%s\t\t%s\t\t%s\t\t%s\t\t%s\n", username, role, email, status, createdAt)
	}

	if err = rows.Err(); err != nil {
		fmt.Printf("遍历行失败: %v\n", err)
	}
}
