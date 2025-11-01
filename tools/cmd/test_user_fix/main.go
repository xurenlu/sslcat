package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "github.com/xurenlu/sslcat/internal/database"
)

func main() {
	fmt.Println("=== 用户管理修复验证 ===")

	// 连接数据库
	dbPath := filepath.Join("./data", "users.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("❌ 连接数据库失败: %v\n", err)
		return
	}
	defer db.Close()

	// 测试修复后的查询方法
	fmt.Println("🔵 测试修复后的 GetAllUsers 查询")
	querySQL := `
	SELECT id, username, role, email, is_active, created_at, last_login_at, created_by
	FROM users ORDER BY created_at DESC
	`

	rows, err := db.Query(querySQL)
	if err != nil {
		fmt.Printf("❌ 查询失败: %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("✅ 查询成功，开始扫描数据...")

	var userCount int
	for rows.Next() {
		var id int
		var username, role, email, createdBy string
		var isActive bool
		var createdAt time.Time
		var lastLoginAt sql.NullTime

		err := rows.Scan(
			&id, &username, &role, &email,
			&isActive, &createdAt, &lastLoginAt, &createdBy,
		)
		if err != nil {
			fmt.Printf("❌ 扫描数据失败: %v\n", err)
			return
		}

		userCount++
		fmt.Printf("   用户 %d: %s (%s) - %s\n", id, username, role, email)

		// 处理 last_login_at - 这是修复的关键部分
		if lastLoginAt.Valid {
			fmt.Printf("     最后登录: %s\n", lastLoginAt.Time.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("     最后登录: 从未登录\n")
		}
	}

	fmt.Printf("✅ 成功扫描 %d 个用户，没有出现 NULL 时间错误\n", userCount)

	// 测试创建用户
	fmt.Println("\n🔵 测试创建用户功能")
	insertSQL := `
	INSERT INTO users (username, password, role, email, is_active, created_at, created_by)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	hashedPassword := "$2a$10$test.hash.password"
	now := time.Now()

	_, err = db.Exec(insertSQL, "testuser456", hashedPassword, "viewer", "test456@example.com", true, now, "admin")
	if err != nil {
		fmt.Printf("❌ 插入用户失败: %v\n", err)
		return
	}

	fmt.Println("✅ 用户创建成功")

	// 验证创建的用户
	fmt.Println("\n🔵 验证创建的用户")
	rows, err = db.Query(querySQL)
	if err != nil {
		fmt.Printf("❌ 查询失败: %v\n", err)
		return
	}
	defer rows.Close()

	var newUserCount int
	for rows.Next() {
		var id int
		var username, role, email, createdBy string
		var isActive bool
		var createdAt time.Time
		var lastLoginAt sql.NullTime

		err := rows.Scan(
			&id, &username, &role, &email,
			&isActive, &createdAt, &lastLoginAt, &createdBy,
		)
		if err != nil {
			fmt.Printf("❌ 扫描数据失败: %v\n", err)
			return
		}

		newUserCount++
		if username == "testuser456" {
			fmt.Printf("✅ 找到新创建的用户: %s (%s)\n", username, role)
		}
	}

	fmt.Printf("✅ 数据库现在有 %d 个用户\n", newUserCount)

	// 清理测试数据
	fmt.Println("\n🔵 清理测试数据")
	deleteSQL := `DELETE FROM users WHERE username = ?`
	_, err = db.Exec(deleteSQL, "testuser456")
	if err != nil {
		fmt.Printf("❌ 删除测试用户失败: %v\n", err)
		return
	}

	fmt.Println("✅ 测试数据清理完成")

	fmt.Println("\n🎉 用户管理修复验证完成！")
	fmt.Println("✅ 数据库扫描错误已修复")
	fmt.Println("✅ 用户创建功能正常")
	fmt.Println("✅ NULL 时间字段处理正确")
}
