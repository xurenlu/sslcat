package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/xurenlu/sslcat/internal/database"
)

func main() {
	fmt.Println("🔧 SQLite驱动测试工具")
	fmt.Println("====================")
	fmt.Println()

	// 创建测试数据库路径
	dataDir := "./data"
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		fmt.Printf("❌ 创建数据目录失败: %v\n", err)
		return
	}

	dbPath := filepath.Join(dataDir, "test.db")
	fmt.Printf("📁 测试数据库路径: %s\n", dbPath)

	// 打开数据库
	fmt.Println("🔗 连接数据库...")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Printf("❌ 打开数据库失败: %v\n", err)
		return
	}
	defer db.Close()

	// 测试连接
	fmt.Println("🧪 测试数据库连接...")
	if err := db.Ping(); err != nil {
		fmt.Printf("❌ 数据库连接失败: %v\n", err)
		return
	}

	// 创建测试表
	fmt.Println("📋 创建测试表...")
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS test_table (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	if _, err := db.Exec(createTableSQL); err != nil {
		fmt.Printf("❌ 创建表失败: %v\n", err)
		return
	}

	// 插入测试数据
	fmt.Println("📝 插入测试数据...")
	insertSQL := "INSERT INTO test_table (name) VALUES (?)"
	result, err := db.Exec(insertSQL, "测试数据")
	if err != nil {
		fmt.Printf("❌ 插入数据失败: %v\n", err)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		fmt.Printf("❌ 获取插入ID失败: %v\n", err)
		return
	}

	// 查询测试数据
	fmt.Println("🔍 查询测试数据...")
	querySQL := "SELECT id, name, created_at FROM test_table WHERE id = ?"
	row := db.QueryRow(querySQL, id)

	var testID int
	var name string
	var createdAt string

	if err := row.Scan(&testID, &name, &createdAt); err != nil {
		fmt.Printf("❌ 查询数据失败: %v\n", err)
		return
	}

	// 显示结果
	fmt.Println("✅ SQLite驱动测试成功!")
	fmt.Printf("   ID: %d\n", testID)
	fmt.Printf("   名称: %s\n", name)
	fmt.Printf("   创建时间: %s\n", createdAt)

	// 清理测试数据
	fmt.Println("🧹 清理测试数据...")
	if _, err := db.Exec("DELETE FROM test_table WHERE id = ?", id); err != nil {
		fmt.Printf("⚠️  清理数据失败: %v\n", err)
	}

	// 删除测试数据库
	if err := os.Remove(dbPath); err != nil {
		fmt.Printf("⚠️  删除测试数据库失败: %v\n", err)
	}

	fmt.Println()
	fmt.Println("🎉 所有测试通过！SQLite驱动工作正常。")
}
