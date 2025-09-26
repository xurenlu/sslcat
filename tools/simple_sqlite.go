package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	fmt.Println("测试SQLite驱动...")
	
	// 检查驱动是否注册
	drivers := sql.Drivers()
	fmt.Printf("已注册的驱动: %v\n", drivers)
	
	// 尝试打开数据库
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		return
	}
	defer db.Close()
	
	fmt.Println("SQLite驱动工作正常！")
}
