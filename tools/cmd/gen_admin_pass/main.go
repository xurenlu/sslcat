// gen_admin_pass 生成并覆盖 admin.pass 文件
// 用法: go run ./tools/cmd/gen_admin_pass/main.go <新密码> [输出路径]
// 示例: go run ./tools/cmd/gen_admin_pass/main.go myNewPassword
// 示例: go run ./tools/cmd/gen_admin_pass/main.go myNewPassword ./data/admin.pass
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run main.go <新密码> [输出路径]")
		fmt.Println("示例: go run main.go myNewPassword")
		fmt.Println("示例: go run main.go myNewPassword ./data/admin.pass")
		os.Exit(1)
	}

	password := os.Args[1]
	passFile := "./data/admin.pass"
	if len(os.Args) >= 3 {
		passFile = os.Args[2]
	}

	// 支持环境变量指定数据目录
	if envDataDir := os.Getenv("SSLcat_DATA_DIR"); envDataDir != "" && passFile == "./data/admin.pass" {
		passFile = filepath.Join(envDataDir, "admin.pass")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("生成 bcrypt 哈希失败: %v\n", err)
		os.Exit(1)
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(passFile), 0755); err != nil {
		fmt.Printf("创建目录失败: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(passFile, append(hash, '\n'), 0600); err != nil {
		fmt.Printf("写入文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("已成功覆盖 %s，新密码已生效。\n", passFile)
}
