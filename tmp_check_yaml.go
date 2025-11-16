package main

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run tmp_check_yaml.go <yaml文件>")
		os.Exit(1)
	}

	filePath := os.Args[1]
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("无法打开文件: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var data interface{}
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&data); err != nil {
		fmt.Printf("YAML格式错误: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("YAML格式正确")
}

