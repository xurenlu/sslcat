package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/xurenlu/sslcat/internal/runner"
)

func TestDeploymentSystem() {
	// 创建临时目录
	tempDir := "/tmp/sslcat_deployment_test"
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fmt.Println("🧪 测试发布管理系统...")

	// 1. 初始化发布数据库
	fmt.Println("📊 初始化发布数据库...")
	db, err := runner.NewDeploymentDatabase(tempDir)
	if err != nil {
		log.Fatalf("初始化发布数据库失败: %v", err)
	}
	defer db.Close()

	// 2. 创建发布日志记录器
	fmt.Println("📝 创建发布日志记录器...")
	deployLogger, err := runner.NewDeploymentLogger(
		"test-app",
		"abc123def456",
		"main",
		"test-user",
		"Test deployment",
		db,
		tempDir,
	)
	if err != nil {
		log.Fatalf("创建发布日志记录器失败: %v", err)
	}
	defer deployLogger.Close()

	// 3. 模拟部署过程
	fmt.Println("🚀 模拟部署过程...")
	
	// 设置状态回调
	deployLogger.SetStatusCallback(func(status string, progress int, message string) {
		fmt.Printf("📡 状态更新: %s (%d%%) - %s\n", status, progress, message)
	})

	// 写入一些日志
	deployLogger.WriteLog("info", "git", "开始检测应用类型")
	deployLogger.UpdateStatus("building", 20, "检测应用类型")
	
	time.Sleep(100 * time.Millisecond)
	
	deployLogger.WriteLog("info", "build", "执行构建命令")
	deployLogger.UpdateStatus("building", 50, "构建应用")
	
	time.Sleep(100 * time.Millisecond)
	
	deployLogger.WriteLog("info", "deploy", "启动应用")
	deployLogger.UpdateStatus("deploying", 80, "部署应用")
	
	time.Sleep(100 * time.Millisecond)
	
	deployLogger.WriteLog("info", "deploy", "部署完成")
	deployLogger.UpdateStatus("success", 100, "部署成功")

	// 4. 查询发布记录
	fmt.Println("📋 查询发布记录...")
	deployments, err := db.GetDeployments("test-app", 10, 0)
	if err != nil {
		log.Fatalf("查询发布记录失败: %v", err)
	}

	fmt.Printf("📊 找到 %d 个发布记录:\n", len(deployments))
	for _, deployment := range deployments {
		fmt.Printf("  - UUID: %s\n", deployment.UUID)
		fmt.Printf("    应用: %s\n", deployment.AppName)
		fmt.Printf("    提交: %s\n", deployment.CommitSHA)
		fmt.Printf("    分支: %s\n", deployment.Branch)
		fmt.Printf("    状态: %s\n", deployment.Status)
		fmt.Printf("    开始时间: %s\n", deployment.StartedAt.Format("2006-01-02 15:04:05"))
		if deployment.CompletedAt != nil {
			fmt.Printf("    完成时间: %s\n", deployment.CompletedAt.Format("2006-01-02 15:04:05"))
		}
		if deployment.BuildDuration != nil {
			fmt.Printf("    构建耗时: %d ms\n", *deployment.BuildDuration)
		}
		fmt.Println()
	}

	// 5. 查询发布日志
	if len(deployments) > 0 {
		fmt.Println("📝 查询发布日志...")
		logs, err := db.GetDeploymentLogs(deployments[0].UUID, 10, 0)
		if err != nil {
			log.Fatalf("查询发布日志失败: %v", err)
		}

		fmt.Printf("📊 找到 %d 条日志记录:\n", len(logs))
		for _, logEntry := range logs {
			fmt.Printf("  - [%s] [%s] %s: %s\n", 
				logEntry.Timestamp.Format("15:04:05"),
				logEntry.Level,
				logEntry.Source,
				logEntry.Message,
			)
		}
		fmt.Println()
	}

	// 6. 查询发布状态
	if len(deployments) > 0 {
		fmt.Println("📊 查询发布状态...")
		statuses, err := db.GetDeploymentStatus(deployments[0].UUID)
		if err != nil {
			log.Fatalf("查询发布状态失败: %v", err)
		}

		fmt.Printf("📊 找到 %d 个状态记录:\n", len(statuses))
		for _, status := range statuses {
			fmt.Printf("  - [%s] %s (%d%%): %s\n",
				status.Timestamp.Format("15:04:05"),
				status.Status,
				status.Progress,
				status.Message,
			)
		}
		fmt.Println()
	}

	fmt.Println("✅ 测试完成！发布管理系统工作正常。")
}
