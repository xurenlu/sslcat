package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PHPBuilder PHP 应用构建器
type PHPBuilder struct {
	*BaseBuilder
}

// NewPHPBuilder 创建 PHP 构建器
func NewPHPBuilder(gs *GitServer) *PHPBuilder {
	return &PHPBuilder{
		BaseBuilder: NewBaseBuilder("php", "PHP", 8000, gs),
	}
}

// Detect 检测是否为 PHP 应用
func (b *PHPBuilder) Detect(appPath string) (bool, error) {
	// 检查 composer.json 或 index.php
	return b.fileExists(appPath, "composer.json") || b.fileExists(appPath, "index.php"), nil
}

// Build 构建应用
func (b *PHPBuilder) Build(app *GitApp) error {
	// 安装 Composer 依赖
	if b.fileExists(app.GitPath, "composer.json") {
		if err := b.runCommand(app.GitPath, "composer", "install", "--no-dev", "--optimize-autoloader"); err != nil {
			return fmt.Errorf("composer install 失败: %w", err)
		}
	}

	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *PHPBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "php", "开始 PHP 应用构建流程")

	framework := b.detectFramework(app.GitPath)
	if framework != "" {
		logger.WriteLog("info", "php", fmt.Sprintf("检测到框架: %s", framework))
	}

	// 安装依赖
	if b.fileExists(app.GitPath, "composer.json") {
		logger.WriteLog("info", "php", "安装 Composer 依赖...")
		if err := b.runCommandWithLogging(app.GitPath, logger, "composer", "install", "--no-dev", "--optimize-autoloader"); err != nil {
			return fmt.Errorf("composer install 失败: %w", err)
		}
	}

	// Laravel 特殊处理
	if framework == "Laravel" {
		logger.WriteLog("info", "php", "执行 Laravel 优化...")
		// 生成缓存
		b.runCommandWithLogging(app.GitPath, logger, "php", "artisan", "config:cache")
		b.runCommandWithLogging(app.GitPath, logger, "php", "artisan", "route:cache")
		b.runCommandWithLogging(app.GitPath, logger, "php", "artisan", "view:cache")
	}

	logger.WriteLog("info", "php", "构建完成")
	return nil
}

// Start 启动应用
func (b *PHPBuilder) Start(app *GitApp) error {
	startCommand := b.getStartCommand(app.GitPath)
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *PHPBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "php", "启动 PHP 应用...")
	startCommand := b.getStartCommand(app.GitPath)
	logger.WriteLog("info", "php", fmt.Sprintf("启动命令: %s", startCommand))

	if err := b.startProcessWithLogging(app, startCommand, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "php", "应用启动成功")
	return nil
}

// detectFramework 检测 PHP 框架
func (b *PHPBuilder) detectFramework(appPath string) string {
	// 检查 Laravel
	if b.fileExists(appPath, "artisan") {
		return "Laravel"
	}

	// 检查 Symfony
	if b.fileExists(appPath, "bin/console") && b.fileExists(appPath, "symfony.lock") {
		return "Symfony"
	}

	// 检查 composer.json
	if b.fileExists(appPath, "composer.json") {
		data, err := os.ReadFile(filepath.Join(appPath, "composer.json"))
		if err == nil {
			var composer struct {
				Require map[string]string `json:"require"`
			}
			if json.Unmarshal(data, &composer) == nil {
				for pkg := range composer.Require {
					pkgLower := strings.ToLower(pkg)
					if strings.Contains(pkgLower, "laravel/framework") {
						return "Laravel"
					}
					if strings.Contains(pkgLower, "symfony/symfony") {
						return "Symfony"
					}
					if strings.Contains(pkgLower, "codeigniter4/framework") {
						return "CodeIgniter"
					}
					if strings.Contains(pkgLower, "slim/slim") {
						return "Slim"
					}
				}
			}
		}
	}

	return "PHP"
}

// getStartCommand 获取启动命令
func (b *PHPBuilder) getStartCommand(appPath string) string {
	framework := b.detectFramework(appPath)

	// Laravel 应用
	if framework == "Laravel" {
		return "php artisan serve --host=0.0.0.0 --port=${PORT:-8000}"
	}

	// Symfony 应用
	if framework == "Symfony" {
		return "symfony server:start --port=${PORT:-8000} --no-tls"
	}

	// 通用 PHP 应用（使用内置服务器）
	// 检测文档根目录
	docRoot := "."
	if b.fileExists(appPath, "public/index.php") {
		docRoot = "public"
	}

	return fmt.Sprintf("php -S 0.0.0.0:${PORT:-8000} -t %s", docRoot)
}

// GetDefaultPort PHP 默认端口
func (b *PHPBuilder) GetDefaultPort() int {
	return 8000
}
