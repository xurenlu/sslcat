package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RubyBuilder Ruby 应用构建器
type RubyBuilder struct {
	*BaseBuilder
}

// NewRubyBuilder 创建 Ruby 构建器
func NewRubyBuilder(gs *GitServer) *RubyBuilder {
	return &RubyBuilder{
		BaseBuilder: NewBaseBuilder("ruby", "Ruby", 3000, gs),
	}
}

// Detect 检测是否为 Ruby 应用
func (b *RubyBuilder) Detect(appPath string) (bool, error) {
	// 检查 Gemfile 或 config.ru（Rack 应用）
	return b.fileExists(appPath, "Gemfile") || b.fileExists(appPath, "config.ru"), nil
}

// Build 构建应用
func (b *RubyBuilder) Build(app *GitApp) error {
	// 安装依赖
	if b.fileExists(app.GitPath, "Gemfile") {
		if err := b.runCommand(app.GitPath, "bundle", "install", "--deployment", "--without", "development", "test"); err != nil {
			return fmt.Errorf("bundle install 失败: %w", err)
		}
	}

	// 检测 Rails 应用并预编译资产
	if b.isRailsApp(app.GitPath) {
		// Rails 资产预编译
		if err := b.runCommand(app.GitPath, "bundle", "exec", "rake", "assets:precompile"); err != nil {
			// 资产预编译失败不阻止部署
			fmt.Printf("警告: Rails 资产预编译失败: %v\n", err)
		}

		// 数据库迁移（如果需要）
		if b.fileExists(app.GitPath, "db/migrate") {
			if err := b.runCommand(app.GitPath, "bundle", "exec", "rake", "db:migrate"); err != nil {
				fmt.Printf("警告: 数据库迁移失败: %v\n", err)
			}
		}
	}

	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *RubyBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "ruby", "开始 Ruby 应用构建流程")

	framework := b.detectFramework(app.GitPath)
	logger.WriteLog("info", "ruby", fmt.Sprintf("检测到框架: %s", framework))

	// 安装依赖
	if b.fileExists(app.GitPath, "Gemfile") {
		logger.WriteLog("info", "ruby", "安装 Gem 依赖...")
		if err := b.runCommandWithLogging(app.GitPath, logger, "bundle", "install", "--deployment"); err != nil {
			return fmt.Errorf("bundle install 失败: %w", err)
		}
	}

	// Rails 特殊处理
	if b.isRailsApp(app.GitPath) {
		logger.WriteLog("info", "ruby", "检测到 Rails 应用，执行资产预编译...")
		if err := b.runCommandWithLogging(app.GitPath, logger, "bundle", "exec", "rake", "assets:precompile", "RAILS_ENV=production"); err != nil {
			logger.WriteLog("warn", "ruby", "资产预编译失败，继续部署")
		}

		logger.WriteLog("info", "ruby", "执行数据库迁移...")
		if err := b.runCommandWithLogging(app.GitPath, logger, "bundle", "exec", "rake", "db:migrate", "RAILS_ENV=production"); err != nil {
			logger.WriteLog("warn", "ruby", "数据库迁移失败，继续部署")
		}
	}

	logger.WriteLog("info", "ruby", "构建完成")
	return nil
}

// Start 启动应用
func (b *RubyBuilder) Start(app *GitApp) error {
	startCommand := b.getStartCommand(app.GitPath)
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *RubyBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "ruby", "启动 Ruby 应用...")
	startCommand := b.getStartCommand(app.GitPath)
	logger.WriteLog("info", "ruby", fmt.Sprintf("启动命令: %s", startCommand))

	if err := b.startProcessWithLogging(app, startCommand, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "ruby", "应用启动成功")
	return nil
}

// isRailsApp 检查是否为 Rails 应用
func (b *RubyBuilder) isRailsApp(appPath string) bool {
	// 检查 Rails 特征文件
	return b.fileExists(appPath, "config/application.rb") &&
		b.fileExists(appPath, "config/environment.rb")
}

// detectFramework 检测 Ruby 框架
func (b *RubyBuilder) detectFramework(appPath string) string {
	if b.isRailsApp(appPath) {
		return "Rails"
	}

	// 检查 Gemfile 内容
	gemfile := b.readGemfile(appPath)
	if strings.Contains(gemfile, "sinatra") {
		return "Sinatra"
	}
	if strings.Contains(gemfile, "hanami") {
		return "Hanami"
	}
	if strings.Contains(gemfile, "padrino") {
		return "Padrino"
	}

	if b.fileExists(appPath, "config.ru") {
		return "Rack"
	}

	return "Ruby"
}

// getStartCommand 获取启动命令
func (b *RubyBuilder) getStartCommand(appPath string) string {
	// Rails 应用
	if b.isRailsApp(appPath) {
		return "bundle exec rails server -p ${PORT:-3000} -e production"
	}

	// Rack 应用（包括 Sinatra）
	if b.fileExists(appPath, "config.ru") {
		return "bundle exec rackup config.ru -p ${PORT:-3000}"
	}

	// 纯 Ruby 脚本
	if b.fileExists(appPath, "app.rb") {
		return "bundle exec ruby app.rb"
	}
	if b.fileExists(appPath, "server.rb") {
		return "bundle exec ruby server.rb"
	}

	return "bundle exec ruby app.rb"
}

// readGemfile 读取 Gemfile 内容
func (b *RubyBuilder) readGemfile(appPath string) string {
	data, err := os.ReadFile(filepath.Join(appPath, "Gemfile"))
	if err != nil {
		return ""
	}
	return string(data)
}

// GetDefaultPort Ruby 默认端口
func (b *RubyBuilder) GetDefaultPort() int {
	return 3000
}
