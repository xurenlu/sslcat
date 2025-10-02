package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PythonBuilder Python 应用构建器
type PythonBuilder struct {
	*BaseBuilder
}

// NewPythonBuilder 创建 Python 构建器
func NewPythonBuilder(gs *GitServer) *PythonBuilder {
	return &PythonBuilder{
		BaseBuilder: NewBaseBuilder("python", "Python", 8000, gs),
	}
}

// Detect 检测是否为 Python 应用
func (b *PythonBuilder) Detect(appPath string) (bool, error) {
	return b.anyFileExists(appPath, []string{
		"requirements.txt",
		"Pipfile",
		"pyproject.toml",
		"setup.py",
	}), nil
}

// Build 构建应用
func (b *PythonBuilder) Build(app *GitApp) error {
	packageManager := b.detectPackageManager(app.GitPath)

	switch packageManager {
	case "poetry":
		if err := b.runCommand(app.GitPath, "poetry", "install", "--no-dev"); err != nil {
			return fmt.Errorf("poetry install 失败: %w", err)
		}
	case "pipenv":
		if err := b.runCommand(app.GitPath, "pipenv", "install", "--deploy"); err != nil {
			return fmt.Errorf("pipenv install 失败: %w", err)
		}
	case "pip":
		if b.fileExists(app.GitPath, "requirements.txt") {
			if err := b.runCommand(app.GitPath, "pip", "install", "-r", "requirements.txt"); err != nil {
				return fmt.Errorf("pip install 失败: %w", err)
			}
		}
	}

	return nil
}

// BuildWithLogging 构建应用（带日志）
func (b *PythonBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "python", "开始 Python 应用构建流程")

	packageManager := b.detectPackageManager(app.GitPath)
	logger.WriteLog("info", "python", fmt.Sprintf("检测到包管理器: %s", packageManager))

	// 安装依赖
	logger.WriteLog("info", "python", "安装依赖...")
	switch packageManager {
	case "poetry":
		if err := b.runCommandWithLogging(app.GitPath, logger, "poetry", "install", "--no-dev"); err != nil {
			return fmt.Errorf("poetry install 失败: %w", err)
		}
	case "pipenv":
		if err := b.runCommandWithLogging(app.GitPath, logger, "pipenv", "install", "--deploy"); err != nil {
			return fmt.Errorf("pipenv install 失败: %w", err)
		}
	case "pip":
		if b.fileExists(app.GitPath, "requirements.txt") {
			if err := b.runCommandWithLogging(app.GitPath, logger, "pip", "install", "-r", "requirements.txt"); err != nil {
				return fmt.Errorf("pip install 失败: %w", err)
			}
		}
	}

	// 检测框架并执行特定构建步骤
	framework := b.detectFramework(app.GitPath)
	if framework != "" {
		logger.WriteLog("info", "python", fmt.Sprintf("检测到框架: %s", framework))
	}

	logger.WriteLog("info", "python", "构建完成")
	return nil
}

// Start 启动应用
func (b *PythonBuilder) Start(app *GitApp) error {
	startCommand := b.getStartCommand(app.GitPath)
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *PythonBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "python", "启动 Python 应用...")
	startCommand := b.getStartCommand(app.GitPath)
	logger.WriteLog("info", "python", fmt.Sprintf("启动命令: %s", startCommand))

	if err := b.startProcessWithLogging(app, startCommand, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "python", "应用启动成功")
	return nil
}

// detectPackageManager 检测包管理器
func (b *PythonBuilder) detectPackageManager(appPath string) string {
	if b.fileExists(appPath, "poetry.lock") || b.fileExists(appPath, "pyproject.toml") {
		return "poetry"
	}
	if b.fileExists(appPath, "Pipfile") {
		return "pipenv"
	}
	return "pip"
}

// detectFramework 检测 Python 框架
func (b *PythonBuilder) detectFramework(appPath string) string {
	// 检查 Django
	if b.fileExists(appPath, "manage.py") {
		return "Django"
	}

	// 检查 requirements.txt
	if b.fileExists(appPath, "requirements.txt") {
		content, err := os.ReadFile(filepath.Join(appPath, "requirements.txt"))
		if err == nil {
			contentStr := strings.ToLower(string(content))
			if strings.Contains(contentStr, "fastapi") {
				return "FastAPI"
			}
			if strings.Contains(contentStr, "flask") {
				return "Flask"
			}
			if strings.Contains(contentStr, "django") {
				return "Django"
			}
		}
	}

	return ""
}

// getStartCommand 获取启动命令
func (b *PythonBuilder) getStartCommand(appPath string) string {
	packageManager := b.detectPackageManager(appPath)
	framework := b.detectFramework(appPath)

	// Django 应用
	if framework == "Django" {
		if packageManager == "poetry" {
			return "poetry run python manage.py runserver 0.0.0.0:${PORT:-8000}"
		} else if packageManager == "pipenv" {
			return "pipenv run python manage.py runserver 0.0.0.0:${PORT:-8000}"
		}
		return "python manage.py runserver 0.0.0.0:${PORT:-8000}"
	}

	// FastAPI/Flask/通用 WSGI 应用
	// 检测常见的入口文件
	entryFiles := []string{"app.py", "main.py", "server.py", "wsgi.py", "application.py"}
	for _, file := range entryFiles {
		if b.fileExists(appPath, file) {
			if packageManager == "poetry" {
				return fmt.Sprintf("poetry run python %s", file)
			} else if packageManager == "pipenv" {
				return fmt.Sprintf("pipenv run python %s", file)
			}
			return fmt.Sprintf("python %s", file)
		}
	}

	// 默认使用 app.py
	if packageManager == "poetry" {
		return "poetry run python app.py"
	} else if packageManager == "pipenv" {
		return "pipenv run python app.py"
	}
	return "python app.py"
}

// GetDefaultPort Python 默认端口
func (b *PythonBuilder) GetDefaultPort() int {
	return 8000
}
