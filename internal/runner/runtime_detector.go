package runner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// RuntimeDetector 运行时检测器
type RuntimeDetector struct{}

// NewRuntimeDetector 创建新的运行时检测器
func NewRuntimeDetector() *RuntimeDetector {
	return &RuntimeDetector{}
}

// DetectProjectType 检测项目类型
func (rd *RuntimeDetector) DetectProjectType(projectPath string) (*ProjectInfo, error) {
	info := &ProjectInfo{
		Path: projectPath,
	}

	// 检测 Dockerfile
	info.HasDockerfile = rd.hasFile(projectPath, "Dockerfile")

	// 检测 docker-compose 文件
	info.HasDockerCompose = rd.hasAnyFile(projectPath, []string{"docker-compose.yml", "docker-compose.yaml"})

	// 如果有 Dockerfile 或 docker-compose，优先使用
	if info.HasDockerfile {
		info.Type = "dockerfile"
		info.Runtime = "docker"
		return info, nil
	}
	if info.HasDockerCompose {
		info.Type = "dockercompose"
		info.Runtime = "docker"
		return info, nil
	}

	// 检测其他运行时
	runtime := rd.detectRuntime(projectPath)
	info.Runtime = runtime
	info.Type = runtime

	// 检测构建工具和框架
	rd.detectBuildTools(projectPath, info)
	rd.detectFrameworks(projectPath, info)

	return info, nil
}

// detectRuntime 检测运行时类型
func (rd *RuntimeDetector) detectRuntime(projectPath string) string {
	// 最高优先级：Dockerfile
	if rd.hasFile(projectPath, "Dockerfile") {
		return "docker"
	}

	// 检查 Deno 项目
	if rd.hasAnyFile(projectPath, []string{"deno.json", "deno.jsonc"}) {
		return "deno"
	}

	// 检查 Bun 项目
	if rd.hasFile(projectPath, "bun.lockb") || rd.hasFile(projectPath, "bunfig.toml") {
		return "bun"
	}

	// 检查 Node.js 项目
	if rd.hasFile(projectPath, "package.json") {
		return "nodejs"
	}

	// 检查 Python 项目
	if rd.hasAnyFile(projectPath, []string{"requirements.txt", "setup.py", "pyproject.toml", "Pipfile"}) {
		return "python"
	}

	// 检查 Go 项目
	if rd.hasFile(projectPath, "go.mod") {
		return "golang"
	}

	// 检查 Rust 项目
	if rd.hasFile(projectPath, "Cargo.toml") {
		return "rust"
	}

	// 检查 Java 项目
	if rd.hasAnyFile(projectPath, []string{"pom.xml", "build.gradle", "build.gradle.kts"}) {
		return "java"
	}

	// 检查 .NET 项目
	if rd.hasFile(projectPath, "*.csproj") || rd.hasFile(projectPath, "*.fsproj") || rd.hasFile(projectPath, "*.vbproj") || rd.hasFile(projectPath, "*.sln") {
		return "dotnet"
	}

	// 检查 Ruby 项目
	if rd.hasFile(projectPath, "Gemfile") || rd.hasFile(projectPath, "config.ru") {
		return "ruby"
	}

	// 检查 PHP 项目
	if rd.hasFile(projectPath, "composer.json") || rd.hasFile(projectPath, "index.php") {
		return "php"
	}

	// 检查静态文件
	if rd.hasAnyFile(projectPath, []string{"index.html", "index.htm"}) {
		return "static"
	}

	// 检查 C/C++ 项目
	if rd.hasAnyFile(projectPath, []string{"Makefile", "CMakeLists.txt", "configure", "*.c", "*.cpp"}) {
		return "c"
	}

	return "unknown"
}

// detectBuildTools 检测构建工具
func (rd *RuntimeDetector) detectBuildTools(projectPath string, info *ProjectInfo) {
	// Go 构建工具
	if rd.hasFile(projectPath, "go.mod") {
		info.BuildTools = append(info.BuildTools, "go")
	}

	// Node.js 构建工具
	if rd.hasFile(projectPath, "package.json") {
		info.BuildTools = append(info.BuildTools, "npm")

		// 检查其他包管理器
		if rd.hasFile(projectPath, "yarn.lock") {
			info.BuildTools = append(info.BuildTools, "yarn")
		}
		if rd.hasFile(projectPath, "pnpm-lock.yaml") {
			info.BuildTools = append(info.BuildTools, "pnpm")
		}
	}

	// Python 构建工具
	if rd.hasFile(projectPath, "requirements.txt") {
		info.BuildTools = append(info.BuildTools, "pip")
	}
	if rd.hasFile(projectPath, "Pipfile") {
		info.BuildTools = append(info.BuildTools, "pipenv")
	}
	if rd.hasFile(projectPath, "pyproject.toml") {
		info.BuildTools = append(info.BuildTools, "poetry")
	}

	// Java 构建工具
	if rd.hasFile(projectPath, "pom.xml") {
		info.BuildTools = append(info.BuildTools, "maven")
	}
	if rd.hasFile(projectPath, "build.gradle") {
		info.BuildTools = append(info.BuildTools, "gradle")
	}

	// PHP 构建工具
	if rd.hasFile(projectPath, "composer.json") {
		info.BuildTools = append(info.BuildTools, "composer")
	}

	// Ruby 构建工具
	if rd.hasFile(projectPath, "Gemfile") {
		info.BuildTools = append(info.BuildTools, "bundle")
	}

	// Rust 构建工具
	if rd.hasFile(projectPath, "Cargo.toml") {
		info.BuildTools = append(info.BuildTools, "cargo")
	}
}

// detectFrameworks 检测框架
func (rd *RuntimeDetector) detectFrameworks(projectPath string, info *ProjectInfo) {
	// 检查 package.json 中的依赖
	if rd.hasFile(projectPath, "package.json") {
		packageJSON := rd.readPackageJSON(projectPath)
		if packageJSON != nil {
			rd.detectNodeFrameworks(packageJSON, info)
		}
	}

	// 检查 requirements.txt 中的依赖
	if rd.hasFile(projectPath, "requirements.txt") {
		requirements := rd.readRequirements(projectPath)
		rd.detectPythonFrameworks(requirements, info)
	}

	// 检查 composer.json 中的依赖
	if rd.hasFile(projectPath, "composer.json") {
		composerJSON := rd.readComposerJSON(projectPath)
		if composerJSON != nil {
			rd.detectPHPFrameworks(composerJSON, info)
		}
	}

	// 检查 Gemfile 中的依赖
	if rd.hasFile(projectPath, "Gemfile") {
		gemfile := rd.readGemfile(projectPath)
		rd.detectRubyFrameworks(gemfile, info)
	}

	// 检查 Go 模块
	if rd.hasFile(projectPath, "go.mod") {
		goMod := rd.readGoMod(projectPath)
		rd.detectGoFrameworks(goMod, info)
	}
}

// detectNodeFrameworks 检测 Node.js 框架
func (rd *RuntimeDetector) detectNodeFrameworks(pkg *PackageJSON, info *ProjectInfo) {
	deps := make(map[string]string)

	// 合并所有依赖
	for name, version := range pkg.Dependencies {
		deps[name] = version
	}
	for name, version := range pkg.DevDependencies {
		deps[name] = version
	}

	// 检测框架
	if _, exists := deps["express"]; exists {
		info.Frameworks = append(info.Frameworks, "express")
	}
	if _, exists := deps["koa"]; exists {
		info.Frameworks = append(info.Frameworks, "koa")
	}
	if _, exists := deps["fastify"]; exists {
		info.Frameworks = append(info.Frameworks, "fastify")
	}
	if _, exists := deps["next"]; exists {
		info.Frameworks = append(info.Frameworks, "nextjs")
		info.Type = "nextjs"
	}
	if _, exists := deps["react"]; exists {
		info.Frameworks = append(info.Frameworks, "react")
	}
	if _, exists := deps["vue"]; exists {
		info.Frameworks = append(info.Frameworks, "vue")
	}
	if _, exists := deps["angular"]; exists {
		info.Frameworks = append(info.Frameworks, "angular")
	}
	if _, exists := deps["svelte"]; exists {
		info.Frameworks = append(info.Frameworks, "svelte")
	}
}

// detectPythonFrameworks 检测 Python 框架
func (rd *RuntimeDetector) detectPythonFrameworks(requirements []string, info *ProjectInfo) {
	for _, req := range requirements {
		req = strings.ToLower(strings.TrimSpace(req))

		if strings.Contains(req, "django") {
			info.Frameworks = append(info.Frameworks, "django")
		}
		if strings.Contains(req, "flask") {
			info.Frameworks = append(info.Frameworks, "flask")
		}
		if strings.Contains(req, "fastapi") {
			info.Frameworks = append(info.Frameworks, "fastapi")
		}
		if strings.Contains(req, "tornado") {
			info.Frameworks = append(info.Frameworks, "tornado")
		}
		if strings.Contains(req, "aiohttp") {
			info.Frameworks = append(info.Frameworks, "aiohttp")
		}
	}
}

// detectPHPFrameworks 检测 PHP 框架
func (rd *RuntimeDetector) detectPHPFrameworks(composer *ComposerJSON, info *ProjectInfo) {
	deps := make(map[string]string)

	// 合并所有依赖
	for name, version := range composer.Require {
		deps[name] = version
	}
	for name, version := range composer.RequireDev {
		deps[name] = version
	}

	// 检测主流框架
	if _, exists := deps["laravel/framework"]; exists {
		info.Frameworks = append(info.Frameworks, "laravel")
	}
	if _, exists := deps["symfony/symfony"]; exists {
		info.Frameworks = append(info.Frameworks, "symfony")
	}
	if _, exists := deps["codeigniter/framework"]; exists {
		info.Frameworks = append(info.Frameworks, "codeigniter")
	}
	if _, exists := deps["cakephp/cakephp"]; exists {
		info.Frameworks = append(info.Frameworks, "cakephp")
	}

	// 检测更多现代 PHP 框架
	if _, exists := deps["slim/slim"]; exists {
		info.Frameworks = append(info.Frameworks, "slim")
	}
	if _, exists := deps["yiisoft/yii2"]; exists {
		info.Frameworks = append(info.Frameworks, "yii2")
	}
	if _, exists := deps["zendframework/zendframework"]; exists {
		info.Frameworks = append(info.Frameworks, "zend")
	}
	if _, exists := deps["phalcon/cphalcon"]; exists {
		info.Frameworks = append(info.Frameworks, "phalcon")
	}
	if _, exists := deps["spiral/framework"]; exists {
		info.Frameworks = append(info.Frameworks, "spiral")
	}
	if _, exists := deps["hyperf/hyperf"]; exists {
		info.Frameworks = append(info.Frameworks, "hyperf")
	}

	// 检测 CMS 系统
	if _, exists := deps["drupal/core"]; exists {
		info.Frameworks = append(info.Frameworks, "drupal")
	}
	if _, exists := deps["wordpress/wordpress"]; exists {
		info.Frameworks = append(info.Frameworks, "wordpress")
	}
	if _, exists := deps["magento/magento2-base"]; exists {
		info.Frameworks = append(info.Frameworks, "magento2")
	}
}

// detectRubyFrameworks 检测 Ruby 框架
func (rd *RuntimeDetector) detectRubyFrameworks(gemfile []string, info *ProjectInfo) {
	for _, line := range gemfile {
		line = strings.ToLower(strings.TrimSpace(line))

		if strings.Contains(line, "rails") {
			info.Frameworks = append(info.Frameworks, "rails")
		}
		if strings.Contains(line, "sinatra") {
			info.Frameworks = append(info.Frameworks, "sinatra")
		}
		if strings.Contains(line, "hanami") {
			info.Frameworks = append(info.Frameworks, "hanami")
		}
	}
}

// detectGoFrameworks 检测 Go 框架
func (rd *RuntimeDetector) detectGoFrameworks(goMod []string, info *ProjectInfo) {
	for _, line := range goMod {
		line = strings.ToLower(strings.TrimSpace(line))

		if strings.Contains(line, "github.com/gin-gonic/gin") {
			info.Frameworks = append(info.Frameworks, "gin")
		}
		if strings.Contains(line, "github.com/gorilla/mux") {
			info.Frameworks = append(info.Frameworks, "gorilla")
		}
		if strings.Contains(line, "github.com/labstack/echo") {
			info.Frameworks = append(info.Frameworks, "echo")
		}
		if strings.Contains(line, "github.com/gin-gonic/gin") {
			info.Frameworks = append(info.Frameworks, "gin")
		}
	}
}

// hasFile 检查文件是否存在
func (rd *RuntimeDetector) hasFile(projectPath, filename string) bool {
	_, err := os.Stat(filepath.Join(projectPath, filename))
	return err == nil
}

// hasAnyFile 检查任意一个文件是否存在
func (rd *RuntimeDetector) hasAnyFile(projectPath string, filenames []string) bool {
	for _, filename := range filenames {
		if rd.hasFile(projectPath, filename) {
			return true
		}
	}
	return false
}

// readPackageJSON 读取 package.json
func (rd *RuntimeDetector) readPackageJSON(projectPath string) *PackageJSON {
	// 这里应该实现 JSON 解析，简化处理
	return nil
}

// readRequirements 读取 requirements.txt
func (rd *RuntimeDetector) readRequirements(projectPath string) []string {
	file, err := os.Open(filepath.Join(projectPath, "requirements.txt"))
	if err != nil {
		return nil
	}
	defer file.Close()

	var requirements []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			requirements = append(requirements, line)
		}
	}
	return requirements
}

// readComposerJSON 读取 composer.json
func (rd *RuntimeDetector) readComposerJSON(projectPath string) *ComposerJSON {
	// 这里应该实现 JSON 解析，简化处理
	return nil
}

// readGemfile 读取 Gemfile
func (rd *RuntimeDetector) readGemfile(projectPath string) []string {
	file, err := os.Open(filepath.Join(projectPath, "Gemfile"))
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// readGoMod 读取 go.mod
func (rd *RuntimeDetector) readGoMod(projectPath string) []string {
	file, err := os.Open(filepath.Join(projectPath, "go.mod"))
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "//") {
			lines = append(lines, line)
		}
	}
	return lines
}

// ProjectInfo 项目信息
type ProjectInfo struct {
	Path             string   `json:"path"`
	Type             string   `json:"type"`
	Runtime          string   `json:"runtime"`
	HasDockerfile    bool     `json:"has_dockerfile"`
	HasDockerCompose bool     `json:"has_docker_compose"`
	BuildTools       []string `json:"build_tools"`
	Frameworks       []string `json:"frameworks"`
}

// PackageJSON package.json 结构
type PackageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// ComposerJSON composer.json 结构
type ComposerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}
