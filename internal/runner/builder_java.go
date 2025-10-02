package runner

import (
	"fmt"
	"path/filepath"
	"strings"
)

// JavaBuilder Java 应用构建器
type JavaBuilder struct {
	*BaseBuilder
}

// NewJavaBuilder 创建 Java 构建器
func NewJavaBuilder(gs *GitServer) *JavaBuilder {
	return &JavaBuilder{
		BaseBuilder: NewBaseBuilder("java", "Java", 8080, gs),
	}
}

// Detect 检测是否为 Java 应用
func (b *JavaBuilder) Detect(appPath string) (bool, error) {
	// 检查构建文件
	return b.anyFileExists(appPath, []string{
		"pom.xml",          // Maven
		"build.gradle",     // Gradle
		"build.gradle.kts", // Gradle Kotlin DSL
		"gradlew",          // Gradle Wrapper
	}), nil
}

// Build 构建应用
func (b *JavaBuilder) Build(app *GitApp) error {
	buildTool := b.detectBuildTool(app.GitPath)

	switch buildTool {
	case "maven":
		return b.buildWithMaven(app.GitPath)
	case "gradle":
		return b.buildWithGradle(app.GitPath)
	default:
		return fmt.Errorf("未检测到有效的 Java 构建工具")
	}
}

// BuildWithLogging 构建应用（带日志）
func (b *JavaBuilder) BuildWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "java", "开始 Java 应用构建流程")

	buildTool := b.detectBuildTool(app.GitPath)
	logger.WriteLog("info", "java", fmt.Sprintf("检测到构建工具: %s", buildTool))

	var err error
	switch buildTool {
	case "maven":
		err = b.buildWithMavenLogging(app.GitPath, logger)
	case "gradle":
		err = b.buildWithGradleLogging(app.GitPath, logger)
	default:
		return fmt.Errorf("未检测到有效的 Java 构建工具")
	}

	if err != nil {
		return err
	}

	logger.WriteLog("info", "java", "构建完成")
	return nil
}

// Start 启动应用
func (b *JavaBuilder) Start(app *GitApp) error {
	jarPath := b.findJarFile(app.GitPath)
	if jarPath == "" {
		return fmt.Errorf("未找到可执行的 JAR 文件")
	}

	startCommand := fmt.Sprintf("java -jar %s --server.port=${PORT:-8080}", jarPath)
	return b.startProcess(app, startCommand)
}

// StartWithLogging 启动应用（带日志）
func (b *JavaBuilder) StartWithLogging(app *GitApp, logger *DeployLogger) error {
	logger.WriteLog("info", "java", "启动 Java 应用...")

	jarPath := b.findJarFile(app.GitPath)
	if jarPath == "" {
		return fmt.Errorf("未找到可执行的 JAR 文件")
	}

	logger.WriteLog("info", "java", fmt.Sprintf("找到 JAR 文件: %s", jarPath))
	startCommand := fmt.Sprintf("java -jar %s --server.port=${PORT:-8080}", jarPath)
	logger.WriteLog("info", "java", fmt.Sprintf("启动命令: %s", startCommand))

	if err := b.startProcessWithLogging(app, startCommand, logger); err != nil {
		return fmt.Errorf("启动失败: %w", err)
	}

	logger.WriteLog("info", "java", "应用启动成功")
	return nil
}

// detectBuildTool 检测构建工具
func (b *JavaBuilder) detectBuildTool(appPath string) string {
	if b.fileExists(appPath, "pom.xml") {
		return "maven"
	}
	if b.anyFileExists(appPath, []string{"build.gradle", "build.gradle.kts", "gradlew"}) {
		return "gradle"
	}
	return ""
}

// buildWithMaven 使用 Maven 构建
func (b *JavaBuilder) buildWithMaven(appPath string) error {
	// 使用 Maven Wrapper 如果存在
	mvnCmd := "mvn"
	if b.fileExists(appPath, "mvnw") {
		mvnCmd = "./mvnw"
	}

	if err := b.runCommand(appPath, mvnCmd, "clean", "package", "-DskipTests"); err != nil {
		return fmt.Errorf("Maven 构建失败: %w", err)
	}

	return nil
}

// buildWithMavenLogging 使用 Maven 构建（带日志）
func (b *JavaBuilder) buildWithMavenLogging(appPath string, logger *DeployLogger) error {
	mvnCmd := "mvn"
	if b.fileExists(appPath, "mvnw") {
		mvnCmd = "./mvnw"
	}

	logger.WriteLog("info", "java", "执行 Maven 构建...")
	if err := b.runCommandWithLogging(appPath, logger, mvnCmd, "clean", "package", "-DskipTests"); err != nil {
		return fmt.Errorf("Maven 构建失败: %w", err)
	}

	return nil
}

// buildWithGradle 使用 Gradle 构建
func (b *JavaBuilder) buildWithGradle(appPath string) error {
	// 使用 Gradle Wrapper 如果存在
	gradleCmd := "gradle"
	if b.fileExists(appPath, "gradlew") {
		gradleCmd = "./gradlew"
	}

	if err := b.runCommand(appPath, gradleCmd, "clean", "build", "-x", "test"); err != nil {
		return fmt.Errorf("Gradle 构建失败: %w", err)
	}

	return nil
}

// buildWithGradleLogging 使用 Gradle 构建（带日志）
func (b *JavaBuilder) buildWithGradleLogging(appPath string, logger *DeployLogger) error {
	gradleCmd := "gradle"
	if b.fileExists(appPath, "gradlew") {
		gradleCmd = "./gradlew"
	}

	logger.WriteLog("info", "java", "执行 Gradle 构建...")
	if err := b.runCommandWithLogging(appPath, logger, gradleCmd, "clean", "build", "-x", "test"); err != nil {
		return fmt.Errorf("Gradle 构建失败: %w", err)
	}

	return nil
}

// findJarFile 查找生成的 JAR 文件
func (b *JavaBuilder) findJarFile(appPath string) string {
	// Maven 默认输出目录
	targetDir := filepath.Join(appPath, "target")
	if jarPath := b.findJarInDir(targetDir); jarPath != "" {
		return jarPath
	}

	// Gradle 默认输出目录
	buildDir := filepath.Join(appPath, "build", "libs")
	if jarPath := b.findJarInDir(buildDir); jarPath != "" {
		return jarPath
	}

	return ""
}

// findJarInDir 在目录中查找 JAR 文件
func (b *JavaBuilder) findJarInDir(dir string) string {
	entries, err := filepath.Glob(filepath.Join(dir, "*.jar"))
	if err != nil || len(entries) == 0 {
		return ""
	}

	// 优先选择非 sources 和 javadoc 的 JAR
	for _, entry := range entries {
		name := filepath.Base(entry)
		if !strings.Contains(name, "sources") && !strings.Contains(name, "javadoc") {
			return entry
		}
	}

	return entries[0]
}

// GetDefaultPort Java 默认端口（Spring Boot）
func (b *JavaBuilder) GetDefaultPort() int {
	return 8080
}
