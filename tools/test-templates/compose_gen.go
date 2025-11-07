package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// ComposeGenerator Compose 文件生成器
type ComposeGenerator struct {
	basePort int
}

// NewComposeGenerator 创建生成器
func NewComposeGenerator(basePort int) *ComposeGenerator {
	return &ComposeGenerator{
		basePort: basePort,
	}
}

// Generate 生成测试用的 docker-compose.yml
func (cg *ComposeGenerator) Generate(
	templateInfo *TemplateInfo,
	meta *TemplateMeta,
	compose *ComposeFile,
	testPort int,
) (string, error) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("test-template-%s-%d", templateInfo.ID, testPort))
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}

	// 生成变量映射
	variables := cg.buildVariables(templateInfo, meta, testPort)

	// 读取原始 compose 文件
	composePath := filepath.Join(templateInfo.Dir, templateInfo.ComposeFile)
	composeData, err := os.ReadFile(composePath)
	if err != nil {
		return "", fmt.Errorf("读取 compose 文件失败: %w", err)
	}

	// 替换变量
	composeContent := string(composeData)
	for key, value := range variables {
		placeholder := fmt.Sprintf("{{%s}}", key)
		valueStr := fmt.Sprintf("%v", value)
		composeContent = strings.ReplaceAll(composeContent, placeholder, valueStr)
	}

	// 处理端口映射中的变量
	composeContent = cg.replacePorts(composeContent, variables)

	// 写入临时文件
	outputPath := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(outputPath, []byte(composeContent), 0644); err != nil {
		return "", fmt.Errorf("写入 compose 文件失败: %w", err)
	}

	return tempDir, nil
}

// buildVariables 构建变量映射
func (cg *ComposeGenerator) buildVariables(templateInfo *TemplateInfo, meta *TemplateMeta, testPort int) map[string]interface{} {
	variables := make(map[string]interface{})

	// 基础变量
	variables["APP_NAME"] = fmt.Sprintf("test-%s-%d", templateInfo.ID, testPort)
	variables["PRIMARY_DOMAIN"] = fmt.Sprintf("test-%s.local", templateInfo.ID)

	// 从 template.yaml 的 variables 获取默认值
	for _, v := range meta.Variables {
		if v.Default != nil {
			variables[v.Name] = v.Default
		} else {
			// 根据类型设置默认值
			switch v.Type {
			case "number":
				variables[v.Name] = testPort
			case "string":
				variables[v.Name] = ""
			case "bool":
				variables[v.Name] = false
			case "select":
				if len(v.Options) > 0 {
					variables[v.Name] = v.Options[0]
				}
			default:
				variables[v.Name] = ""
			}
		}
	}

	// 处理端口变量
	for key, value := range variables {
		if strings.HasSuffix(key, "_PORT") || strings.HasSuffix(key, "_SSH_PORT") || strings.HasSuffix(key, "_HTTPS_PORT") {
			if port, ok := value.(int); ok && port > 0 {
				// 保持原端口值
			} else {
				variables[key] = testPort
			}
		}
	}

	return variables
}

// replacePorts 替换端口映射中的变量
func (cg *ComposeGenerator) replacePorts(content string, variables map[string]interface{}) string {
	// 使用模板引擎处理端口映射
	tmpl, err := template.New("compose").Parse(content)
	if err != nil {
		// 如果模板解析失败，使用简单的字符串替换
		return content
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, variables); err != nil {
		// 如果执行失败，返回原始内容
		return content
	}

	return buf.String()
}

// GenerateCredentials 生成凭证（如果需要）
func (cg *ComposeGenerator) GenerateCredentials(meta *TemplateMeta, appName string) map[string]map[string]string {
	credentials := make(map[string]map[string]string)

	// 这里可以生成随机凭证，但为了简化，我们使用固定模式
	// 实际部署时会由 CredentialManager 生成

	return credentials
}

