package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

	// 替换变量 - 先替换所有已知变量
	composeContent := string(composeData)
	for key, value := range variables {
		placeholder := fmt.Sprintf("{{%s}}", key)
		valueStr := fmt.Sprintf("%v", value)
		composeContent = strings.ReplaceAll(composeContent, placeholder, valueStr)
	}
	
	// 替换所有剩余的未定义变量（使用默认值）
	composeContent = cg.replaceRemainingVariables(composeContent)

	// 处理端口映射中的变量
	composeContent = cg.replacePorts(composeContent, variables)

	// 写入临时文件
	outputPath := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(outputPath, []byte(composeContent), 0644); err != nil {
		return "", fmt.Errorf("写入 compose 文件失败: %w", err)
	}

	return tempDir, nil
}

// GetMappedPorts 从生成的 compose 文件中提取端口映射
func (cg *ComposeGenerator) GetMappedPorts(workDir string) (map[string]int, error) {
	composePath := filepath.Join(workDir, "docker-compose.yml")
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, err
	}

	var compose ComposeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return nil, err
	}

	portMap := make(map[string]int)
	for serviceName, service := range compose.Services {
		// 处理 Ports 字段（可能是 []string 或 map）
		var ports []string
		switch v := service.Ports.(type) {
		case []interface{}:
			for _, p := range v {
				if str, ok := p.(string); ok {
					ports = append(ports, str)
				}
			}
		case []string:
			ports = v
		case string:
			ports = []string{v}
		}
		
		for _, portMapping := range ports {
			// 解析端口映射格式 "外部端口:内部端口"
			parts := strings.Split(portMapping, ":")
			if len(parts) == 2 {
				if externalPort, err := strconv.Atoi(parts[0]); err == nil {
					portMap[serviceName] = externalPort
					break // 只取第一个端口
				}
			}
		}
	}

	return portMap, nil
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

	// 处理端口变量 - 如果端口变量没有默认值或值为0，使用 testPort
	for _, v := range meta.Variables {
		key := v.Name
		if strings.HasSuffix(key, "_PORT") || strings.HasSuffix(key, "_SSH_PORT") || strings.HasSuffix(key, "_HTTPS_PORT") {
			if value, exists := variables[key]; !exists || value == nil || value == "" {
				variables[key] = testPort
			} else {
				// 尝试转换为 int
				switch val := value.(type) {
				case int:
					if val == 0 {
						variables[key] = testPort
					}
				case float64:
					if val == 0 {
						variables[key] = testPort
					}
				case string:
					if val == "" || val == "0" {
						variables[key] = testPort
					}
				}
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

// replaceRemainingVariables 替换所有剩余的未定义变量
func (cg *ComposeGenerator) replaceRemainingVariables(content string) string {
	// 匹配所有 {{VAR}} 格式的变量
	re := regexp.MustCompile(`\{\{([A-Z_]+)\}\}`)
	
	// 根据变量名推断默认值
	content = re.ReplaceAllStringFunc(content, func(match string) string {
		varName := strings.Trim(match, "{}")
		
		// 根据变量名模式推断默认值
		if strings.Contains(varName, "VERSION") {
			return "latest"
		}
		if strings.Contains(varName, "PORT") {
			return "8080"
		}
		if strings.Contains(varName, "PASSWORD") || strings.Contains(varName, "SECRET") || strings.Contains(varName, "KEY") {
			return "test-password-123"
		}
		if strings.Contains(varName, "USER") || strings.Contains(varName, "USERNAME") {
			return "test-user"
		}
		if strings.Contains(varName, "DATABASE") || strings.Contains(varName, "DB") {
			return "test-db"
		}
		if strings.Contains(varName, "NAME") || strings.Contains(varName, "DOMAIN") {
			return "test-app"
		}
		if strings.Contains(varName, "EMAIL") {
			return "test@example.com"
		}
		if strings.Contains(varName, "ORG") || strings.Contains(varName, "ORGANIZATION") {
			return "test-org"
		}
		if strings.Contains(varName, "CLIENT") {
			return "test-client-id"
		}
		if strings.Contains(varName, "COOKIE") {
			return "test-cookie-secret"
		}
		
		// 默认值
		return "test-value"
	})
	
	return content
}

// GenerateCredentials 生成凭证（如果需要）
func (cg *ComposeGenerator) GenerateCredentials(meta *TemplateMeta, appName string) map[string]map[string]string {
	credentials := make(map[string]map[string]string)

	// 这里可以生成随机凭证，但为了简化，我们使用固定模式
	// 实际部署时会由 CredentialManager 生成

	return credentials
}

