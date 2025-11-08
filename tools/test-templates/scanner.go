package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Scanner 模板扫描器
type Scanner struct {
	templatesDir string
}

// NewScanner 创建扫描器
func NewScanner(templatesDir string) *Scanner {
	return &Scanner{
		templatesDir: templatesDir,
	}
}

// ScanTemplates 扫描所有模板
func (s *Scanner) ScanTemplates() ([]TemplateInfo, error) {
	var templates []TemplateInfo

	err := filepath.Walk(s.templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		// 检查是否有 template.yaml
		templateYAML := filepath.Join(path, "template.yaml")
		if _, err := os.Stat(templateYAML); os.IsNotExist(err) {
			return nil
		}

		// 解析 template.yaml 获取基本信息
		meta, err := s.parseTemplateMeta(templateYAML)
		if err != nil {
			// 如果解析失败，记录警告但继续处理其他模板
			fmt.Printf("⚠️  警告: 跳过模板 %s (解析失败: %v)\n", templateYAML, err)
			return nil // 跳过这个模板，继续处理其他模板
		}

		// 读取原始文件获取 compose_file
		data, _ := os.ReadFile(templateYAML)
		var rawMeta map[string]interface{}
		yaml.Unmarshal(data, &rawMeta)
		
		composeFile := "docker-compose.yml"
		if cf, ok := rawMeta["compose_file"].(string); ok && cf != "" {
			composeFile = cf
		}

		// 检查 compose 文件是否存在
		composePath := filepath.Join(path, composeFile)
		if _, err := os.Stat(composePath); os.IsNotExist(err) {
			return fmt.Errorf("模板 %s 缺少 compose 文件 %s", meta.ID, composeFile)
		}

		templates = append(templates, TemplateInfo{
			ID:          meta.ID,
			Name:        meta.Name,
			Category:    meta.Category,
			Subcategory: meta.Subcategory,
			Dir:         path,
			ComposeFile: composeFile,
			MetaPath:    templateYAML,
		})

		return nil
	})

	return templates, err
}

// parseTemplateMeta 解析 template.yaml
func (s *Scanner) parseTemplateMeta(path string) (*TemplateMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// 先解析为 map 以便处理 duration 字符串和模板变量
	var rawMeta map[string]interface{}
	if err := yaml.Unmarshal(data, &rawMeta); err != nil {
		// 如果解析失败，尝试清理 metadata 中的模板变量
		cleanedData := s.cleanTemplateVariables(data)
		if err2 := yaml.Unmarshal(cleanedData, &rawMeta); err2 != nil {
			return nil, fmt.Errorf("解析失败: %w (原始错误: %v)", err2, err)
		}
	}

	// 清理 metadata 中的模板变量（如果存在）
	if metadata, ok := rawMeta["metadata"].(map[string]interface{}); ok {
		cleanedMetadata := make(map[string]interface{})
		for k, v := range metadata {
			if str, ok := v.(string); ok && (strings.Contains(str, "{{") || strings.Contains(str, "{")) {
				// 替换模板变量为占位符
				cleanedMetadata[k] = s.replaceTemplateVars(str)
			} else {
				cleanedMetadata[k] = v
			}
		}
		rawMeta["metadata"] = cleanedMetadata
	}

	// 重新序列化为 YAML 再解析
	cleanedYAML, err := yaml.Marshal(rawMeta)
	if err != nil {
		return nil, fmt.Errorf("重新序列化失败: %w", err)
	}

	// 转换为 TemplateMeta
	var meta TemplateMeta
	if err := yaml.Unmarshal(cleanedYAML, &meta); err != nil {
		return nil, fmt.Errorf("解析 TemplateMeta 失败: %w", err)
	}

	// 处理 healthcheck_global 的 timeout（可能是字符串格式）
	if hcRaw, ok := rawMeta["healthcheck_global"].(map[string]interface{}); ok {
		if timeoutStr, ok := hcRaw["timeout"].(string); ok {
			if timeout, err := time.ParseDuration(timeoutStr); err == nil {
				meta.Healthcheck.Timeout = timeout
			}
		}
	}

	return &meta, nil
}

// cleanTemplateVariables 清理 YAML 中的模板变量
func (s *Scanner) cleanTemplateVariables(data []byte) []byte {
	content := string(data)
	// 替换 metadata 中的 {{VAR}} 为占位符
	lines := strings.Split(content, "\n")
	var cleanedLines []string
	inMetadata := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "metadata:") {
			inMetadata = true
			cleanedLines = append(cleanedLines, line)
			continue
		}
		if inMetadata {
			if strings.HasPrefix(strings.TrimSpace(line), "  ") || strings.HasPrefix(strings.TrimSpace(line), "- ") {
				// 在 metadata 块内
				cleanedLine := s.replaceTemplateVarsInLine(line)
				cleanedLines = append(cleanedLines, cleanedLine)
			} else if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				// 退出 metadata 块
				inMetadata = false
				cleanedLines = append(cleanedLines, line)
			} else {
				cleanedLines = append(cleanedLines, line)
			}
		} else {
			cleanedLines = append(cleanedLines, line)
		}
	}
	return []byte(strings.Join(cleanedLines, "\n"))
}

// replaceTemplateVarsInLine 替换行中的模板变量
func (s *Scanner) replaceTemplateVarsInLine(line string) string {
	// 匹配 {{VAR}} 或 {VAR} 格式
	re := regexp.MustCompile(`\{\{([A-Z_]+)\}\}`)
	line = re.ReplaceAllString(line, `"$1"`)
	re2 := regexp.MustCompile(`\{([A-Z_]+)\}`)
	line = re2.ReplaceAllString(line, `"$1"`)
	return line
}

// replaceTemplateVars 替换字符串中的模板变量
func (s *Scanner) replaceTemplateVars(str string) string {
	re := regexp.MustCompile(`\{\{([A-Z_]+)\}\}`)
	str = re.ReplaceAllString(str, `$1`)
	re2 := regexp.MustCompile(`\{([A-Z_]+)\}`)
	str = re2.ReplaceAllString(str, `$1`)
	return str
}

// LoadTemplateMeta 加载模板元数据
func (s *Scanner) LoadTemplateMeta(template *TemplateInfo) (*TemplateMeta, error) {
	return s.parseTemplateMeta(template.MetaPath)
}

// LoadComposeFile 加载 docker-compose.yml
func (s *Scanner) LoadComposeFile(template *TemplateInfo) (*ComposeFile, error) {
	composePath := filepath.Join(template.Dir, template.ComposeFile)
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, err
	}

	// 清理模板变量以便解析
	cleanedData := s.cleanComposeTemplateVariables(data)

	var compose ComposeFile
	if err := yaml.Unmarshal(cleanedData, &compose); err != nil {
		return nil, fmt.Errorf("解析 Compose 文件失败: %w", err)
	}

	return &compose, nil
}

// cleanComposeTemplateVariables 清理 docker-compose.yml 中的模板变量
func (s *Scanner) cleanComposeTemplateVariables(data []byte) []byte {
	content := string(data)
	// 简单替换：将所有 {{VAR}} 替换为 "latest"（用于版本）或 "test"（用于其他）
	// 先处理版本相关的变量
	reVersion := regexp.MustCompile(`\{\{([A-Z_]*VERSION[A-Z_]*)\}\}`)
	content = reVersion.ReplaceAllString(content, `latest`)
	
	// 处理端口变量，替换为默认端口
	rePort := regexp.MustCompile(`\{\{([A-Z_]*PORT[A-Z_]*)\}\}`)
	content = rePort.ReplaceAllString(content, `8080`)
	
	// 处理其他变量，替换为简单的占位符
	reOther := regexp.MustCompile(`\{\{([A-Z_]+)\}\}`)
	content = reOther.ReplaceAllStringFunc(content, func(match string) string {
		varName := strings.Trim(match, "{}")
		// 根据变量类型返回合适的默认值
		if strings.Contains(varName, "NAME") || strings.Contains(varName, "DOMAIN") {
			return `test-app`
		}
		if strings.Contains(varName, "PASSWORD") || strings.Contains(varName, "SECRET") {
			return `test-password`
		}
		if strings.Contains(varName, "USER") {
			return `test-user`
		}
		return `test-value`
	})
	
	return []byte(content)
}

// FilterByCategory 按分类过滤
func FilterByCategory(templates []TemplateInfo, category string) []TemplateInfo {
	if category == "" {
		return templates
	}

	var filtered []TemplateInfo
	for _, tpl := range templates {
		if strings.EqualFold(tpl.Category, category) {
			filtered = append(filtered, tpl)
		}
	}
	return filtered
}

// FilterByTemplateID 按模板 ID 过滤
func FilterByTemplateID(templates []TemplateInfo, templateID string) []TemplateInfo {
	if templateID == "" {
		return templates
	}

	var filtered []TemplateInfo
	for _, tpl := range templates {
		if strings.EqualFold(tpl.ID, templateID) {
			filtered = append(filtered, tpl)
		}
	}
	return filtered
}

// GroupByCategory 按分类分组
func GroupByCategory(templates []TemplateInfo) map[string][]TemplateInfo {
	groups := make(map[string][]TemplateInfo)
	for _, tpl := range templates {
		category := tpl.Category
		if category == "" {
			category = "uncategorized"
		}
		groups[category] = append(groups[category], tpl)
	}
	return groups
}

