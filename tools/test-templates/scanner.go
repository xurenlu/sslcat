package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
			return fmt.Errorf("解析 %s 失败: %w", templateYAML, err)
		}

		composeFile := "docker-compose.yml"
		if meta.ComposeFile != "" {
			composeFile = meta.ComposeFile
		}

		// 检查 compose 文件是否存在
		composePath := filepath.Join(path, composeFile)
		if _, err := os.Stat(composePath); os.IsNotExist(err) {
			return fmt.Errorf("模板 %s 缺少 compose 文件 %s", meta.ID, composeFile)
		}

		// 获取相对路径作为模板 ID
		relPath, err := filepath.Rel(s.templatesDir, path)
		if err != nil {
			relPath = filepath.Base(path)
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

	var meta TemplateMeta
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
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

	var compose ComposeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return nil, err
	}

	return &compose, nil
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

