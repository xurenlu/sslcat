package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type TemplateMeta struct {
	ID                string                 `yaml:"id"`
	Name              string                 `yaml:"name"`
	Category          string                 `yaml:"category"`
	Subcategory       string                 `yaml:"subcategory,omitempty"`
	Description       string                 `yaml:"description,omitempty"`
	Website           string                 `yaml:"website,omitempty"`
	Services          []TemplateService      `yaml:"services,omitempty"`
	Credentials       map[string]interface{} `yaml:"credentials,omitempty"`
	ConnectionStrings map[string]string      `yaml:"connection_strings,omitempty"`
}

type TemplateService struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"`
	Description string   `yaml:"description,omitempty"`
	DependsOn   []string `yaml:"depends_on,omitempty"`
	Ports       []struct {
		Internal int  `yaml:"internal"`
		Public   bool `yaml:"public"`
	} `yaml:"ports,omitempty"`
	Volumes []struct {
		Name string `yaml:"name"`
		Path string `yaml:"path"`
	} `yaml:"volumes,omitempty"`
}

func main() {
	templatesDir := "internal/runner/templates/builtin"
	if len(os.Args) > 1 {
		templatesDir = os.Args[1]
	}

	templates, err := findTemplates(templatesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding templates: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d templates\n", len(templates))

	generated := 0
	skipped := 0

	for _, templatePath := range templates {
		dir := filepath.Dir(templatePath)
		readmePath := filepath.Join(dir, "README.md")

		// Skip if README.md already exists
		if _, err := os.Stat(readmePath); err == nil {
			skipped++
			continue
		}

		meta, err := loadTemplateMeta(templatePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading template %s: %v\n", templatePath, err)
			continue
		}

		composePath := filepath.Join(dir, "docker-compose.yml")
		composeContent, _ := ioutil.ReadFile(composePath)

		readme := generateREADME(meta, composeContent)
		if err := ioutil.WriteFile(readmePath, []byte(readme), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing README for %s: %v\n", meta.ID, err)
			continue
		}

		generated++
		fmt.Printf("Generated README for %s (%s)\n", meta.ID, meta.Name)
	}

	fmt.Printf("\nSummary: Generated %d, Skipped %d (already exist)\n", generated, skipped)
}

func findTemplates(dir string) ([]string, error) {
	var templates []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Name() == "template.yaml" {
			templates = append(templates, path)
		}
		return nil
	})
	sort.Strings(templates)
	return templates, err
}

func loadTemplateMeta(path string) (*TemplateMeta, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var meta TemplateMeta
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

func generateREADME(meta *TemplateMeta, composeContent []byte) string {
	var buf strings.Builder

	// Title
	buf.WriteString(fmt.Sprintf("# %s 模板\n\n", meta.Name))
	buf.WriteString(fmt.Sprintf("%s\n\n", meta.Description))

	// Features
	buf.WriteString("## 功能特性\n\n")
	features := extractFeatures(meta, composeContent)
	for _, feature := range features {
		buf.WriteString(fmt.Sprintf("- ✅ %s\n", feature))
	}
	buf.WriteString("\n")

	// Credentials
	if len(meta.Credentials) > 0 {
		buf.WriteString("## 默认凭证\n\n")
		buf.WriteString("部署后，系统会自动生成以下凭证：\n\n")
		credentials := extractCredentials(meta)
		for _, cred := range credentials {
			buf.WriteString(fmt.Sprintf("- **%s**: %s\n", cred.Label, cred.Value))
		}
		buf.WriteString("\n")
	}

	// Connection info for databases
	if isDatabase(meta) {
		buf.WriteString("## 连接信息\n\n")
		connInfo := extractConnectionInfo(meta)
		for _, info := range connInfo {
			buf.WriteString(fmt.Sprintf("- **%s**: %s\n", info.Label, info.Value))
		}
		buf.WriteString("\n")
	}

	// First access for web apps
	if isWebApp(meta) {
		buf.WriteString("## 首次访问\n\n")
		buf.WriteString(fmt.Sprintf("1. 访问 `http://{{PRIMARY_DOMAIN}}`\n"))
		buf.WriteString("2. 按照安装向导完成配置\n")
		if len(meta.Credentials) > 0 {
			buf.WriteString("3. 使用系统生成的凭证登录\n")
		}
		buf.WriteString("\n")
	}

	// Data persistence
	buf.WriteString("## 数据持久化\n\n")
	volumes := extractVolumes(meta)
	if len(volumes) > 0 {
		buf.WriteString("所有数据存储在 Docker volumes 中：\n\n")
		for _, vol := range volumes {
			buf.WriteString(fmt.Sprintf("- `%s`: %s\n", vol.Name, vol.Description))
		}
		buf.WriteString("\n")
		buf.WriteString("**重要**: 即使容器重启，所有数据都会保留。\n\n")
	} else {
		buf.WriteString("数据存储在 Docker volumes 中，即使容器重启，数据也会保留。\n\n")
	}

	// Environment variables (if applicable)
	if hasEnvironmentVariables(meta, composeContent) {
		buf.WriteString("## 环境变量\n\n")
		buf.WriteString("重要的环境变量（系统自动设置）：\n\n")
		envVars := extractEnvVars(meta, composeContent)
		for _, env := range envVars {
			buf.WriteString(fmt.Sprintf("- `%s`: %s\n", env.Name, env.Description))
		}
		buf.WriteString("\n")
	}

	// Management commands
	buf.WriteString("## 管理命令\n\n")
	buf.WriteString("```bash\n")
	buf.WriteString("# 查看日志\n")
	buf.WriteString("docker-compose -f docker-compose.yml -p sslcat-{app_name} logs -f\n\n")
	buf.WriteString("# 重启服务\n")
	buf.WriteString("docker-compose -f docker-compose.yml -p sslcat-{app_name} restart\n\n")
	buf.WriteString("# 停止服务\n")
	buf.WriteString("docker-compose -f docker-compose.yml -p sslcat-{app_name} stop\n\n")
	buf.WriteString("# 启动服务\n")
	buf.WriteString("docker-compose -f docker-compose.yml -p sslcat-{app_name} up -d\n")
	buf.WriteString("```\n\n")

	// Notes
	buf.WriteString("## 注意事项\n\n")
	notes := extractNotes(meta)
	for _, note := range notes {
		buf.WriteString(fmt.Sprintf("%d. %s\n", note.Number, note.Text))
	}
	if len(notes) == 0 {
		buf.WriteString("1. 首次部署可能需要等待服务完全启动（约 30-60 秒）\n")
		if meta.Website != "" {
			buf.WriteString(fmt.Sprintf("2. 更多信息请访问：%s\n", meta.Website))
		}
	}
	buf.WriteString("\n")

	return buf.String()
}

func extractFeatures(meta *TemplateMeta, composeContent []byte) []string {
	features := []string{}

	// Check service types
	for _, svc := range meta.Services {
		switch svc.Type {
		case "web":
			features = append(features, "Web 应用服务")
		case "database":
			features = append(features, "数据库服务")
		case "cache":
			features = append(features, "缓存服务")
		case "queue":
			features = append(features, "消息队列服务")
		}
	}

	// Check for healthcheck
	if strings.Contains(string(composeContent), "healthcheck") {
		features = append(features, "健康检查支持")
	}

	// Check for volumes
	if strings.Contains(string(composeContent), "volumes:") {
		features = append(features, "数据持久化存储")
	}

	// Check for multiple services
	if len(meta.Services) > 1 {
		features = append(features, "多服务架构")
	}

	if len(features) == 0 {
		features = append(features, "完整的应用部署")
	}

	return features
}

func extractCredentials(meta *TemplateMeta) []CredentialInfo {
	var creds []CredentialInfo

	for svcName, svcCreds := range meta.Credentials {
		credMap, ok := svcCreds.(map[string]interface{})
		if !ok {
			continue
		}

		if username, ok := credMap["username"].(map[string]interface{}); ok {
			if pattern, ok := username["pattern"].(string); ok {
				creds = append(creds, CredentialInfo{
					Label: fmt.Sprintf("%s 用户名", svcName),
					Value: formatPattern(pattern),
				})
			}
		}

		if password, ok := credMap["password"].(map[string]interface{}); ok {
			if length, ok := password["length"].(int); ok {
				creds = append(creds, CredentialInfo{
					Label: fmt.Sprintf("%s 密码", svcName),
					Value: fmt.Sprintf("自动生成（%d位随机密码）", length),
				})
			} else {
				creds = append(creds, CredentialInfo{
					Label: fmt.Sprintf("%s 密码", svcName),
					Value: "自动生成",
				})
			}
		}

		if database, ok := credMap["database"].(map[string]interface{}); ok {
			if pattern, ok := database["pattern"].(string); ok {
				creds = append(creds, CredentialInfo{
					Label: fmt.Sprintf("%s 数据库名", svcName),
					Value: formatPattern(pattern),
				})
			}
		}

		if rootPassword, ok := credMap["root_password"].(map[string]interface{}); ok {
			if length, ok := rootPassword["length"].(int); ok {
				creds = append(creds, CredentialInfo{
					Label: fmt.Sprintf("%s Root 密码", svcName),
					Value: fmt.Sprintf("自动生成（%d位随机密码）", length),
				})
			}
		}

		if secretKey, ok := credMap["secret_key"].(map[string]interface{}); ok {
			if length, ok := secretKey["length"].(int); ok {
				creds = append(creds, CredentialInfo{
					Label: fmt.Sprintf("%s Secret Key", svcName),
					Value: fmt.Sprintf("自动生成（%d位随机密钥）", length),
				})
			}
		}
	}

	return creds
}

func formatPattern(pattern string) string {
	return strings.ReplaceAll(pattern, "{app_name}", "{app_name}")
}

func extractConnectionInfo(meta *TemplateMeta) []InfoItem {
	var info []InfoItem

	for _, svc := range meta.Services {
		if svc.Type == "database" {
			for _, port := range svc.Ports {
				info = append(info, InfoItem{
					Label: "主机",
					Value: fmt.Sprintf("`%s` (容器内) 或 `127.0.0.1` (外部)", svc.Name),
				})
				info = append(info, InfoItem{
					Label: "端口",
					Value: fmt.Sprintf("`%d`", port.Internal),
				})
				break
			}
		}
	}

	return info
}

func extractVolumes(meta *TemplateMeta) []VolumeInfo {
	var volumes []VolumeInfo

	for _, svc := range meta.Services {
		for _, vol := range svc.Volumes {
			desc := fmt.Sprintf("%s 数据存储", svc.Name)
			if strings.Contains(vol.Path, "data") {
				desc = fmt.Sprintf("%s 数据文件", svc.Name)
			} else if strings.Contains(vol.Path, "config") {
				desc = fmt.Sprintf("%s 配置文件", svc.Name)
			}
			volumes = append(volumes, VolumeInfo{
				Name:        vol.Name,
				Description: desc,
			})
		}
	}

	return volumes
}

func extractEnvVars(meta *TemplateMeta, composeContent []byte) []EnvVar {
	var envVars []EnvVar

	// Common environment variables
	if strings.Contains(string(composeContent), "DATABASE_URL") {
		envVars = append(envVars, EnvVar{
			Name:        "DATABASE_URL",
			Description: "数据库连接字符串（自动生成）",
		})
	}

	if strings.Contains(string(composeContent), "REDIS_URL") || strings.Contains(string(composeContent), "REDIS_HOST") {
		envVars = append(envVars, EnvVar{
			Name:        "REDIS_URL / REDIS_HOST",
			Description: "Redis 连接信息（自动生成）",
		})
	}

	return envVars
}

func extractNotes(meta *TemplateMeta) []Note {
	var notes []Note

	// Add category-specific notes
	switch meta.Category {
	case "ai":
		notes = append(notes, Note{
			Number: 1,
			Text:   "部分 AI 应用需要 GPU 支持，请确保已安装 NVIDIA 驱动和 nvidia-container-toolkit",
		})
	case "database":
		notes = append(notes, Note{
			Number: 1,
			Text:   "首次部署需要等待数据库完全启动（约 30-60 秒）",
		})
	}

	if meta.Website != "" {
		notes = append(notes, Note{
			Number: len(notes) + 1,
			Text:   fmt.Sprintf("更多信息请访问：%s", meta.Website),
		})
	}

	return notes
}

func isDatabase(meta *TemplateMeta) bool {
	for _, svc := range meta.Services {
		if svc.Type == "database" {
			return true
		}
	}
	return meta.Category == "database"
}

func isWebApp(meta *TemplateMeta) bool {
	for _, svc := range meta.Services {
		if svc.Type == "web" {
			return true
		}
	}
	return meta.Category == "cms" || meta.Category == "blog" || meta.Category == "collaboration"
}

func hasEnvironmentVariables(meta *TemplateMeta, composeContent []byte) bool {
	return strings.Contains(string(composeContent), "environment:") ||
		strings.Contains(string(composeContent), "DATABASE_URL") ||
		strings.Contains(string(composeContent), "REDIS")
}

type CredentialInfo struct {
	Label string
	Value string
}

type InfoItem struct {
	Label string
	Value string
}

type VolumeInfo struct {
	Name        string
	Description string
}

type EnvVar struct {
	Name        string
	Description string
}

type Note struct {
	Number int
	Text   string
}

