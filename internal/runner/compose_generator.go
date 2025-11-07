package runner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ComposeGenerationParams 定义 Compose 生成所需的参数
type ComposeGenerationParams struct {
	AppName        string
	PrimaryDomain  string
	Domains        []string
	Variables      map[string]interface{}
	Credentials    map[string]map[string]string
	ExtraEnv       map[string]string
	WorkingSubPath string
}

// ComposeRenderResult 表示生成结果
type ComposeRenderResult struct {
	WorkDir     string
	ComposeFile string
	EnvFile     string
	Template    *AppTemplate
	Variables   map[string]string
	Cleanup     func() error
}

// ComposeGenerator 负责基于模板生成 docker-compose 文件
type ComposeGenerator struct {
	templates *TemplateManager
	baseDir   string
	logger    *logrus.Entry
}

// NewComposeGenerator 创建 Compose 生成器
func NewComposeGenerator(tm *TemplateManager, baseDir string, logger *logrus.Logger) (*ComposeGenerator, error) {
	if tm == nil {
		return nil, fmt.Errorf("template manager 不能为空")
	}
	if baseDir == "" {
		return nil, fmt.Errorf("baseDir 不能为空")
	}

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建模板工作目录失败: %w", err)
	}

	entry := logger.WithField("component", "compose_generator")

	return &ComposeGenerator{
		templates: tm,
		baseDir:   baseDir,
		logger:    entry,
	}, nil
}

// Generate 根据模板与参数生成 Compose 文件
func (cg *ComposeGenerator) Generate(tpl *AppTemplate, params ComposeGenerationParams) (*ComposeRenderResult, error) {
	if tpl == nil {
		return nil, fmt.Errorf("模板不能为空")
	}
	if params.AppName == "" {
		return nil, fmt.Errorf("AppName 不能为空")
	}

	workDir, err := cg.prepareWorkDir(params)
	if err != nil {
		return nil, err
	}

	cleanup := func() error {
		return os.RemoveAll(workDir)
	}

	if err := cg.copyTemplateAssets(workDir, tpl); err != nil {
		cleanup()
		return nil, err
	}

	variables := cg.buildVariableMap(tpl, params)

	composePath := filepath.Join(workDir, tpl.ComposePath)
	if err := cg.renderFile(composePath, variables); err != nil {
		cleanup()
		return nil, err
	}

	envPath := filepath.Join(workDir, ".env.sslcat")
	if err := cg.writeEnvFile(envPath, variables); err != nil {
		cleanup()
		return nil, err
	}

	return &ComposeRenderResult{
		WorkDir:     workDir,
		ComposeFile: composePath,
		EnvFile:     envPath,
		Template:    tpl,
		Variables:   variables,
		Cleanup:     cleanup,
	}, nil
}

func (cg *ComposeGenerator) prepareWorkDir(params ComposeGenerationParams) (string, error) {
	subPath := params.WorkingSubPath
	if subPath == "" {
		subPath = params.AppName
	}

	timestamp := time.Now().UTC().Format("20060102-150405-000")
	workDir := filepath.Join(cg.baseDir, subPath, timestamp)

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", fmt.Errorf("创建工作目录失败: %w", err)
	}

	return workDir, nil
}

func (cg *ComposeGenerator) copyTemplateAssets(dst string, tpl *AppTemplate) error {
	return fs.WalkDir(tpl.RootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		target := filepath.Join(dst, path)

		if d.IsDir() {
			if path == "." {
				return nil
			}
			return os.MkdirAll(target, 0o755)
		}

		data, err := fs.ReadFile(tpl.RootFS, path)
		if err != nil {
			return err
		}

		mode := fs.FileMode(0o644)
		if info, err := d.Info(); err == nil {
			mode = info.Mode()
		}

		if err := os.WriteFile(target, data, mode); err != nil {
			return err
		}

		return nil
	})
}

func (cg *ComposeGenerator) buildVariableMap(tpl *AppTemplate, params ComposeGenerationParams) map[string]string {
	vars := make(map[string]string)

	vars["APP_NAME"] = params.AppName
	vars["SSLCAT_APP_NAME"] = params.AppName
	vars["PRIMARY_DOMAIN"] = params.PrimaryDomain
	vars["SSLCAT_PRIMARY_DOMAIN"] = params.PrimaryDomain

	domains := append([]string{}, params.Domains...)
	if params.PrimaryDomain != "" {
		present := false
		for _, d := range domains {
			if strings.EqualFold(d, params.PrimaryDomain) {
				present = true
				break
			}
		}
		if !present {
			domains = append([]string{params.PrimaryDomain}, domains...)
		}
	}

	if len(domains) > 0 {
		sort.Strings(domains)
		vars["SSLCAT_DOMAINS"] = strings.Join(domains, ",")
	}

	for k, v := range params.Variables {
		if v == nil {
			continue
		}
		s := fmt.Sprint(v)
		vars[strings.ToUpper(k)] = s
	}

	for svc, cred := range params.Credentials {
		svcUpper := strings.ToUpper(svc)
		for field, value := range cred {
			if value == "" {
				continue
			}
			fieldUpper := strings.ToUpper(field)
			vars[svcUpper+"_"+fieldUpper] = value
			vars[svcUpper+"."+strings.ToLower(field)] = value
		}
	}

	for k, v := range params.ExtraEnv {
		if v == "" {
			continue
		}
		vars[strings.ToUpper(k)] = v
	}

	return vars
}

func (cg *ComposeGenerator) renderFile(path string, variables map[string]string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取 Compose 文件失败: %w", err)
	}

	replacements := make([]string, 0, len(variables)*2)
	for k, v := range variables {
		replacements = append(replacements, "{{"+k+"}}", v)
	}

	replacer := strings.NewReplacer(replacements...)
	rendered := replacer.Replace(string(content))

	if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
		return fmt.Errorf("写入 Compose 文件失败: %w", err)
	}

	return nil
}

func (cg *ComposeGenerator) writeEnvFile(path string, variables map[string]string) error {
	keys := make([]string, 0, len(variables))
	for k := range variables {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	builder := &strings.Builder{}
	for _, key := range keys {
		if !isEnvKey(key) {
			continue
		}
		value := variables[key]
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(escapeEnvValue(value))
		builder.WriteString("\n")
	}

	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func isEnvKey(key string) bool {
	return strings.HasPrefix(key, "SSLCAT_") || !strings.Contains(key, ".")
}

func escapeEnvValue(value string) string {
	if value == "" {
		return ""
	}
	if strings.ContainsAny(value, " #"+"\t") {
		return fmt.Sprintf("\"%s\"", strings.ReplaceAll(value, "\"", "\\\""))
	}
	return value
}
