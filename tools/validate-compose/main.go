package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ComposeFile struct {
	Services map[string]interface{} `yaml:"services"`
	Volumes  map[string]interface{} `yaml:"volumes,omitempty"`
	Networks map[string]interface{} `yaml:"networks,omitempty"`
}

type Service struct {
	Image         string                 `yaml:"image"`
	ContainerName string                 `yaml:"container_name,omitempty"`
	Restart       string                 `yaml:"restart,omitempty"`
	Ports         interface{}            `yaml:"ports,omitempty"`
	Environment   map[string]interface{} `yaml:"environment,omitempty"`
	Volumes       interface{}            `yaml:"volumes,omitempty"`
	DependsOn     interface{}            `yaml:"depends_on,omitempty"`
	Networks      interface{}            `yaml:"networks,omitempty"`
	Healthcheck   map[string]interface{} `yaml:"healthcheck,omitempty"`
	Runtime       string                 `yaml:"runtime,omitempty"`
	Command       interface{}           `yaml:"command,omitempty"`
}

type Issue struct {
	TemplateID string
	Severity   string // "error", "warning", "info"
	Message    string
}

func main() {
	templatesDir := "internal/runner/templates/builtin"
	if len(os.Args) > 1 {
		templatesDir = os.Args[1]
	}

	issues := []Issue{}

	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Name() != "docker-compose.yml" {
			return nil
		}

		templateID := filepath.Base(filepath.Dir(path))
		composeIssues := validateComposeFile(path, templateID)
		issues = append(issues, composeIssues...)

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking directory: %v\n", err)
		os.Exit(1)
	}

	// Group issues by severity
	errors := []Issue{}
	warnings := []Issue{}
	infos := []Issue{}

	for _, issue := range issues {
		switch issue.Severity {
		case "error":
			errors = append(errors, issue)
		case "warning":
			warnings = append(warnings, issue)
		case "info":
			infos = append(infos, issue)
		}
	}

	// Print summary
	fmt.Printf("=== Docker Compose 文件验证报告 ===\n\n")
	fmt.Printf("总计检查: %d 个模板\n", len(issues))
	fmt.Printf("错误: %d\n", len(errors))
	fmt.Printf("警告: %d\n", len(warnings))
	fmt.Printf("信息: %d\n\n", len(infos))

	if len(errors) > 0 {
		fmt.Printf("=== 错误 ===\n")
		for _, issue := range errors {
			fmt.Printf("[%s] %s: %s\n", issue.Severity, issue.TemplateID, issue.Message)
		}
		fmt.Printf("\n")
	}

	if len(warnings) > 0 {
		fmt.Printf("=== 警告 ===\n")
		for _, issue := range warnings {
			fmt.Printf("[%s] %s: %s\n", issue.Severity, issue.TemplateID, issue.Message)
		}
		fmt.Printf("\n")
	}

	if len(infos) > 0 && len(os.Args) > 2 && os.Args[2] == "--verbose" {
		fmt.Printf("=== 信息 ===\n")
		for _, issue := range infos {
			fmt.Printf("[%s] %s: %s\n", issue.Severity, issue.TemplateID, issue.Message)
		}
		fmt.Printf("\n")
	}

	if len(errors) > 0 {
		os.Exit(1)
	}
}

func validateComposeFile(path string, templateID string) []Issue {
	issues := []Issue{}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    fmt.Sprintf("无法读取文件: %v", err),
		})
		return issues
	}

	// Check if file is empty
	content := strings.TrimSpace(string(data))
	if len(content) == 0 {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    "文件为空",
		})
		return issues
	}

	// Remove leading empty lines
	lines := strings.Split(string(data), "\n")
	startIdx := 0
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			startIdx = i
			break
		}
	}
	cleanedData := strings.Join(lines[startIdx:], "\n")

	var compose ComposeFile
	if err := yaml.Unmarshal([]byte(cleanedData), &compose); err != nil {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    fmt.Sprintf("YAML 解析错误: %v", err),
		})
		return issues
	}

	// Check services
	if compose.Services == nil || len(compose.Services) == 0 {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    "缺少 services 定义",
		})
		return issues
	}

	// Check each service
	for svcName, svcData := range compose.Services {
		svcMap, ok := svcData.(map[string]interface{})
		if !ok {
			continue
		}

		// Convert to Service struct for easier checking
		svcBytes, _ := yaml.Marshal(svcMap)
		var svc Service
		yaml.Unmarshal(svcBytes, &svc)

		// Check required fields
		if svc.Image == "" {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "error",
				Message:    fmt.Sprintf("服务 %s 缺少 image", svcName),
			})
		}

		// Check container_name format
		if svc.ContainerName != "" && !strings.Contains(svc.ContainerName, "{{APP_NAME}}") {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "warning",
				Message:    fmt.Sprintf("服务 %s 的 container_name 未使用 {{APP_NAME}} 变量", svcName),
			})
		}

		// Check restart policy
		if svc.Restart == "" {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "warning",
				Message:    fmt.Sprintf("服务 %s 缺少 restart 策略", svcName),
			})
		}

		// Check healthcheck
		if svc.Healthcheck == nil || len(svc.Healthcheck) == 0 {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "warning",
				Message:    fmt.Sprintf("服务 %s 缺少 healthcheck", svcName),
			})
		}

		// Check networks
		if svc.Networks == nil {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "warning",
				Message:    fmt.Sprintf("服务 %s 缺少 networks 配置", svcName),
			})
		}
	}

	// Check volumes section
	if compose.Volumes == nil || len(compose.Volumes) == 0 {
		// Check if any service uses volumes
		hasVolumes := false
		for _, svcData := range compose.Services {
			svcMap, ok := svcData.(map[string]interface{})
			if !ok {
				continue
			}
			if volumes, exists := svcMap["volumes"]; exists && volumes != nil {
				hasVolumes = true
				break
			}
		}
		if hasVolumes {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "error",
				Message:    "服务使用了 volumes 但未定义 volumes 部分",
			})
		}
	}

	// Check networks section
	if compose.Networks == nil || len(compose.Networks) == 0 {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    "缺少 networks 定义",
		})
	} else {
		// Check if {{APP_NAME}}_network exists
		hasAppNetwork := false
		for netName := range compose.Networks {
			if strings.Contains(netName, "{{APP_NAME}}") {
				hasAppNetwork = true
				break
			}
		}
		if !hasAppNetwork {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "warning",
				Message:    "networks 中未找到 {{APP_NAME}}_network",
			})
		}
	}

	return issues
}

