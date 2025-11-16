package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

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
	templateCount := 0

	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Name() != "docker-compose.yml" {
			return nil
		}

		templateID := filepath.Base(filepath.Dir(path))
		templateCount++
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
	fmt.Printf("总计检查: %d 个模板\n", templateCount)
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

	content := string(data)
	lines := strings.Split(content, "\n")

	// Check if file is empty
	if len(strings.TrimSpace(content)) == 0 {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    "文件为空",
		})
		return issues
	}

	// Check for services section
	hasServices := false
	hasVolumes := false
	hasNetworks := false
	serviceCount := 0
	volumeCount := 0
	networkCount := 0

	services := []string{}
	volumes := []string{}
	networks := []string{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Check for services section
		if trimmed == "services:" {
			hasServices = true
		}
		
		// Check for volumes section
		if trimmed == "volumes:" {
			hasVolumes = true
		}
		
		// Check for networks section
		if trimmed == "networks:" {
			hasNetworks = true
		}

		// Count services (lines starting with 2 spaces and ending with :)
		if strings.HasPrefix(line, "  ") && strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "#") {
			if hasServices && !hasVolumes && !hasNetworks {
				serviceName := strings.TrimSuffix(trimmed, ":")
				services = append(services, serviceName)
				serviceCount++
			}
		}

		// Check for volume definitions
		if hasVolumes && strings.HasPrefix(line, "  ") && strings.HasSuffix(trimmed, ":") {
			volName := strings.TrimSuffix(trimmed, ":")
			if volName != "" && !strings.HasPrefix(volName, "#") {
				volumes = append(volumes, volName)
				volumeCount++
			}
		}

		// Check for network definitions
		if hasNetworks && strings.HasPrefix(line, "  ") && strings.HasSuffix(trimmed, ":") {
			netName := strings.TrimSuffix(trimmed, ":")
			if netName != "" && !strings.HasPrefix(netName, "#") {
				networks = append(networks, netName)
				networkCount++
			}
		}
	}

	// Validate structure
	if !hasServices {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    "缺少 services 部分",
		})
	} else if serviceCount == 0 {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    "services 部分为空",
		})
	}

	// Check each service
	for _, svcName := range services {
		svcIssues := validateService(content, templateID, svcName)
		issues = append(issues, svcIssues...)
	}

	// Check volumes
	hasVolumeUsage := regexp.MustCompile(`\w+_data:`).MatchString(content) || 
		regexp.MustCompile(`\w+_config:`).MatchString(content)
	if hasVolumeUsage && !hasVolumes {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    "服务使用了 volumes 但未定义 volumes 部分",
		})
	}

	// Check networks
	hasNetworkUsage := strings.Contains(content, "networks:") && strings.Contains(content, "{{APP_NAME}}_network")
	if hasNetworkUsage && !hasNetworks {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    "服务使用了 networks 但未定义 networks 部分",
		})
	} else if hasNetworks {
		hasAppNetwork := false
		for _, net := range networks {
			if strings.Contains(net, "{{APP_NAME}}") {
				hasAppNetwork = true
				break
			}
		}
		if !hasAppNetwork && hasNetworkUsage {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "warning",
				Message:    "networks 中未找到 {{APP_NAME}}_network",
			})
		}
	}

	return issues
}

func validateService(content string, templateID string, svcName string) []Issue {
	issues := []Issue{}

	// Extract service block
	svcPattern := regexp.MustCompile(fmt.Sprintf(`(?m)^  %s:\n((?:    .*\n)*)`, regexp.QuoteMeta(svcName)))
	matches := svcPattern.FindStringSubmatch(content)
	if len(matches) == 0 {
		return issues
	}

	svcContent := matches[1]

	// Check for image
	if !strings.Contains(svcContent, "image:") {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "error",
			Message:    fmt.Sprintf("服务 %s 缺少 image", svcName),
		})
	}

	// Check for container_name (should use {{APP_NAME}})
	if strings.Contains(svcContent, "container_name:") {
		if !strings.Contains(svcContent, "{{APP_NAME}}") {
			issues = append(issues, Issue{
				TemplateID: templateID,
				Severity:   "warning",
				Message:    fmt.Sprintf("服务 %s 的 container_name 未使用 {{APP_NAME}} 变量", svcName),
			})
		}
	}

	// Check for restart
	if !strings.Contains(svcContent, "restart:") {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "warning",
			Message:    fmt.Sprintf("服务 %s 缺少 restart 策略", svcName),
		})
	}

	// Check for healthcheck
	if !strings.Contains(svcContent, "healthcheck:") {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "warning",
			Message:    fmt.Sprintf("服务 %s 缺少 healthcheck", svcName),
		})
	}

	// Check for networks
	if !strings.Contains(svcContent, "networks:") {
		issues = append(issues, Issue{
			TemplateID: templateID,
			Severity:   "warning",
			Message:    fmt.Sprintf("服务 %s 缺少 networks 配置", svcName),
		})
	}

	return issues
}

