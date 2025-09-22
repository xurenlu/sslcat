package web

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// AdvancedPHPSecurity 高级 PHP 安全管理器
type AdvancedPHPSecurity struct {
	config *config.Config
	log    *logrus.Entry
}

// SecurityScanResult 安全扫描结果
type SecurityScanResult struct {
	Domain          string                   `json:"domain"`
	ScanTime        time.Time                `json:"scan_time"`
	TotalIssues     int                      `json:"total_issues"`
	CriticalIssues  int                      `json:"critical_issues"`
	HighIssues      int                      `json:"high_issues"`
	MediumIssues    int                      `json:"medium_issues"`
	LowIssues       int                      `json:"low_issues"`
	Issues          []SecurityIssue          `json:"issues"`
	Recommendations []SecurityRecommendation `json:"recommendations"`
	SecurityScore   int                      `json:"security_score"`
}

// SecurityIssue 安全问题
type SecurityIssue struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Code        string `json:"code,omitempty"`
	Fixable     bool   `json:"fixable"`
	AutoFix     string `json:"auto_fix,omitempty"`
}

// SecurityRecommendation 安全建议
type SecurityRecommendation struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Action      string `json:"action"`
}

// NewAdvancedPHPSecurity 创建高级 PHP 安全管理器
func NewAdvancedPHPSecurity(cfg *config.Config) *AdvancedPHPSecurity {
	return &AdvancedPHPSecurity{
		config: cfg,
		log:    logrus.WithFields(logrus.Fields{"component": "advanced_php_security"}),
	}
}

// PerformAdvancedSecurityScan 执行高级安全扫描
func (aps *AdvancedPHPSecurity) PerformAdvancedSecurityScan(domain string) (*SecurityScanResult, error) {
	result := &SecurityScanResult{
		Domain:          domain,
		ScanTime:        time.Now(),
		Issues:          []SecurityIssue{},
		Recommendations: []SecurityRecommendation{},
	}

	// 查找对应的 PHP 站点
	var site *config.PHPSite
	for i := range aps.config.PHPSites {
		if strings.EqualFold(aps.config.PHPSites[i].Domain, domain) {
			site = &aps.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 执行各种安全扫描
	aps.scanFileUploadSecurity(site, result)
	aps.scanCodeInjectionVulnerabilities(site, result)
	aps.scanSQLInjectionVulnerabilities(site, result)
	aps.scanXSSVulnerabilities(site, result)
	aps.scanPathTraversalVulnerabilities(site, result)
	aps.scanConfigurationSecurity(site, result)
	aps.scanDependencyVulnerabilities(site, result)
	aps.scanFilePermissions(site, result)
	aps.scanSensitiveDataExposure(site, result)

	// 计算安全评分
	result.calculateSecurityScore()

	// 生成安全建议
	aps.generateSecurityRecommendations(result)

	return result, nil
}

// scanFileUploadSecurity 扫描文件上传安全
func (aps *AdvancedPHPSecurity) scanFileUploadSecurity(site *config.PHPSite, result *SecurityScanResult) {
	// 检查文件上传配置
	if site.SecurityConfig == nil {
		result.Issues = append(result.Issues, SecurityIssue{
			ID:          "file_upload_config_missing",
			Type:        "file_upload",
			Severity:    "high",
			Title:       "缺少文件上传安全配置",
			Description: "未配置文件上传安全限制，存在安全风险",
			Fixable:     true,
			AutoFix:     "enable_file_upload_security",
		})
		return
	}

	// 检查文件大小限制
	if site.SecurityConfig.MaxUploadSize == 0 {
		result.Issues = append(result.Issues, SecurityIssue{
			ID:          "file_upload_size_unlimited",
			Type:        "file_upload",
			Severity:    "high",
			Title:       "文件上传大小无限制",
			Description: "未设置文件上传大小限制，可能导致存储空间耗尽",
			Fixable:     true,
			AutoFix:     "set_upload_size_limit",
		})
	}

	// 检查文件类型限制
	if len(site.SecurityConfig.AllowedExtensions) == 0 {
		result.Issues = append(result.Issues, SecurityIssue{
			ID:          "file_upload_type_unlimited",
			Type:        "file_upload",
			Severity:    "critical",
			Title:       "文件类型无限制",
			Description: "未设置允许的文件类型，可能允许上传恶意文件",
			Fixable:     true,
			AutoFix:     "set_allowed_file_types",
		})
	}

	// 检查危险文件类型
	dangerousExtensions := []string{".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".pht", ".phtm"}
	for _, ext := range dangerousExtensions {
		for _, allowed := range site.SecurityConfig.AllowedExtensions {
			if strings.EqualFold(ext, allowed) {
				result.Issues = append(result.Issues, SecurityIssue{
					ID:          "dangerous_file_type_allowed",
					Type:        "file_upload",
					Severity:    "critical",
					Title:       "允许上传危险文件类型",
					Description: fmt.Sprintf("允许上传 %s 文件，存在代码执行风险", ext),
					Fixable:     true,
					AutoFix:     "remove_dangerous_file_types",
				})
			}
		}
	}
}

// scanCodeInjectionVulnerabilities 扫描代码注入漏洞
func (aps *AdvancedPHPSecurity) scanCodeInjectionVulnerabilities(site *config.PHPSite, result *SecurityScanResult) {
	// 扫描 PHP 文件中的危险函数
	phpFiles := aps.findPHPFiles(site.Root)

	for _, file := range phpFiles {
		issues := aps.scanFileForCodeInjection(file)
		result.Issues = append(result.Issues, issues...)
	}
}

// scanFileForCodeInjection 扫描单个文件的代码注入
func (aps *AdvancedPHPSecurity) scanFileForCodeInjection(filePath string) []SecurityIssue {
	var issues []SecurityIssue

	file, err := os.Open(filePath)
	if err != nil {
		return issues
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// 危险函数模式
	dangerousPatterns := map[string]string{
		`eval\s*\(`:                   "eval() 函数",
		`exec\s*\(`:                   "exec() 函数",
		`system\s*\(`:                 "system() 函数",
		`shell_exec\s*\(`:             "shell_exec() 函数",
		`passthru\s*\(`:               "passthru() 函数",
		`proc_open\s*\(`:              "proc_open() 函数",
		`popen\s*\(`:                  "popen() 函数",
		`file_get_contents\s*\(\s*\$`: "file_get_contents() 使用变量",
		`include\s*\(\s*\$`:           "include() 使用变量",
		`require\s*\(\s*\$`:           "require() 使用变量",
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for pattern, description := range dangerousPatterns {
			if matched, _ := regexp.MatchString(pattern, line); matched {
				severity := "high"
				if strings.Contains(pattern, "eval") || strings.Contains(pattern, "exec") || strings.Contains(pattern, "system") {
					severity = "critical"
				}

				issues = append(issues, SecurityIssue{
					ID:          fmt.Sprintf("code_injection_%d_%d", lineNum, len(issues)),
					Type:        "code_injection",
					Severity:    severity,
					Title:       fmt.Sprintf("发现 %s", description),
					Description: fmt.Sprintf("在文件 %s 第 %d 行发现 %s，存在代码执行风险", filePath, lineNum, description),
					File:        filePath,
					Line:        lineNum,
					Code:        strings.TrimSpace(line),
					Fixable:     true,
					AutoFix:     "remove_dangerous_functions",
				})
			}
		}
	}

	return issues
}

// scanSQLInjectionVulnerabilities 扫描 SQL 注入漏洞
func (aps *AdvancedPHPSecurity) scanSQLInjectionVulnerabilities(site *config.PHPSite, result *SecurityScanResult) {
	phpFiles := aps.findPHPFiles(site.Root)

	for _, file := range phpFiles {
		issues := aps.scanFileForSQLInjection(file)
		result.Issues = append(result.Issues, issues...)
	}
}

// scanFileForSQLInjection 扫描单个文件的 SQL 注入
func (aps *AdvancedPHPSecurity) scanFileForSQLInjection(filePath string) []SecurityIssue {
	var issues []SecurityIssue

	file, err := os.Open(filePath)
	if err != nil {
		return issues
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// SQL 注入模式
	sqlPatterns := map[string]string{
		`mysql_query\s*\(\s*["\']\s*SELECT.*\$`:  "mysql_query() 直接拼接变量",
		`mysqli_query\s*\(\s*["\']\s*SELECT.*\$`: "mysqli_query() 直接拼接变量",
		`PDO::query\s*\(\s*["\']\s*SELECT.*\$`:   "PDO::query() 直接拼接变量",
		`SELECT.*\$.*FROM`:                       "SQL 查询中直接使用变量",
		`INSERT.*\$.*INTO`:                       "INSERT 语句中直接使用变量",
		`UPDATE.*\$.*SET`:                        "UPDATE 语句中直接使用变量",
		`DELETE.*\$.*FROM`:                       "DELETE 语句中直接使用变量",
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for pattern, description := range sqlPatterns {
			if matched, _ := regexp.MatchString(pattern, line); matched {
				issues = append(issues, SecurityIssue{
					ID:          fmt.Sprintf("sql_injection_%d_%d", lineNum, len(issues)),
					Type:        "sql_injection",
					Severity:    "critical",
					Title:       fmt.Sprintf("发现 %s", description),
					Description: fmt.Sprintf("在文件 %s 第 %d 行发现 %s，存在 SQL 注入风险", filePath, lineNum, description),
					File:        filePath,
					Line:        lineNum,
					Code:        strings.TrimSpace(line),
					Fixable:     true,
					AutoFix:     "use_prepared_statements",
				})
			}
		}
	}

	return issues
}

// scanXSSVulnerabilities 扫描 XSS 漏洞
func (aps *AdvancedPHPSecurity) scanXSSVulnerabilities(site *config.PHPSite, result *SecurityScanResult) {
	phpFiles := aps.findPHPFiles(site.Root)

	for _, file := range phpFiles {
		issues := aps.scanFileForXSS(file)
		result.Issues = append(result.Issues, issues...)
	}
}

// scanFileForXSS 扫描单个文件的 XSS 漏洞
func (aps *AdvancedPHPSecurity) scanFileForXSS(filePath string) []SecurityIssue {
	var issues []SecurityIssue

	file, err := os.Open(filePath)
	if err != nil {
		return issues
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// XSS 模式
	xssPatterns := map[string]string{
		`echo\s+\$`:                      "echo 直接输出变量",
		`print\s+\$`:                     "print 直接输出变量",
		`printf\s+["\'].*\$.*["\']`:      "printf 直接输出变量",
		`<.*\$.*>`:                       "HTML 中直接使用变量",
		`javascript:.*\$`:                "JavaScript 中使用变量",
		`onclick\s*=\s*["\'].*\$.*["\']`: "onclick 事件中使用变量",
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for pattern, description := range xssPatterns {
			if matched, _ := regexp.MatchString(pattern, line); matched {
				issues = append(issues, SecurityIssue{
					ID:          fmt.Sprintf("xss_%d_%d", lineNum, len(issues)),
					Type:        "xss",
					Severity:    "high",
					Title:       fmt.Sprintf("发现 %s", description),
					Description: fmt.Sprintf("在文件 %s 第 %d 行发现 %s，存在 XSS 风险", filePath, lineNum, description),
					File:        filePath,
					Line:        lineNum,
					Code:        strings.TrimSpace(line),
					Fixable:     true,
					AutoFix:     "escape_output",
				})
			}
		}
	}

	return issues
}

// scanPathTraversalVulnerabilities 扫描路径遍历漏洞
func (aps *AdvancedPHPSecurity) scanPathTraversalVulnerabilities(site *config.PHPSite, result *SecurityScanResult) {
	phpFiles := aps.findPHPFiles(site.Root)

	for _, file := range phpFiles {
		issues := aps.scanFileForPathTraversal(file)
		result.Issues = append(result.Issues, issues...)
	}
}

// scanFileForPathTraversal 扫描单个文件的路径遍历
func (aps *AdvancedPHPSecurity) scanFileForPathTraversal(filePath string) []SecurityIssue {
	var issues []SecurityIssue

	file, err := os.Open(filePath)
	if err != nil {
		return issues
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// 路径遍历模式
	pathPatterns := map[string]string{
		`include\s*\(\s*\$`:           "include() 使用变量",
		`require\s*\(\s*\$`:           "require() 使用变量",
		`file_get_contents\s*\(\s*\$`: "file_get_contents() 使用变量",
		`fopen\s*\(\s*\$`:             "fopen() 使用变量",
		`readfile\s*\(\s*\$`:          "readfile() 使用变量",
		`file\s*\(\s*\$`:              "file() 使用变量",
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for pattern, description := range pathPatterns {
			if matched, _ := regexp.MatchString(pattern, line); matched {
				issues = append(issues, SecurityIssue{
					ID:          fmt.Sprintf("path_traversal_%d_%d", lineNum, len(issues)),
					Type:        "path_traversal",
					Severity:    "high",
					Title:       fmt.Sprintf("发现 %s", description),
					Description: fmt.Sprintf("在文件 %s 第 %d 行发现 %s，存在路径遍历风险", filePath, lineNum, description),
					File:        filePath,
					Line:        lineNum,
					Code:        strings.TrimSpace(line),
					Fixable:     true,
					AutoFix:     "validate_file_paths",
				})
			}
		}
	}

	return issues
}

// scanConfigurationSecurity 扫描配置安全
func (aps *AdvancedPHPSecurity) scanConfigurationSecurity(site *config.PHPSite, result *SecurityScanResult) {
	// 检查 PHP 配置安全性
	if site.SecurityConfig == nil {
		result.Issues = append(result.Issues, SecurityIssue{
			ID:          "security_config_missing",
			Type:        "configuration",
			Severity:    "high",
			Title:       "缺少安全配置",
			Description: "未配置 PHP 安全设置",
			Fixable:     true,
			AutoFix:     "enable_security_config",
		})
		return
	}

	// 检查各种安全配置
	if !site.SecurityConfig.DisableEval {
		result.Issues = append(result.Issues, SecurityIssue{
			ID:          "eval_not_disabled",
			Type:        "configuration",
			Severity:    "critical",
			Title:       "eval() 函数未禁用",
			Description: "eval() 函数未禁用，存在代码执行风险",
			Fixable:     true,
			AutoFix:     "disable_eval",
		})
	}

	if !site.SecurityConfig.DisableShellExec {
		result.Issues = append(result.Issues, SecurityIssue{
			ID:          "shell_exec_not_disabled",
			Type:        "configuration",
			Severity:    "critical",
			Title:       "Shell 执行函数未禁用",
			Description: "Shell 执行函数未禁用，存在命令执行风险",
			Fixable:     true,
			AutoFix:     "disable_shell_exec",
		})
	}

	if !site.SecurityConfig.DisablePathTraversal {
		result.Issues = append(result.Issues, SecurityIssue{
			ID:          "path_traversal_not_disabled",
			Type:        "configuration",
			Severity:    "high",
			Title:       "路径遍历保护未启用",
			Description: "路径遍历保护未启用，存在文件访问风险",
			Fixable:     true,
			AutoFix:     "enable_path_traversal_protection",
		})
	}
}

// scanDependencyVulnerabilities 扫描依赖漏洞
func (aps *AdvancedPHPSecurity) scanDependencyVulnerabilities(site *config.PHPSite, result *SecurityScanResult) {
	// 检查 composer.json 文件
	composerFile := filepath.Join(site.Root, "composer.json")
	if _, err := os.Stat(composerFile); err == nil {
		// 这里可以集成第三方漏洞数据库检查
		result.Issues = append(result.Issues, SecurityIssue{
			ID:          "dependency_scan_needed",
			Type:        "dependency",
			Severity:    "medium",
			Title:       "需要检查依赖漏洞",
			Description: "发现 composer.json 文件，建议检查依赖包的安全漏洞",
			File:        composerFile,
			Fixable:     false,
		})
	}
}

// scanFilePermissions 扫描文件权限
func (aps *AdvancedPHPSecurity) scanFilePermissions(site *config.PHPSite, result *SecurityScanResult) {
	// 检查敏感文件的权限
	sensitiveFiles := []string{
		"config.php",
		"database.php",
		".env",
		"wp-config.php",
		"configuration.php",
	}

	for _, fileName := range sensitiveFiles {
		filePath := filepath.Join(site.Root, fileName)
		if info, err := os.Stat(filePath); err == nil {
			mode := info.Mode()
			if mode&0o002 != 0 || mode&0o020 != 0 {
				result.Issues = append(result.Issues, SecurityIssue{
					ID:          fmt.Sprintf("file_permission_%s", fileName),
					Type:        "file_permission",
					Severity:    "high",
					Title:       fmt.Sprintf("文件权限过于宽松: %s", fileName),
					Description: fmt.Sprintf("文件 %s 的权限为 %o，过于宽松", fileName, mode&0o777),
					File:        filePath,
					Fixable:     true,
					AutoFix:     "fix_file_permissions",
				})
			}
		}
	}
}

// scanSensitiveDataExposure 扫描敏感数据泄露
func (aps *AdvancedPHPSecurity) scanSensitiveDataExposure(site *config.PHPSite, result *SecurityScanResult) {
	phpFiles := aps.findPHPFiles(site.Root)

	for _, file := range phpFiles {
		issues := aps.scanFileForSensitiveData(file)
		result.Issues = append(result.Issues, issues...)
	}
}

// scanFileForSensitiveData 扫描单个文件的敏感数据
func (aps *AdvancedPHPSecurity) scanFileForSensitiveData(filePath string) []SecurityIssue {
	var issues []SecurityIssue

	file, err := os.Open(filePath)
	if err != nil {
		return issues
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// 敏感数据模式
	sensitivePatterns := map[string]string{
		`password\s*=\s*["\'][^"\']+["\']`:         "硬编码密码",
		`api_key\s*=\s*["\'][^"\']+["\']`:          "硬编码 API 密钥",
		`secret\s*=\s*["\'][^"\']+["\']`:           "硬编码密钥",
		`token\s*=\s*["\'][^"\']+["\']`:            "硬编码令牌",
		`mysql_connect\s*\([^)]*["\'][^"\']+["\']`: "硬编码数据库密码",
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for pattern, description := range sensitivePatterns {
			if matched, _ := regexp.MatchString(pattern, line); matched {
				issues = append(issues, SecurityIssue{
					ID:          fmt.Sprintf("sensitive_data_%d_%d", lineNum, len(issues)),
					Type:        "sensitive_data",
					Severity:    "high",
					Title:       fmt.Sprintf("发现 %s", description),
					Description: fmt.Sprintf("在文件 %s 第 %d 行发现 %s", filePath, lineNum, description),
					File:        filePath,
					Line:        lineNum,
					Code:        strings.TrimSpace(line),
					Fixable:     true,
					AutoFix:     "move_to_environment_variables",
				})
			}
		}
	}

	return issues
}

// findPHPFiles 查找 PHP 文件
func (aps *AdvancedPHPSecurity) findPHPFiles(rootDir string) []string {
	var phpFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".php") {
			phpFiles = append(phpFiles, path)
		}

		return nil
	})

	if err != nil {
		aps.log.Warnf("Error walking directory %s: %v", rootDir, err)
	}

	return phpFiles
}

// calculateSecurityScore 计算安全评分
func (result *SecurityScanResult) calculateSecurityScore() {
	// 统计问题数量
	for _, issue := range result.Issues {
		result.TotalIssues++
		switch issue.Severity {
		case "critical":
			result.CriticalIssues++
		case "high":
			result.HighIssues++
		case "medium":
			result.MediumIssues++
		case "low":
			result.LowIssues++
		}
	}

	// 计算安全评分 (0-100)
	score := 100
	score -= result.CriticalIssues * 20
	score -= result.HighIssues * 10
	score -= result.MediumIssues * 5
	score -= result.LowIssues * 2

	if score < 0 {
		score = 0
	}

	result.SecurityScore = score
}

// generateSecurityRecommendations 生成安全建议
func (aps *AdvancedPHPSecurity) generateSecurityRecommendations(result *SecurityScanResult) {
	// 基于扫描结果生成建议
	if result.CriticalIssues > 0 {
		result.Recommendations = append(result.Recommendations, SecurityRecommendation{
			Type:        "critical",
			Title:       "立即修复关键安全问题",
			Description: fmt.Sprintf("发现 %d 个关键安全问题，建议立即修复", result.CriticalIssues),
			Priority:    "high",
			Action:      "fix_critical_issues",
		})
	}

	if result.HighIssues > 0 {
		result.Recommendations = append(result.Recommendations, SecurityRecommendation{
			Type:        "high",
			Title:       "修复高风险安全问题",
			Description: fmt.Sprintf("发现 %d 个高风险安全问题，建议尽快修复", result.HighIssues),
			Priority:    "medium",
			Action:      "fix_high_risk_issues",
		})
	}

	// 通用安全建议
	result.Recommendations = append(result.Recommendations, SecurityRecommendation{
		Type:        "general",
		Title:       "启用安全响应头",
		Description: "建议启用 X-Frame-Options、X-XSS-Protection 等安全响应头",
		Priority:    "medium",
		Action:      "enable_security_headers",
	})

	result.Recommendations = append(result.Recommendations, SecurityRecommendation{
		Type:        "general",
		Title:       "定期更新依赖包",
		Description: "建议定期更新 composer 依赖包，修复已知安全漏洞",
		Priority:    "low",
		Action:      "update_dependencies",
	})
}

// AutoFixSecurityIssues 自动修复安全问题
func (aps *AdvancedPHPSecurity) AutoFixSecurityIssues(domain string, issueIDs []string) error {
	// 查找对应的 PHP 站点
	var site *config.PHPSite
	for i := range aps.config.PHPSites {
		if strings.EqualFold(aps.config.PHPSites[i].Domain, domain) {
			site = &aps.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 执行自动修复
	for _, issueID := range issueIDs {
		if err := aps.fixSecurityIssue(site, issueID); err != nil {
			aps.log.Warnf("Failed to fix security issue %s: %v", issueID, err)
		}
	}

	return nil
}

// fixSecurityIssue 修复单个安全问题
func (aps *AdvancedPHPSecurity) fixSecurityIssue(site *config.PHPSite, issueID string) error {
	switch issueID {
	case "enable_file_upload_security":
		return aps.enableFileUploadSecurity(site)
	case "set_upload_size_limit":
		return aps.setUploadSizeLimit(site)
	case "set_allowed_file_types":
		return aps.setAllowedFileTypes(site)
	case "remove_dangerous_file_types":
		return aps.removeDangerousFileTypes(site)
	case "disable_eval":
		return aps.disableEval(site)
	case "disable_shell_exec":
		return aps.disableShellExec(site)
	case "enable_path_traversal_protection":
		return aps.enablePathTraversalProtection(site)
	case "enable_security_config":
		return aps.enableSecurityConfig(site)
	default:
		return fmt.Errorf("unknown security issue: %s", issueID)
	}
}

// 各种自动修复方法的实现
func (aps *AdvancedPHPSecurity) enableFileUploadSecurity(site *config.PHPSite) error {
	if site.SecurityConfig == nil {
		site.SecurityConfig = &config.PHPSecurityConfig{}
	}
	return nil
}

func (aps *AdvancedPHPSecurity) setUploadSizeLimit(site *config.PHPSite) error {
	if site.SecurityConfig == nil {
		site.SecurityConfig = &config.PHPSecurityConfig{}
	}
	site.SecurityConfig.MaxUploadSize = 10 * 1024 * 1024 // 10MB
	return nil
}

func (aps *AdvancedPHPSecurity) setAllowedFileTypes(site *config.PHPSite) error {
	if site.SecurityConfig == nil {
		site.SecurityConfig = &config.PHPSecurityConfig{}
	}
	site.SecurityConfig.AllowedExtensions = []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".doc", ".docx"}
	return nil
}

func (aps *AdvancedPHPSecurity) removeDangerousFileTypes(site *config.PHPSite) error {
	if site.SecurityConfig == nil {
		return nil
	}

	// 移除危险的文件类型
	dangerousExts := []string{".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".pht", ".phtm"}
	var newAllowed []string

	for _, ext := range site.SecurityConfig.AllowedExtensions {
		isDangerous := false
		for _, dangerous := range dangerousExts {
			if strings.EqualFold(ext, dangerous) {
				isDangerous = true
				break
			}
		}
		if !isDangerous {
			newAllowed = append(newAllowed, ext)
		}
	}

	site.SecurityConfig.AllowedExtensions = newAllowed
	return nil
}

func (aps *AdvancedPHPSecurity) disableEval(site *config.PHPSite) error {
	if site.SecurityConfig == nil {
		site.SecurityConfig = &config.PHPSecurityConfig{}
	}
	site.SecurityConfig.DisableEval = true
	return nil
}

func (aps *AdvancedPHPSecurity) disableShellExec(site *config.PHPSite) error {
	if site.SecurityConfig == nil {
		site.SecurityConfig = &config.PHPSecurityConfig{}
	}
	site.SecurityConfig.DisableShellExec = true
	return nil
}

func (aps *AdvancedPHPSecurity) enablePathTraversalProtection(site *config.PHPSite) error {
	if site.SecurityConfig == nil {
		site.SecurityConfig = &config.PHPSecurityConfig{}
	}
	site.SecurityConfig.DisablePathTraversal = true
	return nil
}

func (aps *AdvancedPHPSecurity) enableSecurityConfig(site *config.PHPSite) error {
	site.SecurityConfig = &config.PHPSecurityConfig{
		MaxUploadSize:        10 * 1024 * 1024, // 10MB
		AllowedExtensions:    []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"},
		BlockedExtensions:    []string{".php", ".phtml", ".php3", ".php4", ".php5", ".php7"},
		DisableEval:          true,
		DisableShellExec:     true,
		DisablePathTraversal: true,
	}
	return nil
}
