package web

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// PHPSecurity PHP 安全管理器
type PHPSecurity struct {
	config *config.Config
	log    *logrus.Entry
}

// NewPHPSecurity 创建 PHP 安全管理器
func NewPHPSecurity(cfg *config.Config) *PHPSecurity {
	return &PHPSecurity{
		config: cfg,
		log:    logrus.WithFields(logrus.Fields{"component": "php_security"}),
	}
}

// SecurityViolation 安全违规记录
type SecurityViolation struct {
	Timestamp  time.Time `json:"timestamp"`
	Domain     string    `json:"domain"`
	Type       string    `json:"type"`     // path_traversal|file_upload|code_injection|sql_injection
	Severity   string    `json:"severity"` // low|medium|high|critical
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	RequestURI string    `json:"request_uri"`
	Payload    string    `json:"payload"`
	Blocked    bool      `json:"blocked"`
	Action     string    `json:"action"` // blocked|logged|monitored
}

// ValidateUpload 验证文件上传
func (ps *PHPSecurity) ValidateUpload(domain string, filename string, size int64, contentType string) (*SecurityViolation, error) {
	var site *config.PHPSite
	for i := range ps.config.PHPSites {
		if strings.EqualFold(ps.config.PHPSites[i].Domain, domain) {
			site = &ps.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 检查是否启用安全配置
	if site.SecurityConfig == nil {
		return nil, nil // 未启用安全检查
	}

	violation := &SecurityViolation{
		Timestamp: time.Now(),
		Domain:    domain,
		Type:      "file_upload",
		Severity:  "medium",
		Blocked:   false,
		Action:    "logged",
	}

	// 检查文件大小
	if site.SecurityConfig.MaxUploadSize > 0 && size > site.SecurityConfig.MaxUploadSize {
		violation.Severity = "high"
		violation.Blocked = true
		violation.Action = "blocked"
		violation.Payload = fmt.Sprintf("文件大小 %d 超过限制 %d", size, site.SecurityConfig.MaxUploadSize)
		ps.logSecurityViolation(violation)
		return violation, fmt.Errorf("文件大小超过限制")
	}

	// 检查文件扩展名
	ext := strings.ToLower(filepath.Ext(filename))

	// 检查禁止的扩展名
	for _, blockedExt := range site.SecurityConfig.BlockedExtensions {
		if strings.EqualFold(ext, blockedExt) {
			violation.Severity = "critical"
			violation.Blocked = true
			violation.Action = "blocked"
			violation.Payload = fmt.Sprintf("禁止的文件扩展名: %s", ext)
			ps.logSecurityViolation(violation)
			return violation, fmt.Errorf("禁止的文件扩展名: %s", ext)
		}
	}

	// 检查允许的扩展名
	if len(site.SecurityConfig.AllowedExtensions) > 0 {
		allowed := false
		for _, allowedExt := range site.SecurityConfig.AllowedExtensions {
			if strings.EqualFold(ext, allowedExt) {
				allowed = true
				break
			}
		}
		if !allowed {
			violation.Severity = "high"
			violation.Blocked = true
			violation.Action = "blocked"
			violation.Payload = fmt.Sprintf("不允许的文件扩展名: %s", ext)
			ps.logSecurityViolation(violation)
			return violation, fmt.Errorf("不允许的文件扩展名: %s", ext)
		}
	}

	// 检查文件内容（简单的 MIME 类型验证）
	if !ps.validateFileContent(filename, contentType) {
		violation.Severity = "high"
		violation.Blocked = true
		violation.Action = "blocked"
		violation.Payload = fmt.Sprintf("文件内容与扩展名不匹配: %s", contentType)
		ps.logSecurityViolation(violation)
		return violation, fmt.Errorf("文件内容与扩展名不匹配")
	}

	return nil, nil // 通过验证
}

// ValidatePath 验证路径安全
func (ps *PHPSecurity) ValidatePath(domain string, path string, clientIP string, userAgent string) (*SecurityViolation, error) {
	var site *config.PHPSite
	for i := range ps.config.PHPSites {
		if strings.EqualFold(ps.config.PHPSites[i].Domain, domain) {
			site = &ps.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	// 检查是否启用路径安全检查
	if site.SecurityConfig == nil || !site.SecurityConfig.DisablePathTraversal {
		return nil, nil
	}

	violation := &SecurityViolation{
		Timestamp:  time.Now(),
		Domain:     domain,
		Type:       "path_traversal",
		Severity:   "high",
		IP:         clientIP,
		UserAgent:  userAgent,
		RequestURI: path,
		Blocked:    false,
		Action:     "logged",
	}

	// 检查路径遍历攻击
	if ps.containsPathTraversal(path) {
		violation.Severity = "critical"
		violation.Blocked = true
		violation.Action = "blocked"
		violation.Payload = path
		ps.logSecurityViolation(violation)
		return violation, fmt.Errorf("检测到路径遍历攻击")
	}

	// 检查允许的路径
	if len(site.SecurityConfig.AllowedPaths) > 0 {
		allowed := false
		for _, allowedPath := range site.SecurityConfig.AllowedPaths {
			if strings.HasPrefix(path, allowedPath) {
				allowed = true
				break
			}
		}
		if !allowed {
			violation.Severity = "medium"
			violation.Blocked = true
			violation.Action = "blocked"
			violation.Payload = path
			ps.logSecurityViolation(violation)
			return violation, fmt.Errorf("访问路径不在允许列表中")
		}
	}

	return nil, nil
}

// ValidateCode 验证代码安全
func (ps *PHPSecurity) ValidateCode(domain string, code string, clientIP string, userAgent string) (*SecurityViolation, error) {
	var site *config.PHPSite
	for i := range ps.config.PHPSites {
		if strings.EqualFold(ps.config.PHPSites[i].Domain, domain) {
			site = &ps.config.PHPSites[i]
			break
		}
	}

	if site == nil {
		return nil, fmt.Errorf("PHP site not found for domain: %s", domain)
	}

	if site.SecurityConfig == nil {
		return nil, nil
	}

	violation := &SecurityViolation{
		Timestamp: time.Now(),
		Domain:    domain,
		Type:      "code_injection",
		Severity:  "critical",
		IP:        clientIP,
		UserAgent: userAgent,
		Payload:   code,
		Blocked:   false,
		Action:    "logged",
	}

	// 检查危险函数
	if ps.containsDangerousFunctions(code, site.SecurityConfig) {
		violation.Severity = "critical"
		violation.Blocked = true
		violation.Action = "blocked"
		ps.logSecurityViolation(violation)
		return violation, fmt.Errorf("检测到危险函数调用")
	}

	// 检查 SQL 注入
	if ps.containsSQLInjection(code) {
		violation.Type = "sql_injection"
		violation.Severity = "critical"
		violation.Blocked = true
		violation.Action = "blocked"
		ps.logSecurityViolation(violation)
		return violation, fmt.Errorf("检测到 SQL 注入攻击")
	}

	// 检查代码注入
	if ps.containsCodeInjection(code) {
		violation.Severity = "critical"
		violation.Blocked = true
		violation.Action = "blocked"
		ps.logSecurityViolation(violation)
		return violation, fmt.Errorf("检测到代码注入攻击")
	}

	return nil, nil
}

// containsPathTraversal 检查是否包含路径遍历
func (ps *PHPSecurity) containsPathTraversal(path string) bool {
	dangerousPatterns := []string{
		"../", "..\\", "..%2f", "..%5c",
		"%2e%2e%2f", "%2e%2e%5c",
		"....//", "....\\\\",
	}

	pathLower := strings.ToLower(path)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}

	return false
}

// containsDangerousFunctions 检查是否包含危险函数
func (ps *PHPSecurity) containsDangerousFunctions(code string, securityConfig *config.PHPSecurityConfig) bool {
	// 检查禁用的函数
	if securityConfig.DisableEval && strings.Contains(code, "eval(") {
		return true
	}

	if securityConfig.DisableShellExec {
		shellFunctions := []string{
			"exec(", "system(", "shell_exec(", "passthru(",
			"proc_open(", "popen(", "proc_get_status(",
		}
		for _, funcName := range shellFunctions {
			if strings.Contains(code, funcName) {
				return true
			}
		}
	}

	// 检查允许的函数列表
	if len(securityConfig.AllowedFunctions) > 0 {
		dangerousFunctions := []string{
			"file_get_contents(", "file_put_contents(", "fopen(", "fwrite(",
			"unlink(", "rmdir(", "mkdir(", "chmod(", "chown(",
			"ini_set(", "ini_get(", "set_time_limit(",
		}

		for _, funcName := range dangerousFunctions {
			if strings.Contains(code, funcName) {
				// 检查是否在允许列表中
				allowed := false
				for _, allowedFunc := range securityConfig.AllowedFunctions {
					if strings.Contains(funcName, allowedFunc) {
						allowed = true
						break
					}
				}
				if !allowed {
					return true
				}
			}
		}
	}

	return false
}

// containsSQLInjection 检查是否包含 SQL 注入
func (ps *PHPSecurity) containsSQLInjection(code string) bool {
	sqlPatterns := []string{
		"union select", "union all select",
		"drop table", "delete from", "truncate table",
		"insert into", "update set",
		"or 1=1", "and 1=1",
		"'; --", "\"; --",
		"sleep(", "benchmark(",
		"load_file(", "into outfile",
	}

	codeLower := strings.ToLower(code)
	for _, pattern := range sqlPatterns {
		if strings.Contains(codeLower, pattern) {
			return true
		}
	}

	return false
}

// containsCodeInjection 检查是否包含代码注入
func (ps *PHPSecurity) containsCodeInjection(code string) bool {
	injectionPatterns := []string{
		"<script", "</script>",
		"javascript:", "vbscript:",
		"onload=", "onerror=", "onclick=",
		"eval(", "setTimeout(", "setInterval(",
		"document.cookie", "document.location",
		"window.location", "location.href",
	}

	codeLower := strings.ToLower(code)
	for _, pattern := range injectionPatterns {
		if strings.Contains(codeLower, pattern) {
			return true
		}
	}

	return false
}

// validateFileContent 验证文件内容
func (ps *PHPSecurity) validateFileContent(filename string, contentType string) bool {
	ext := strings.ToLower(filepath.Ext(filename))

	// 简单的 MIME 类型验证
	mimeMap := map[string][]string{
		".jpg":  {"image/jpeg", "image/jpg"},
		".jpeg": {"image/jpeg", "image/jpg"},
		".png":  {"image/png"},
		".gif":  {"image/gif"},
		".pdf":  {"application/pdf"},
		".txt":  {"text/plain"},
		".html": {"text/html"},
		".css":  {"text/css"},
		".js":   {"application/javascript", "text/javascript"},
	}

	expectedTypes, exists := mimeMap[ext]
	if !exists {
		return true // 未知扩展名，不进行验证
	}

	for _, expectedType := range expectedTypes {
		if strings.EqualFold(contentType, expectedType) {
			return true
		}
	}

	return false
}

// logSecurityViolation 记录安全违规
func (ps *PHPSecurity) logSecurityViolation(violation *SecurityViolation) {
	ps.log.WithFields(logrus.Fields{
		"domain":   violation.Domain,
		"type":     violation.Type,
		"severity": violation.Severity,
		"ip":       violation.IP,
		"payload":  violation.Payload,
		"blocked":  violation.Blocked,
	}).Warnf("PHP 安全违规: %s", violation.Type)
}

// GenerateSecurityHeaders 生成安全响应头
func (ps *PHPSecurity) GenerateSecurityHeaders(domain string) map[string]string {
	headers := make(map[string]string)

	// 基础安全头
	headers["X-Content-Type-Options"] = "nosniff"
	headers["X-Frame-Options"] = "DENY"
	headers["X-XSS-Protection"] = "1; mode=block"
	headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

	// 内容安全策略
	headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"

	// 隐藏 PHP 版本
	headers["X-Powered-By"] = "sslcat"

	// 严格传输安全（仅 HTTPS）
	headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

	return headers
}

// ApplySecurityHeaders 应用安全响应头
func (ps *PHPSecurity) ApplySecurityHeaders(w http.ResponseWriter, domain string) {
	headers := ps.GenerateSecurityHeaders(domain)
	for key, value := range headers {
		w.Header().Set(key, value)
	}
}

// GetSecurityReport 获取安全报告
func (ps *PHPSecurity) GetSecurityReport(domain string, days int) (map[string]interface{}, error) {
	// 这里应该从安全日志中读取数据
	// 简化实现，返回模拟数据
	report := map[string]interface{}{
		"domain":           domain,
		"period_days":      days,
		"total_violations": 0,
		"blocked_requests": 0,
		"violations_by_type": map[string]int{
			"path_traversal": 0,
			"file_upload":    0,
			"code_injection": 0,
			"sql_injection":  0,
		},
		"violations_by_severity": map[string]int{
			"low":      0,
			"medium":   0,
			"high":     0,
			"critical": 0,
		},
		"top_attack_ips": []map[string]interface{}{},
		"security_score": 100, // 0-100 安全评分
	}

	return report, nil
}
