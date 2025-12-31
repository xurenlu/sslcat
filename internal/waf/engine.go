package waf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// RuleType WAF规则类型
type RuleType string

const (
	RuleTypeSQLInjection     RuleType = "sql_injection"
	RuleTypeXSS              RuleType = "xss"
	RuleTypePathTraversal    RuleType = "path_traversal"
	RuleTypeCommandInjection RuleType = "command_injection"
	RuleTypeFileUpload       RuleType = "file_upload"
	RuleTypeSensitiveFile    RuleType = "sensitive_file"    // 敏感文件访问
	RuleTypeScannerDetection RuleType = "scanner_detection" // 扫描工具检测
	RuleTypeCustom           RuleType = "custom"
)

// Action WAF动作
type Action string

const (
	ActionBlock Action = "block"
	ActionLog   Action = "log"
	ActionWarn  Action = "warn"
)

// Rule WAF规则
type Rule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        RuleType       `json:"type"`
	Pattern     string         `json:"pattern"`
	Regex       *regexp.Regexp `json:"-"`
	Action      Action         `json:"action"`
	Enabled     bool           `json:"enabled"`
	Description string         `json:"description"`
	CreatedAt   time.Time      `json:"created_at"`
}

// AttackEvent 攻击事件
type AttackEvent struct {
	ID        string    `json:"id"`
	ClientIP  string    `json:"client_ip"`
	UserAgent string    `json:"user_agent"`
	URL       string    `json:"url"`
	Method    string    `json:"method"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	RuleType  RuleType  `json:"rule_type"`
	Action    Action    `json:"action"`
	Payload   string    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
	Blocked   bool      `json:"blocked"`
}

// Engine WAF引擎
type Engine struct {
	rules        map[string]*Rule
	sqlPatterns  []*Rule
	xssPatterns  []*Rule
	pathPatterns []*Rule
	cmdPatterns  []*Rule
	customRules  []*Rule
	enabled      bool
	events       []AttackEvent
	maxEvents    int
	mutex        sync.RWMutex
	log          *logrus.Entry
	
	// 日志限流器：防止大量重复日志导致 CPU 高占用
	logLimiter   *wafLogRateLimiter
	// 事件清理定时器
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	
	// 多维度封禁器（替代原有的 rateLimiter）
	multiDimBlocker *wafMultiDimBlocker
}

// WAFRateLimitConfig WAF 频率限制配置（保留向后兼容）
type WAFRateLimitConfig struct {
	Enabled       bool
	WindowSec     int
	MaxHits       int
	BlockDurationSec int
}

// NewEngine 创建WAF引擎
func NewEngine(rateLimitConfig *WAFRateLimitConfig, multiDimConfig *MultiDimBlockConfig) *Engine {
	log := logrus.WithFields(logrus.Fields{
		"component": "waf_engine",
	})

	// 初始化多维度封禁器
	var multiDimBlocker *wafMultiDimBlocker
	if multiDimConfig != nil {
		multiDimBlocker = newWAFMultiDimBlocker(multiDimConfig, log)
	} else if rateLimitConfig != nil {
		// 向后兼容：将旧的 rateLimitConfig 转换为 multiDimConfig
		multiDimBlocker = newWAFMultiDimBlocker(&MultiDimBlockConfig{
			IPEnabled:       rateLimitConfig.Enabled,
			IPWindow:        time.Duration(rateLimitConfig.WindowSec) * time.Second,
			IPMaxHits:       rateLimitConfig.MaxHits,
			IPBlockDuration: time.Duration(rateLimitConfig.BlockDurationSec) * time.Second,
			TLSEnabled:      false,
			SubnetEnabled:   false,
		}, log)
	} else {
		// 默认配置：全部禁用
		multiDimBlocker = newWAFMultiDimBlocker(&MultiDimBlockConfig{
			IPEnabled:     false,
			TLSEnabled:    false,
			SubnetEnabled: false,
		}, log)
	}

	engine := &Engine{
		rules:           make(map[string]*Rule),
		enabled:         true,
		events:          make([]AttackEvent, 0),
		maxEvents:       10000, // 最多保存10000个事件
		logLimiter:      newWAFLogRateLimiter(time.Minute), // 相同攻击每分钟最多记录一次日志
		cleanupTicker:   time.NewTicker(10 * time.Minute), // 每10分钟清理一次过期事件
		stopChan:        make(chan struct{}),
		log:             log,
		multiDimBlocker: multiDimBlocker,
	}

	// 初始化默认规则
	engine.initDefaultRules()

	// 启动事件清理协程
	go engine.eventCleanupLoop()

	return engine
}

// eventCleanupLoop 事件清理循环
func (e *Engine) eventCleanupLoop() {
	for {
		select {
		case <-e.cleanupTicker.C:
			e.cleanupOldEvents()
		case <-e.stopChan:
			e.cleanupTicker.Stop()
			return
		}
	}
}

// cleanupOldEvents 清理超过24小时的旧事件
func (e *Engine) cleanupOldEvents() {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	now := time.Now()
	maxAge := 24 * time.Hour
	keepIndex := -1 // 使用 -1 表示未找到有效事件

	// 找到第一个在24小时内的事件
	for i, event := range e.events {
		if now.Sub(event.Timestamp) <= maxAge {
			keepIndex = i
			break
		}
	}

	// 如果找到了有效事件，删除该索引之前的所有过期事件
	if keepIndex > 0 {
		removed := keepIndex
		e.events = e.events[keepIndex:]
		e.log.Debugf("WAF清理了 %d 个过期事件（超过24小时）", removed)
	} else if keepIndex == -1 {
		// 所有事件都过期了，清空所有事件
		removed := len(e.events)
		e.events = make([]AttackEvent, 0)
		if removed > 0 {
			e.log.Debugf("WAF清理了 %d 个过期事件（超过24小时，全部清空）", removed)
		}
	}
	// 如果 keepIndex == 0，说明第一个事件就是有效的，不需要删除任何事件

	// 如果事件数量仍超过限制，进一步清理
	if len(e.events) > e.maxEvents {
		overflow := len(e.events) - e.maxEvents
		e.events = e.events[overflow:]
		e.log.Debugf("WAF清理了 %d 个超出数量限制的事件", overflow)
	}
}

// Stop 停止WAF引擎（用于优雅关闭）
func (e *Engine) Stop() {
	if e.stopChan != nil {
		close(e.stopChan)
	}
	if e.logLimiter != nil {
		e.logLimiter.Stop()
	}
}

// initDefaultRules 初始化默认规则
func (e *Engine) initDefaultRules() {
	// SQL注入规则
	sqlRules := []struct {
		name    string
		pattern string
	}{
		{"SQL Union Attack", `(?i)(union.*select|select.*union)`},
		{"SQL Comments", `(?i)(--|#|/\*|\*/)`},
		{"SQL Keywords", `(?i)(drop|delete|insert|update|alter|create|exec|execute|sp_|xp_)`},
		{"SQL Functions", `(?i)(concat|substring|char|ascii|hex|unhex|md5|sha1)`},
		{"SQL Operators", `(?i)(\bor\b.*=|and.*=.*|'.*'.*=|".*".*=)`},
		{"SQL Time-based", `(?i)(sleep|benchmark|waitfor|delay)`},
		{"SQL Error-based", `(?i)(extractvalue|updatexml|exp|floor|rand)`},
	}

	for i, rule := range sqlRules {
		e.AddRule(&Rule{
			ID:          fmt.Sprintf("sql_%d", i+1),
			Name:        rule.name,
			Type:        RuleTypeSQLInjection,
			Pattern:     rule.pattern,
			Action:      ActionBlock,
			Enabled:     true,
			Description: "SQL注入攻击检测",
			CreatedAt:   time.Now(),
		})
	}

	// XSS规则
	xssRules := []struct {
		name    string
		pattern string
	}{
		{"Script Tag", `(?i)<script.*?>.*?</script>`},
		{"JavaScript Events", `(?i)(onload|onclick|onmouseover|onerror|onsubmit|onchange)=`},
		{"JavaScript Protocol", `(?i)javascript:`},
		{"HTML Injection", `(?i)<(iframe|object|embed|meta|link|style)`},
		{"Data URI", `(?i)data:.*base64`},
		{"Expression", `(?i)expression\s*\(`},
	}

	for i, rule := range xssRules {
		e.AddRule(&Rule{
			ID:          fmt.Sprintf("xss_%d", i+1),
			Name:        rule.name,
			Type:        RuleTypeXSS,
			Pattern:     rule.pattern,
			Action:      ActionBlock,
			Enabled:     true,
			Description: "跨站脚本攻击检测",
			CreatedAt:   time.Now(),
		})
	}

	// 路径遍历规则
	pathRules := []struct {
		name    string
		pattern string
	}{
		{"Directory Traversal", `\.\.\/|\.\.\\`},
		{"Absolute Path", `^\/.*\/.*\/`},
		{"Null Byte", `%00`},
		{"Encoded Traversal", `%2e%2e%2f|%2e%2e%5c`},
	}

	for i, rule := range pathRules {
		e.AddRule(&Rule{
			ID:          fmt.Sprintf("path_%d", i+1),
			Name:        rule.name,
			Type:        RuleTypePathTraversal,
			Pattern:     rule.pattern,
			Action:      ActionBlock,
			Enabled:     true,
			Description: "路径遍历攻击检测",
			CreatedAt:   time.Now(),
		})
	}

	// 命令注入规则
	cmdRules := []struct {
		name    string
		pattern string
	}{
		{"Command Execution", `(?i)(;|&&|\|\||\|).*?(cat|ls|pwd|id|whoami|uname)`},
		{"System Commands", `(?i)(cmd|bash|sh|powershell|exec|system)`},
		{"File Operations", `(?i)(rm|del|copy|move|mkdir|rmdir)`},
		{"Network Commands", `(?i)(ping|wget|curl|nc|netcat|telnet)`},
	}

	for i, rule := range cmdRules {
		e.AddRule(&Rule{
			ID:          fmt.Sprintf("cmd_%d", i+1),
			Name:        rule.name,
			Type:        RuleTypeCommandInjection,
			Pattern:     rule.pattern,
			Action:      ActionBlock,
			Enabled:     true,
			Description: "命令注入攻击检测",
			CreatedAt:   time.Now(),
		})
	}

	// 敏感文件访问规则
	sensitiveFileRules := []struct {
		name    string
		pattern string
	}{
		{"Git Config", `(?i)/\.git/`},
		{"Git Files", `(?i)\.git/config|\.git/HEAD|\.git/index`},
		{"AWS Credentials", `(?i)/\.aws/|\.aws/credentials`},
		{"Environment Files", `(?i)/\.env$|/\.env\b|\.env\.local`},
		{"Config Files", `(?i)/config\.php|/config\.json|/config\.yml|/config\.yaml`},
		{"Backup Files", `(?i)\.bak$|\.backup$|\.old$|\.orig$|\.swp$|\.tmp$`},
		{"Database Files", `(?i)\.db$|\.sqlite$|\.sql$|/phpmyadmin`},
		{"Private Keys", `(?i)/id_rsa$|/id_dsa$|/\.ssh/|/\.pem$`},
		{"Server Files", `(?i)/server\.js|/package\.json|/composer\.json|/requirements\.txt`},
		{"Admin Panels", `(?i)/admin|/wp-admin|/administrator|/phpmyadmin`},
		{"Test Files", `(?i)/test\.php|/info\.php|/phpinfo\.php`},
	}

	for i, rule := range sensitiveFileRules {
		e.AddRule(&Rule{
			ID:          fmt.Sprintf("sensitive_%d", i+1),
			Name:        rule.name,
			Type:        RuleTypeSensitiveFile,
			Pattern:     rule.pattern,
			Action:      ActionBlock,
			Enabled:     true,
			Description: "敏感文件/路径访问检测",
			CreatedAt:   time.Now(),
		})
	}

	// 安全扫描工具检测规则
	scannerRules := []struct {
		name    string
		pattern string
	}{
		{"Assetnote Scanner", `(?i)Assetnote`},
		{"Nmap Scanner", `(?i)nmap|Nmap`},
		{"Nikto Scanner", `(?i)nikto|Nikto`},
		{"SQLMap Scanner", `(?i)sqlmap`},
		{"Acunetix Scanner", `(?i)Acunetix|WVS`},
		{"AppScan Scanner", `(?i)AppScan|Rational`},
		{"Nessus Scanner", `(?i)Nessus`},
		{"OpenVAS Scanner", `(?i)OpenVAS`},
		{"Qualys Scanner", `(?i)Qualys`},
		{"Burp Scanner", `(?i)Burp`},
		{"OWASP Scanner", `(?i)OWASP|ZAP`},
		{"Masscan Scanner", `(?i)masscan`},
		{"Zmap Scanner", `(?i)zmap`},
		{"Shodan Scanner", `(?i)Shodan`},
		{"Censys Scanner", `(?i)Censys`},
	}

	for i, rule := range scannerRules {
		e.AddRule(&Rule{
			ID:          fmt.Sprintf("scanner_%d", i+1),
			Name:        rule.name,
			Type:        RuleTypeScannerDetection,
			Pattern:     rule.pattern,
			Action:      ActionBlock, // 直接阻止扫描工具
			Enabled:     true,
			Description: "安全扫描工具检测",
			CreatedAt:   time.Now(),
		})
	}

	e.log.Infof("已初始化 %d 个默认WAF规则", len(e.rules))
}

// AddRule 添加规则
func (e *Engine) AddRule(rule *Rule) error {
	regex, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("编译正则表达式失败: %w", err)
	}

	rule.Regex = regex

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.rules[rule.ID] = rule

	// 按类型分类
	switch rule.Type {
	case RuleTypeSQLInjection:
		e.sqlPatterns = append(e.sqlPatterns, rule)
	case RuleTypeXSS:
		e.xssPatterns = append(e.xssPatterns, rule)
	case RuleTypePathTraversal:
		e.pathPatterns = append(e.pathPatterns, rule)
	case RuleTypeCommandInjection:
		e.cmdPatterns = append(e.cmdPatterns, rule)
	case RuleTypeSensitiveFile, RuleTypeScannerDetection:
		// 敏感文件和扫描工具检测规则使用自定义规则存储
		e.customRules = append(e.customRules, rule)
	case RuleTypeCustom:
		e.customRules = append(e.customRules, rule)
	}

	return nil
}

// RemoveRule 删除规则
func (e *Engine) RemoveRule(ruleID string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	delete(e.rules, ruleID)

	// 从分类数组中删除
	e.removeFromSlice(&e.sqlPatterns, ruleID)
	e.removeFromSlice(&e.xssPatterns, ruleID)
	e.removeFromSlice(&e.pathPatterns, ruleID)
	e.removeFromSlice(&e.cmdPatterns, ruleID)
	e.removeFromSlice(&e.customRules, ruleID)
}

// removeFromSlice 从切片中删除规则
func (e *Engine) removeFromSlice(slice *[]*Rule, ruleID string) {
	for i, rule := range *slice {
		if rule.ID == ruleID {
			*slice = append((*slice)[:i], (*slice)[i+1:]...)
			break
		}
	}
}

// CheckRequest 检查请求（不带 TLS 指纹，向后兼容）
func (e *Engine) CheckRequest(r *http.Request) (*AttackEvent, bool) {
	return e.CheckRequestWithTLS(r, "")
}

// CheckRequestWithTLS 检查请求（带 TLS 指纹）
func (e *Engine) CheckRequestWithTLS(r *http.Request, tlsFingerprint string) (*AttackEvent, bool) {
	if !e.enabled {
		return nil, false
	}

	// 获取请求数据
	url := r.URL.String()
	method := r.Method
	clientIP := e.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// 检查多维度封禁
	if e.multiDimBlocker != nil {
		if blocked, dimension, reason := e.multiDimBlocker.IsBlocked(clientIP, tlsFingerprint); blocked {
			event := &AttackEvent{
				ID:        e.generateEventID(),
				ClientIP:  clientIP,
				UserAgent: userAgent,
				URL:       url,
				Method:    method,
				RuleID:    string(dimension),
				RuleName:  fmt.Sprintf("多维度封禁: %s", dimension),
				RuleType:  RuleTypeCustom,
				Action:    ActionBlock,
				Payload:   reason,
				Timestamp: time.Now(),
				Blocked:   true,
			}
			return event, true
		}
	}

	// 使用读锁进行检测
	e.mutex.RLock()
	var event *AttackEvent
	
	// 1. 检查URL路径（敏感文件检测）
	if event = e.checkURLPath(r, clientIP, userAgent, url, method); event == nil {
		// 2. 检查User-Agent（扫描工具检测）
		if event = e.checkUserAgent(r, clientIP, userAgent, url, method); event == nil {
			// 3. 检查URL参数
			if event = e.checkURLParams(r, clientIP, userAgent, url, method); event == nil {
				// 4. 检查请求头
				if event = e.checkHeaders(r, clientIP, userAgent, url, method); event == nil {
					// 5. 检查请求体
					event = e.checkBody(r, clientIP, userAgent, url, method)
				}
			}
		}
	}
	e.mutex.RUnlock()

	// 如果检测到攻击，在释放读锁后添加事件
	if event != nil {
		e.addEvent(event)
		
		// 记录到多维度封禁器
		if e.multiDimBlocker != nil {
			e.multiDimBlocker.RecordHit(clientIP, tlsFingerprint)
		}
		
		return event, event.Blocked
	}

	return nil, false
}

// checkURLPath 检查URL路径
func (e *Engine) checkURLPath(r *http.Request, clientIP, userAgent, url, method string) *AttackEvent {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	// 检查敏感文件路径规则
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		// 只检查敏感文件和扫描工具类型的规则
		if rule.Type != RuleTypeSensitiveFile && rule.Type != RuleTypeScannerDetection {
			continue
		}

		if rule.Regex.MatchString(path) {
			event := &AttackEvent{
				ID:        e.generateEventID(),
				ClientIP:  clientIP,
				UserAgent: userAgent,
				URL:       url,
				Method:    method,
				RuleID:    rule.ID,
				RuleName:  rule.Name,
				RuleType:  rule.Type,
				Action:    rule.Action,
				Payload:   path,
				Timestamp: time.Now(),
				Blocked:   rule.Action == ActionBlock,
			}

			// 日志记录（使用限流器避免日志风暴）
			logKey := fmt.Sprintf("%s:%s:%s", rule.Type, clientIP, rule.ID)
			if shouldLog, _ := e.logLimiter.shouldLog(logKey); shouldLog {
				e.log.Warnf("WAF检测到%s: %s from %s, 路径: %s, 动作: %s",
					map[RuleType]string{
						RuleTypeSensitiveFile:    "敏感文件访问",
						RuleTypeScannerDetection: "扫描工具访问",
					}[rule.Type], rule.Name, clientIP, path, rule.Action)
			}

			return event
		}
	}

	return nil
}

// checkUserAgent 检查User-Agent
func (e *Engine) checkUserAgent(r *http.Request, clientIP, userAgent, url, method string) *AttackEvent {
	if userAgent == "" {
		return nil
	}

	// 检查扫描工具User-Agent规则
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if rule.Type != RuleTypeScannerDetection {
			continue
		}

		if rule.Regex.MatchString(userAgent) {
			event := &AttackEvent{
				ID:        e.generateEventID(),
				ClientIP:  clientIP,
				UserAgent: userAgent,
				URL:       url,
				Method:    method,
				RuleID:    rule.ID,
				RuleName:  rule.Name,
				RuleType:  rule.Type,
				Action:    rule.Action,
				Payload:   "User-Agent: " + userAgent,
				Timestamp: time.Now(),
				Blocked:   rule.Action == ActionBlock,
			}

			// 使用日志限流器：相同扫描工具每分钟最多记录一次日志
			logKey := fmt.Sprintf("scanner:%s:%s:%s", clientIP, rule.ID, userAgent)
			if shouldLog, _ := e.logLimiter.shouldLog(logKey); shouldLog {
				e.log.Warnf("WAF检测到扫描工具: %s from %s, User-Agent: %s, 动作: %s",
					rule.Name, clientIP, userAgent, rule.Action)
			}

			return event
		}
	}

	return nil
}

// checkURLParams 检查URL参数
func (e *Engine) checkURLParams(r *http.Request, clientIP, userAgent, url, method string) *AttackEvent {
	params := r.URL.Query()

	for key, values := range params {
		for _, value := range values {
			payload := key + "=" + value
			if event := e.matchRules(payload, clientIP, userAgent, url, method); event != nil {
				return event
			}
		}
	}

	return nil
}

// checkHeaders 检查请求头
func (e *Engine) checkHeaders(r *http.Request, clientIP, userAgent, url, method string) *AttackEvent {
	for key, values := range r.Header {
		for _, value := range values {
			payload := key + ": " + value
			if event := e.matchRules(payload, clientIP, userAgent, url, method); event != nil {
				return event
			}
		}
	}

	return nil
}

// checkBody 检查请求体
func (e *Engine) checkBody(r *http.Request, clientIP, userAgent, url, method string) *AttackEvent {
	if r.Body == nil {
		return nil
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}

	// 恢复请求体
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// 检查请求体内容
	if len(body) > 0 {
		payload := string(body)
		if event := e.matchRules(payload, clientIP, userAgent, url, method); event != nil {
			return event
		}

		// 如果是表单数据，解析并检查
		if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			if values, err := neturl.ParseQuery(payload); err == nil {
				for key, vals := range values {
					for _, val := range vals {
						formPayload := key + "=" + val
						if event := e.matchRules(formPayload, clientIP, userAgent, url, method); event != nil {
							return event
						}
					}
				}
			}
		}
	}

	return nil
}

// matchRules 匹配规则
func (e *Engine) matchRules(payload, clientIP, userAgent, url, method string) *AttackEvent {
	// 对所有启用的规则进行匹配
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		if rule.Regex.MatchString(payload) {
			event := &AttackEvent{
				ID:        e.generateEventID(),
				ClientIP:  clientIP,
				UserAgent: userAgent,
				URL:       url,
				Method:    method,
				RuleID:    rule.ID,
				RuleName:  rule.Name,
				RuleType:  rule.Type,
				Action:    rule.Action,
				Payload:   payload,
				Timestamp: time.Now(),
				Blocked:   rule.Action == ActionBlock,
			}

			// 使用日志限流器：相同攻击每分钟最多记录一次日志
			logKey := fmt.Sprintf("%s:%s:%s:%s", rule.Type, clientIP, rule.ID, payload[:min(len(payload), 100)])
			if shouldLog, _ := e.logLimiter.shouldLog(logKey); shouldLog {
				e.log.Warnf("WAF检测到攻击: %s from %s, 规则: %s, 动作: %s",
					rule.Type, clientIP, rule.Name, rule.Action)
			}

			return event
		}
	}

	return nil
}

// addEvent 添加事件（注意：调用此方法时必须已经释放读锁，因为需要获取写锁）
func (e *Engine) addEvent(event *AttackEvent) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	
	e.events = append(e.events, *event)

	// 保持事件数量限制
	if len(e.events) > e.maxEvents {
		e.events = e.events[1:]
	}
}

// generateEventID 生成事件ID
func (e *Engine) generateEventID() string {
	return fmt.Sprintf("waf_%d", time.Now().UnixNano())
}

// getClientIP 获取客户端IP
func (e *Engine) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	if ip := r.RemoteAddr; ip != "" {
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			return ip[:idx]
		}
		return ip
	}

	return "unknown"
}

// SetEnabled 设置启用状态
func (e *Engine) SetEnabled(enabled bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.enabled = enabled
	e.log.Infof("WAF引擎已%s", map[bool]string{true: "启用", false: "禁用"}[enabled])
}

// IsEnabled 检查是否启用
func (e *Engine) IsEnabled() bool {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.enabled
}

// GetRules 获取所有规则
func (e *Engine) GetRules() map[string]*Rule {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	result := make(map[string]*Rule)
	for id, rule := range e.rules {
		result[id] = rule
	}

	return result
}

// GetEvents 获取攻击事件
func (e *Engine) GetEvents(limit int) []AttackEvent {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	if limit <= 0 || limit > len(e.events) {
		limit = len(e.events)
	}

	// 返回最新的事件
	start := len(e.events) - limit
	return e.events[start:]
}

// GetEventsByType 按类型获取事件
func (e *Engine) GetEventsByType(ruleType RuleType, limit int) []AttackEvent {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	var filtered []AttackEvent
	for i := len(e.events) - 1; i >= 0; i-- {
		if e.events[i].RuleType == ruleType {
			filtered = append(filtered, e.events[i])
			if len(filtered) >= limit {
				break
			}
		}
	}

	return filtered
}

// GetStats 获取统计信息
func (e *Engine) GetStats() map[string]interface{} {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	stats := map[string]interface{}{
		"enabled":      e.enabled,
		"total_rules":  len(e.rules),
		"total_events": len(e.events),
	}

	// 按类型统计规则
	rulesByType := make(map[RuleType]int)
	for _, rule := range e.rules {
		rulesByType[rule.Type]++
	}
	stats["rules_by_type"] = rulesByType

	// 按类型统计事件
	eventsByType := make(map[RuleType]int)
	blockedEvents := 0

	for _, event := range e.events {
		eventsByType[event.RuleType]++
		if event.Blocked {
			blockedEvents++
		}
	}

	stats["events_by_type"] = eventsByType
	stats["blocked_events"] = blockedEvents
	stats["detection_rate"] = float64(len(e.events)) / float64(len(e.events)+1) * 100

	return stats
}

// ClearEvents 清空事件
func (e *Engine) ClearEvents() {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.events = make([]AttackEvent, 0)
	e.log.Info("WAF攻击事件已清空")
}

// GetRateLimitBlockedIPs 获取被频率限制封禁的 IP 列表（向后兼容）
func (e *Engine) GetRateLimitBlockedIPs() map[string]time.Time {
	if e.multiDimBlocker == nil {
		return make(map[string]time.Time)
	}
	
	result := make(map[string]time.Time)
	for _, record := range e.multiDimBlocker.GetBlockedList(DimensionIP) {
		result[record.Value] = record.ExpireTime
	}
	return result
}

// UnblockRateLimitIP 解除频率限制封禁（向后兼容）
func (e *Engine) UnblockRateLimitIP(ip string) {
	if e.multiDimBlocker != nil {
		e.multiDimBlocker.UnblockByDimension(DimensionIP, ip)
	}
}

// UpdateRateLimitConfig 更新频率限制配置（向后兼容）
func (e *Engine) UpdateRateLimitConfig(config *WAFRateLimitConfig) {
	if e.multiDimBlocker != nil && config != nil {
		// 更新 IP 维度配置
		e.multiDimBlocker.config.IPEnabled = config.Enabled
		e.multiDimBlocker.config.IPWindow = time.Duration(config.WindowSec) * time.Second
		e.multiDimBlocker.config.IPMaxHits = config.MaxHits
		e.multiDimBlocker.config.IPBlockDuration = time.Duration(config.BlockDurationSec) * time.Second
		
		e.log.Infof("WAF 频率限制配置已更新: enabled=%v, window=%ds, max_hits=%d, block=%ds",
			config.Enabled, config.WindowSec, config.MaxHits, config.BlockDurationSec)
	}
}

// GetMultiDimBlockedList 获取多维度封禁列表
func (e *Engine) GetMultiDimBlockedList(dimension BlockDimension) []*BlockRecord {
	if e.multiDimBlocker == nil {
		return []*BlockRecord{}
	}
	return e.multiDimBlocker.GetBlockedList(dimension)
}

// UnblockMultiDim 解除多维度封禁
func (e *Engine) UnblockMultiDim(dimension BlockDimension, value string) {
	if e.multiDimBlocker != nil {
		e.multiDimBlocker.UnblockByDimension(dimension, value)
	}
}

// BlockMultiDim 手动封禁（多维度）
func (e *Engine) BlockMultiDim(dimension BlockDimension, value string, duration time.Duration, reason string) {
	if e.multiDimBlocker != nil {
		e.multiDimBlocker.BlockByDimension(dimension, value, duration, reason)
	}
}

// GetSubnetStats 获取 IP 段统计
func (e *Engine) GetSubnetStats() map[string]int {
	if e.multiDimBlocker == nil {
		return make(map[string]int)
	}
	return e.multiDimBlocker.GetSubnetStats()
}

// GetTLSStats 获取 TLS 指纹统计
func (e *Engine) GetTLSStats() map[string]int {
	if e.multiDimBlocker == nil {
		return make(map[string]int)
	}
	return e.multiDimBlocker.GetTLSStats()
}

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// wafLogRateLimiter WAF日志限流器
type wafLogRateLimiter struct {
	mu            sync.RWMutex
	logs          map[string]time.Time // 日志键 -> 最后记录时间
	window        time.Duration        // 时间窗口
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	totalLogs     int64 // 总日志数（原子操作）
	skippedLogs   int64 // 跳过的日志数（原子操作）
}

// newWAFLogRateLimiter 创建WAF日志限流器
func newWAFLogRateLimiter(window time.Duration) *wafLogRateLimiter {
	limiter := &wafLogRateLimiter{
		logs:          make(map[string]time.Time),
		window:        window,
		cleanupTicker: time.NewTicker(5 * time.Minute), // 每5分钟清理一次过期记录
		stopChan:      make(chan struct{}),
	}

	// 启动清理协程
	go limiter.cleanupLoop()

	return limiter
}

// shouldLog 检查是否应该记录日志
// 返回: (shouldLog, skippedCount)
func (rl *wafLogRateLimiter) shouldLog(logKey string) (bool, int64) {
	atomic.AddInt64(&rl.totalLogs, 1)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	lastLogTime, exists := rl.logs[logKey]

	// 如果日志键不存在或已超过时间窗口，允许记录
	if !exists || now.Sub(lastLogTime) >= rl.window {
		rl.logs[logKey] = now
		return true, atomic.LoadInt64(&rl.skippedLogs)
	}

	// 否则跳过记录
	atomic.AddInt64(&rl.skippedLogs, 1)
	return false, atomic.LoadInt64(&rl.skippedLogs)
}

// cleanupLoop 定期清理过期的日志记录
func (rl *wafLogRateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.cleanup()
		case <-rl.stopChan:
			rl.cleanupTicker.Stop()
			return
		}
	}
}

// cleanup 清理过期的日志记录
func (rl *wafLogRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)

	for key, lastLogTime := range rl.logs {
		if now.Sub(lastLogTime) >= rl.window*2 { // 保留窗口的两倍时间
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(rl.logs, key)
	}
}

// Stop 停止日志限流器
func (rl *wafLogRateLimiter) Stop() {
	if rl.stopChan != nil {
		close(rl.stopChan)
	}
}

// wafRateLimiter WAF 频率限制器
type wafRateLimiter struct {
	mu            sync.RWMutex
	ipHits        map[string][]time.Time // IP -> 触发时间列表
	blockedIPs    map[string]time.Time   // IP -> 封禁到期时间
	enabled       bool
	window        time.Duration // 时间窗口
	maxHits       int           // 最大触发次数
	blockDuration time.Duration // 封禁时长
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	log           *logrus.Entry
}

// newWAFRateLimiter 创建 WAF 频率限制器
func newWAFRateLimiter(enabled bool, windowSec, maxHits, blockSec int, log *logrus.Entry) *wafRateLimiter {
	if windowSec <= 0 {
		windowSec = 60 // 默认 60 秒
	}
	if maxHits <= 0 {
		maxHits = 10 // 默认 10 次
	}
	if blockSec <= 0 {
		blockSec = 3600 // 默认 1 小时
	}

	rl := &wafRateLimiter{
		ipHits:        make(map[string][]time.Time),
		blockedIPs:    make(map[string]time.Time),
		enabled:       enabled,
		window:        time.Duration(windowSec) * time.Second,
		maxHits:       maxHits,
		blockDuration: time.Duration(blockSec) * time.Second,
		cleanupTicker: time.NewTicker(5 * time.Minute), // 每 5 分钟清理一次
		stopChan:      make(chan struct{}),
		log:           log,
	}

	// 启动清理协程
	go rl.cleanup()

	return rl
}

// RecordHit 记录一次 WAF 触发
func (rl *wafRateLimiter) RecordHit(ip string) bool {
	if !rl.enabled {
		return false
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// 检查是否已被封禁
	if expireTime, blocked := rl.blockedIPs[ip]; blocked {
		if now.Before(expireTime) {
			// 仍在封禁期内
			return true
		}
		// 封禁已过期，移除
		delete(rl.blockedIPs, ip)
	}

	// 获取该 IP 的触发历史
	hits := rl.ipHits[ip]

	// 移除过期的触发记录
	validHits := make([]time.Time, 0)
	for _, hitTime := range hits {
		if now.Sub(hitTime) < rl.window {
			validHits = append(validHits, hitTime)
		}
	}

	// 添加当前触发
	validHits = append(validHits, now)
	rl.ipHits[ip] = validHits

	// 检查是否超过阈值
	if len(validHits) >= rl.maxHits {
		// 封禁该 IP
		expireTime := now.Add(rl.blockDuration)
		rl.blockedIPs[ip] = expireTime
		rl.log.Warnf("WAF 频率限制：IP %s 在 %v 内触发 %d 次规则，已封禁 %v",
			ip, rl.window, len(validHits), rl.blockDuration)
		return true
	}

	return false
}

// IsBlocked 检查 IP 是否被封禁
func (rl *wafRateLimiter) IsBlocked(ip string) bool {
	if !rl.enabled {
		return false
	}

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	expireTime, blocked := rl.blockedIPs[ip]
	if !blocked {
		return false
	}

	// 检查是否已过期
	if time.Now().After(expireTime) {
		return false
	}

	return true
}

// GetBlockedIPs 获取所有被封禁的 IP
func (rl *wafRateLimiter) GetBlockedIPs() map[string]time.Time {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	result := make(map[string]time.Time)
	now := time.Now()

	for ip, expireTime := range rl.blockedIPs {
		if now.Before(expireTime) {
			result[ip] = expireTime
		}
	}

	return result
}

// UnblockIP 解除 IP 封禁
func (rl *wafRateLimiter) UnblockIP(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.blockedIPs, ip)
	delete(rl.ipHits, ip)
	rl.log.Infof("WAF 频率限制：已解除 IP %s 的封禁", ip)
}

// UpdateConfig 更新配置
func (rl *wafRateLimiter) UpdateConfig(enabled bool, windowSec, maxHits, blockSec int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.enabled = enabled
	if windowSec > 0 {
		rl.window = time.Duration(windowSec) * time.Second
	}
	if maxHits > 0 {
		rl.maxHits = maxHits
	}
	if blockSec > 0 {
		rl.blockDuration = time.Duration(blockSec) * time.Second
	}
}

// cleanup 清理过期数据
func (rl *wafRateLimiter) cleanup() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.doCleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// doCleanup 执行清理
func (rl *wafRateLimiter) doCleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// 清理过期的封禁记录
	for ip, expireTime := range rl.blockedIPs {
		if now.After(expireTime) {
			delete(rl.blockedIPs, ip)
		}
	}

	// 清理过期的触发记录
	for ip, hits := range rl.ipHits {
		validHits := make([]time.Time, 0)
		for _, hitTime := range hits {
			if now.Sub(hitTime) < rl.window*2 { // 保留窗口的两倍时间
				validHits = append(validHits, hitTime)
			}
		}
		if len(validHits) > 0 {
			rl.ipHits[ip] = validHits
		} else {
			delete(rl.ipHits, ip)
		}
	}
}

// Stop 停止频率限制器
func (rl *wafRateLimiter) Stop() {
	if rl.stopChan != nil {
		close(rl.stopChan)
	}
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
}
