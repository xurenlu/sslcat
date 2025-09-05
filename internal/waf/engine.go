package waf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
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
}

// NewEngine 创建WAF引擎
func NewEngine() *Engine {
	engine := &Engine{
		rules:     make(map[string]*Rule),
		enabled:   true,
		events:    make([]AttackEvent, 0),
		maxEvents: 10000, // 最多保存10000个事件
		log: logrus.WithFields(logrus.Fields{
			"component": "waf_engine",
		}),
	}

	// 初始化默认规则
	engine.initDefaultRules()

	return engine
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

// CheckRequest 检查请求
func (e *Engine) CheckRequest(r *http.Request) (*AttackEvent, bool) {
	if !e.enabled {
		return nil, false
	}

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	// 获取请求数据
	url := r.URL.String()
	method := r.Method
	clientIP := e.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// 检查URL参数
	if event := e.checkURLParams(r, clientIP, userAgent, url, method); event != nil {
		return event, event.Blocked
	}

	// 检查请求头
	if event := e.checkHeaders(r, clientIP, userAgent, url, method); event != nil {
		return event, event.Blocked
	}

	// 检查请求体
	if event := e.checkBody(r, clientIP, userAgent, url, method); event != nil {
		return event, event.Blocked
	}

	return nil, false
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
			if values, err := url.ParseQuery(payload); err == nil {
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

			e.addEvent(event)

			e.log.Warnf("WAF检测到攻击: %s from %s, 规则: %s, 动作: %s",
				rule.Type, clientIP, rule.Name, rule.Action)

			return event
		}
	}

	return nil
}

// addEvent 添加事件
func (e *Engine) addEvent(event *AttackEvent) {
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
