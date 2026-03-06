package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AdvancedEngine 高级WAF引擎
type AdvancedEngine struct {
	*Engine // 嵌入基础引擎

	// 高级规则
	advancedRules   map[string]*AdvancedRule
	rulesByPriority []*AdvancedRule

	// 规则组
	ruleGroups map[string]*RuleGroup

	// 自定义动作处理器
	actionHandlers map[string]ActionHandler

	// 性能统计
	stats *EngineStats

	mutex sync.RWMutex
}

// AdvancedRule 高级WAF规则
type AdvancedRule struct {
	*Rule // 嵌入基础规则

	// 高级属性
	Priority   int             `json:"priority"`   // 优先级，数字越小优先级越高
	Conditions []RuleCondition `json:"conditions"` // 多维度条件
	Actions    []RuleAction    `json:"actions"`    // 多个动作
	Variables  []string        `json:"variables"`  // 检查的变量列表
	Tags       []string        `json:"tags"`       // 规则标签
	Severity   string          `json:"severity"`   // 严重程度: low, medium, high, critical
	Category   string          `json:"category"`   // 规则分类
	References []string        `json:"references"` // 参考链接

	// 规则状态
	HitCount int64     `json:"hit_count"` // 命中次数
	LastHit  time.Time `json:"last_hit"`  // 最后命中时间

	// 性能优化
	CompiledRegex *regexp.Regexp `json:"-"`
	FastMatch     string         `json:"fast_match"` // 快速匹配字符串
}

// RuleCondition 规则条件
type RuleCondition struct {
	Variable  string   `json:"variable"`  // 变量名: REQUEST_URI, REQUEST_BODY, REQUEST_HEADERS等
	Field     string   `json:"field"`     // 具体字段名（如header名）
	Operator  string   `json:"operator"`  // 操作符: equals, contains, regex, gt, lt等
	Value     string   `json:"value"`     // 匹配值
	Transform []string `json:"transform"` // 转换函数: lowercase, urldecode等
	Negate    bool     `json:"negate"`    // 是否取反
}

// RuleAction 规则动作
type RuleAction struct {
	Type       string            `json:"type"`       // 动作类型: block, allow, log, redirect等
	Parameters map[string]string `json:"parameters"` // 动作参数
	Message    string            `json:"message"`    // 自定义消息
}

// RuleGroup 规则组
type RuleGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	RuleIDs     []string `json:"rule_ids"`
	Enabled     bool     `json:"enabled"`
}

// ActionHandler 动作处理器接口
type ActionHandler interface {
	Handle(action RuleAction, event *AttackEvent, w http.ResponseWriter, r *http.Request) error
	GetName() string
}

// EngineStats 引擎统计信息
type EngineStats struct {
	RequestsProcessed int64            `json:"requests_processed"`
	RulesEvaluated    int64            `json:"rules_evaluated"`
	AttacksBlocked    int64            `json:"attacks_blocked"`
	AttacksLogged     int64            `json:"attacks_logged"`
	AverageLatency    time.Duration    `json:"average_latency"`
	RuleHitStats      map[string]int64 `json:"rule_hit_stats"`
	mutex             sync.RWMutex
}

// NewAdvancedEngine 创建高级WAF引擎
func NewAdvancedEngine(rateLimitConfig *WAFRateLimitConfig, multiDimConfig *MultiDimBlockConfig, enabled bool) *AdvancedEngine {
	baseEngine := NewEngine(rateLimitConfig, multiDimConfig, enabled)

	engine := &AdvancedEngine{
		Engine:          baseEngine,
		advancedRules:   make(map[string]*AdvancedRule),
		rulesByPriority: make([]*AdvancedRule, 0),
		ruleGroups:      make(map[string]*RuleGroup),
		actionHandlers:  make(map[string]ActionHandler),
		stats: &EngineStats{
			RuleHitStats: make(map[string]int64),
		},
	}

	// 注册默认动作处理器
	engine.registerDefaultActionHandlers()

	// 初始化高级规则
	engine.initAdvancedRules()

	return engine
}

// registerDefaultActionHandlers 注册默认动作处理器
func (e *AdvancedEngine) registerDefaultActionHandlers() {
	e.actionHandlers["block"] = &BlockActionHandler{}
	e.actionHandlers["allow"] = &AllowActionHandler{}
	e.actionHandlers["log"] = &LogActionHandler{}
	e.actionHandlers["redirect"] = &RedirectActionHandler{}
	e.actionHandlers["rate_limit"] = &RateLimitActionHandler{}
	e.actionHandlers["captcha"] = &CaptchaActionHandler{}
}

// initAdvancedRules 初始化高级规则
func (e *AdvancedEngine) initAdvancedRules() {
	// SQL注入高级规则 - 修复 ReDoS 漏洞：使用原子组或更具体的模式，避免嵌套量词
	e.AddAdvancedRule(&AdvancedRule{
		Rule: &Rule{
			ID:          "advanced_sql_001",
			Name:        "高级SQL注入检测",
			Type:        RuleTypeSQLInjection,
			Enabled:     true,
			Description: "检测复杂的SQL注入攻击模式",
			CreatedAt:   time.Now(),
		},
		Priority: 100,
		Conditions: []RuleCondition{
			{
				Variable: "REQUEST_BODY",
				Operator: "regex",
				// 修复: 使用更精确的模式，避免 .* 嵌套导致的 ReDoS
				Value: `(?i)\bunion\s+\w+\s+select|\bselect\s+\w+\s+from\b|\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b`,
			},
			{
				Variable: "REQUEST_URI",
				Operator: "regex",
				// 修复: 使用更精确的模式
				Value: `(?i)\bunion\s+\w+\s+select|\bselect\s+\w+\s+from\b`,
			},
		},
		Actions: []RuleAction{
			{
				Type:    "block",
				Message: "检测到SQL注入攻击",
			},
			{
				Type: "log",
				Parameters: map[string]string{
					"level": "high",
				},
			},
		},
		Variables: []string{"REQUEST_BODY", "REQUEST_URI", "ARGS"},
		Tags:      []string{"sql", "injection", "database"},
		Severity:  "high",
		Category:  "injection",
	})

	// XSS高级规则 - 修复 ReDoS 漏洞：使用更精确的字符类
	e.AddAdvancedRule(&AdvancedRule{
		Rule: &Rule{
			ID:          "advanced_xss_001",
			Name:        "高级XSS检测",
			Type:        RuleTypeXSS,
			Enabled:     true,
			Description: "检测跨站脚本攻击",
			CreatedAt:   time.Now(),
		},
		Priority: 200,
		Conditions: []RuleCondition{
			{
				Variable:  "ARGS",
				Operator:  "regex",
				// 修复: 使用更精确的模式，避免 \w+ 后面跟量词导致的 ReDoS
				Value:     `(?i)<script[^>]*>|javascript:|on[a-z]+\s*=|<(iframe|object|embed)`,
				Transform: []string{"urldecode", "htmldecode"},
			},
		},
		Actions: []RuleAction{
			{
				Type:    "block",
				Message: "检测到XSS攻击",
			},
		},
		Variables: []string{"ARGS", "REQUEST_BODY", "REQUEST_HEADERS"},
		Tags:      []string{"xss", "script", "client-side"},
		Severity:  "medium",
		Category:  "xss",
	})

	// 路径遍历高级规则
	e.AddAdvancedRule(&AdvancedRule{
		Rule: &Rule{
			ID:          "advanced_path_001",
			Name:        "高级路径遍历检测",
			Type:        RuleTypePathTraversal,
			Enabled:     true,
			Description: "检测目录遍历攻击",
			CreatedAt:   time.Now(),
		},
		Priority: 300,
		Conditions: []RuleCondition{
			{
				Variable:  "REQUEST_URI",
				Operator:  "regex",
				Value:     `(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)`,
				Transform: []string{"urldecode"},
			},
		},
		Actions: []RuleAction{
			{
				Type:    "block",
				Message: "检测到路径遍历攻击",
			},
		},
		Variables: []string{"REQUEST_URI", "ARGS"},
		Tags:      []string{"path", "traversal", "file"},
		Severity:  "high",
		Category:  "traversal",
	})

	e.log.Infof("已初始化 %d 个高级WAF规则", len(e.advancedRules))
	e.sortRulesByPriority()
}

// AddAdvancedRule 添加高级规则
func (e *AdvancedEngine) AddAdvancedRule(rule *AdvancedRule) error {
	// 编译正则表达式
	for _, condition := range rule.Conditions {
		if condition.Operator == "regex" {
			regex, err := regexp.Compile(condition.Value)
			if err != nil {
				return fmt.Errorf("编译正则表达式失败: %w", err)
			}
			rule.CompiledRegex = regex
		}
	}

	// 设置快速匹配字符串
	if rule.FastMatch == "" && len(rule.Conditions) > 0 {
		rule.FastMatch = extractFastMatchString(rule.Conditions[0].Value)
	}

	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.advancedRules[rule.ID] = rule
	e.sortRulesByPriority()

	return nil
}

// @Todo 待集成
// CheckRequestAdvanced 高级请求检查（向后兼容）
func (e *AdvancedEngine) CheckRequestAdvanced(r *http.Request) ([]*AttackEvent, bool) {
	return e.CheckRequestAdvancedWithTLS(r, "")
}

// CheckRequestAdvancedWithTLS 高级请求检查（带 TLS 指纹）
func (e *AdvancedEngine) CheckRequestAdvancedWithTLS(r *http.Request, tlsFingerprint string) ([]*AttackEvent, bool) {
	if !e.enabled {
		return nil, false
	}

	startTime := time.Now()
	defer func() {
		e.updateStats(time.Since(startTime))
	}()

	var events []*AttackEvent
	blocked := false

	// 首先使用基础引擎检查（包含敏感文件和扫描工具检测，带 TLS 指纹）
	if baseEvent, baseBlocked := e.Engine.CheckRequestWithTLS(r, tlsFingerprint); baseEvent != nil {
		events = append(events, baseEvent)
		blocked = baseBlocked
		// 如果基础引擎已经阻止，直接返回
		if blocked {
			e.stats.mutex.Lock()
			e.stats.AttacksBlocked++
			e.stats.mutex.Unlock()
			return events, blocked
		}
	}

	e.mutex.RLock()
	rules := make([]*AdvancedRule, len(e.rulesByPriority))
	copy(rules, e.rulesByPriority)
	e.mutex.RUnlock()

	// 提取请求变量
	variables := e.extractVariables(r)

	// 按优先级顺序检查规则
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		e.stats.mutex.Lock()
		e.stats.RulesEvaluated++
		e.stats.mutex.Unlock()

		// 快速匹配预筛选
		if rule.FastMatch != "" {
			found := false
			for _, value := range variables {
				if strings.Contains(strings.ToLower(value), strings.ToLower(rule.FastMatch)) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// 检查规则条件
		if e.matchAdvancedRule(rule, variables, r) {
			event := e.createAdvancedAttackEvent(rule, r)
			events = append(events, event)

			// 更新规则统计
			e.mutex.Lock()
			rule.HitCount++
			rule.LastHit = time.Now()
			e.mutex.Unlock()

			e.stats.mutex.Lock()
			e.stats.RuleHitStats[rule.ID]++
			e.stats.mutex.Unlock()

			// 执行动作
			hasBlockAction := e.executeActions(rule, event, nil, r)
			if hasBlockAction {
				blocked = true
			}

			// 如果是阻止动作，停止后续规则检查
			if hasBlockAction {
				break
			}
		}
	}

	e.stats.mutex.Lock()
	e.stats.RequestsProcessed++
	if blocked {
		e.stats.AttacksBlocked++
	} else if len(events) > 0 {
		e.stats.AttacksLogged++
	}
	e.stats.mutex.Unlock()

	return events, blocked
}

// matchAdvancedRule 匹配高级规则
func (e *AdvancedEngine) matchAdvancedRule(rule *AdvancedRule, variables map[string]string, r *http.Request) bool {
	if len(rule.Conditions) == 0 {
		return false
	}

	// 所有条件都必须匹配（AND逻辑）
	for _, condition := range rule.Conditions {
		if !e.matchCondition(condition, variables, r) {
			return false
		}
	}

	return true
}

// matchCondition 匹配单个条件
func (e *AdvancedEngine) matchCondition(condition RuleCondition, variables map[string]string, r *http.Request) bool {
	// 获取变量值
	value := e.getVariableValue(condition.Variable, condition.Field, variables, r)
	if value == "" {
		return false
	}

	// 应用转换函数
	transformedValue := e.applyTransforms(value, condition.Transform)

	// 执行匹配操作
	matched := e.executeOperator(condition.Operator, transformedValue, condition.Value)

	// 应用取反
	if condition.Negate {
		matched = !matched
	}

	return matched
}

// getVariableValue 获取变量值
func (e *AdvancedEngine) getVariableValue(variable, field string, variables map[string]string, r *http.Request) string {
	switch variable {
	case "REQUEST_URI":
		return r.URL.RequestURI()
	case "REQUEST_METHOD":
		return r.Method
	case "REQUEST_BODY":
		return variables["REQUEST_BODY"]
	case "ARGS":
		return variables["ARGS"]
	case "REQUEST_HEADERS":
		if field != "" {
			return r.Header.Get(field)
		}
		return variables["REQUEST_HEADERS"]
	case "REMOTE_ADDR":
		return r.RemoteAddr
	case "USER_AGENT":
		return r.Header.Get("User-Agent")
	default:
		return variables[variable]
	}
}

// applyTransforms 应用转换函数
func (e *AdvancedEngine) applyTransforms(value string, transforms []string) string {
	result := value

	for _, transform := range transforms {
		switch transform {
		case "lowercase":
			result = strings.ToLower(result)
		case "uppercase":
			result = strings.ToUpper(result)
		case "urldecode":
			if decoded, err := strconv.Unquote(`"` + strings.ReplaceAll(result, `"`, `\"`) + `"`); err == nil {
				result = decoded
			}
		case "htmldecode":
			result = strings.ReplaceAll(result, "&lt;", "<")
			result = strings.ReplaceAll(result, "&gt;", ">")
			result = strings.ReplaceAll(result, "&amp;", "&")
			result = strings.ReplaceAll(result, "&quot;", "\"")
		case "trim":
			result = strings.TrimSpace(result)
		}
	}

	return result
}

// executeOperator 执行操作符
func (e *AdvancedEngine) executeOperator(operator, value, pattern string) bool {
	switch operator {
	case "equals":
		return value == pattern
	case "contains":
		return strings.Contains(value, pattern)
	case "startswith":
		return strings.HasPrefix(value, pattern)
	case "endswith":
		return strings.HasSuffix(value, pattern)
	case "regex":
		if regex, err := regexp.Compile(pattern); err == nil {
			return regex.MatchString(value)
		}
		return false
	case "gt":
		if valueInt, err := strconv.Atoi(value); err == nil {
			if patternInt, err := strconv.Atoi(pattern); err == nil {
				return valueInt > patternInt
			}
		}
		return false
	case "lt":
		if valueInt, err := strconv.Atoi(value); err == nil {
			if patternInt, err := strconv.Atoi(pattern); err == nil {
				return valueInt < patternInt
			}
		}
		return false
	case "length_gt":
		if patternInt, err := strconv.Atoi(pattern); err == nil {
			return len(value) > patternInt
		}
		return false
	case "length_lt":
		if patternInt, err := strconv.Atoi(pattern); err == nil {
			return len(value) < patternInt
		}
		return false
	default:
		return false
	}
}

// extractVariables 提取请求变量
func (e *AdvancedEngine) extractVariables(r *http.Request) map[string]string {
	variables := make(map[string]string)

	// 请求体 - 重要：读取后需要恢复，否则下游处理器无法读取
	if r.Body != nil {
		if bodyBytes, err := io.ReadAll(r.Body); err == nil {
			variables["REQUEST_BODY"] = string(bodyBytes)
			// 恢复请求体供下游处理器使用
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	// URL参数
	args := r.URL.Query().Encode()
	variables["ARGS"] = args

	// 请求头
	headerBytes, _ := json.Marshal(r.Header)
	variables["REQUEST_HEADERS"] = string(headerBytes)

	return variables
}

// createAdvancedAttackEvent 创建高级攻击事件
func (e *AdvancedEngine) createAdvancedAttackEvent(rule *AdvancedRule, r *http.Request) *AttackEvent {
	return &AttackEvent{
		ID:        e.generateEventID(),
		ClientIP:  e.getClientIP(r),
		UserAgent: r.Header.Get("User-Agent"),
		URL:       r.URL.String(),
		Method:    r.Method,
		RuleID:    rule.ID,
		RuleName:  rule.Name,
		RuleType:  rule.Type,
		Payload:   r.URL.RawQuery,
		Timestamp: time.Now(),
	}
}

// executeActions 执行规则动作
func (e *AdvancedEngine) executeActions(rule *AdvancedRule, event *AttackEvent, w http.ResponseWriter, r *http.Request) bool {
	hasBlockAction := false

	for _, action := range rule.Actions {
		if handler, exists := e.actionHandlers[action.Type]; exists {
			if err := handler.Handle(action, event, w, r); err != nil {
				e.log.Errorf("执行动作 %s 失败: %v", action.Type, err)
			}

			if action.Type == "block" {
				hasBlockAction = true
				event.Blocked = true
			}
		}
	}

	return hasBlockAction
}

// sortRulesByPriority 按优先级排序规则
func (e *AdvancedEngine) sortRulesByPriority() {
	e.rulesByPriority = make([]*AdvancedRule, 0, len(e.advancedRules))
	for _, rule := range e.advancedRules {
		e.rulesByPriority = append(e.rulesByPriority, rule)
	}

	sort.Slice(e.rulesByPriority, func(i, j int) bool {
		return e.rulesByPriority[i].Priority < e.rulesByPriority[j].Priority
	})
}

// updateStats 更新统计信息
func (e *AdvancedEngine) updateStats(latency time.Duration) {
	e.stats.mutex.Lock()
	defer e.stats.mutex.Unlock()

	// 更新平均延迟（简单移动平均）
	if e.stats.RequestsProcessed == 0 {
		e.stats.AverageLatency = latency
	} else {
		e.stats.AverageLatency = (e.stats.AverageLatency + latency) / 2
	}
}

// extractFastMatchString 提取快速匹配字符串
func extractFastMatchString(pattern string) string {
	// 从正则表达式中提取固定字符串部分
	// 这是一个简化实现，实际可以更复杂
	cleaned := strings.ReplaceAll(pattern, "(?i)", "")
	cleaned = strings.ReplaceAll(cleaned, ".*", "")
	cleaned = strings.ReplaceAll(cleaned, ".+", "")
	cleaned = strings.ReplaceAll(cleaned, "\\", "")

	if len(cleaned) > 3 {
		return cleaned[:3]
	}
	return cleaned
}

// GetAdvancedStats 获取高级统计信息
func (e *AdvancedEngine) GetAdvancedStats() *EngineStats {
	e.stats.mutex.RLock()
	defer e.stats.mutex.RUnlock()

	// 创建副本返回
	stats := &EngineStats{
		RequestsProcessed: e.stats.RequestsProcessed,
		RulesEvaluated:    e.stats.RulesEvaluated,
		AttacksBlocked:    e.stats.AttacksBlocked,
		AttacksLogged:     e.stats.AttacksLogged,
		AverageLatency:    e.stats.AverageLatency,
		RuleHitStats:      make(map[string]int64),
	}

	for k, v := range e.stats.RuleHitStats {
		stats.RuleHitStats[k] = v
	}

	return stats
}
