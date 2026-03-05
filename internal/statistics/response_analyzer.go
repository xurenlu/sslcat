package statistics

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// ResponsePattern 响应解析模式
type ResponsePattern struct {
	// 成功值列表：以下值表示成功
	SuccessValues []interface{} `json:"success_values"`
	// 字段路径：支持嵌套，如 "data.status" 或 "errcode"
	FieldPath string `json:"field_path"`
	// 是否启用：默认启用
	Enabled bool `json:"enabled"`
}

// ResponseAnalyzer 响应分析器
type ResponseAnalyzer struct {
	// 内置常见模式
	patterns map[string][]ResponsePattern
	// 学习到的模式（API路径 -> 模式）
	learnedPatterns map[string][]ResponsePattern
	// 模式学习数据（API路径 -> 字段统计）
	patternLearning map[string]*patternStats
	// 失败检测器（error 字段、短响应、Isolation Forest）
	failureDetector *FailureDetector
	// 值分布学习器：学习 code/status 等字段的成功/失败值（替代写死的 SuccessValues）
	valueLearner *ValueLearner
	mutex        sync.RWMutex
}

// patternStats 模式统计数据
type patternStats struct {
	fieldCounts map[string]int    // 字段出现次数
	valueTypes  map[string]string // 字段值类型
	sampleCount int
}

// NewResponseAnalyzer 创建响应分析器
func NewResponseAnalyzer() *ResponseAnalyzer {
	analyzer := &ResponseAnalyzer{
		patterns:        make(map[string][]ResponsePattern),
		learnedPatterns: make(map[string][]ResponsePattern),
		patternLearning: make(map[string]*patternStats),
		failureDetector: NewFailureDetector(),
		valueLearner:    NewValueLearner(),
	}

	// 初始化内置常见模式
	analyzer.initBuiltinPatterns()

	return analyzer
}

// initBuiltinPatterns 初始化内置常见API响应模式
func (ra *ResponseAnalyzer) initBuiltinPatterns() {
	// 模式1: {"status": 0/1} 或 {"status": "success"/"error"}
	ra.patterns["status_int"] = []ResponsePattern{
		{
			FieldPath:    "status",
			SuccessValues: []interface{}{0, 1, "0", "1", "success", "ok", "true"},
			Enabled:      true,
		},
	}

	// 模式2: {"code": 0/200/2000} 等（很多 API 用 200 表示成功，非 HTTP 状态码）
	ra.patterns["code_int"] = []ResponsePattern{
		{
			FieldPath:     "code",
			SuccessValues: []interface{}{0, 200, 2000, 1000, 10000, "0", "200", "2000"},
			Enabled:       true,
		},
	}

	// 模式3: {"errcode": 0} (微信风格)
	ra.patterns["errcode_int"] = []ResponsePattern{
		{
			FieldPath:    "errcode",
			SuccessValues: []interface{}{0, "0"},
			Enabled:      true,
		},
	}

	// 模式4: {"error": null/""} 或 {"error": false}（非空/true 表示失败）
	ra.patterns["error_field"] = []ResponsePattern{
		{
			FieldPath:     "error",
			SuccessValues: []interface{}{nil, "", false, "null", "false"},
			Enabled:       true,
		},
	}

	// 模式4b: {"errmsg": ""} 或 {"message": "ok"}（微信/常见风格）
	ra.patterns["errmsg_field"] = []ResponsePattern{
		{
			FieldPath:     "errmsg",
			SuccessValues: []interface{}{"", "ok", "success"},
			Enabled:       true,
		},
	}

	// 模式5: {"success": true}
	ra.patterns["success_bool"] = []ResponsePattern{
		{
			FieldPath:    "success",
			SuccessValues: []interface{}{true, "true", "1", 1},
			Enabled:      true,
		},
	}

	// 模式6: 嵌套结构 {"data": {"status": ...}}
	ra.patterns["nested_status"] = []ResponsePattern{
		{
			FieldPath:    "data.status",
			SuccessValues: []interface{}{0, 1, "0", "1", "success", "ok"},
			Enabled:      true,
		},
	}

	// 模式7: {"result": {"code": ...}}
	ra.patterns["nested_code"] = []ResponsePattern{
		{
			FieldPath:    "result.code",
			SuccessValues: []interface{}{0, 200, "0", "200"},
			Enabled:      true,
		},
	}

	// 模式8: {"response": {"status": ...}}
	ra.patterns["response_status"] = []ResponsePattern{
		{
			FieldPath:    "response.status",
			SuccessValues: []interface{}{"success", "ok", "true", true, 0, 1},
			Enabled:      true,
		},
	}
}

// AnalyzeResponse 分析响应，提取业务状态码
// host 为空时仅按 path 学习；否则按 host:pathPattern 学习，使不同域名的同 path 分开
func (ra *ResponseAnalyzer) AnalyzeResponse(resp *http.Response, body []byte, host, path string) (*BusinessStatus, error) {
	if len(body) == 0 {
		return nil, nil
	}

	// 二次学习：host + 归一化 path 为 pattern
	// log.17push.com + /api/v1/ingest -> log.17push.com:/api/v1/*
	pathPattern := BuildAPIPatternKey(host, path)

	// 检查是否是JSON响应
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		// 非JSON响应，尝试学习
		ra.learnFromResponse(pathPattern, body, false)
		return nil, nil
	}

	// 解析JSON
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		// JSON解析失败
		return nil, err
	}

	// 优先使用学习到的模式（按 pattern 查找）
	ra.mutex.RLock()
	learnedPatterns, hasLearned := ra.learnedPatterns[pathPattern]
	ra.mutex.RUnlock()

	statusCode := 200
	if resp != nil {
		statusCode = resp.StatusCode
	}

	if hasLearned && len(learnedPatterns) > 0 {
		// 使用学习到的模式
		for _, pattern := range learnedPatterns {
			if !pattern.Enabled {
				continue
			}
			if status := ra.tryPattern(data, pattern, pathPattern, statusCode); status != nil {
				return status, nil
			}
		}
	}

	// 使用内置模式
	for _, patterns := range ra.patterns {
		for _, pattern := range patterns {
			if !pattern.Enabled {
				continue
			}
			if status := ra.tryPattern(data, pattern, pathPattern, statusCode); status != nil {
				// 学习成功模式（按 pattern 存储）
				ra.learnPattern(pathPattern, pattern)
				return status, nil
			}
		}
	}

	// 没有匹配的模式，尝试学习新模式
	ra.learnFromResponse(pathPattern, body, true)

	// Fallback: 失败检测器（error 字段、短响应启发式、Isolation Forest）
	if ra.failureDetector != nil {
		if status := ra.failureDetector.DetectFailure(resp, body, pathPattern); status != nil {
			return status, nil
		}
	}

	return nil, nil
}

// tryPattern 尝试使用指定模式解析
func (ra *ResponseAnalyzer) tryPattern(data interface{}, pattern ResponsePattern, apiPath string, statusCode int) *BusinessStatus {
	value := ra.extractFieldValue(data, pattern.FieldPath)
	if value == nil {
		return nil
	}

	valueStr := ra.stringify(value)

	// 记录样本供 ValueLearner 学习（基于 HTTP 2xx vs 4xx/5xx 分布）
	if ra.valueLearner != nil {
		ra.valueLearner.Record(apiPath, pattern.FieldPath, valueStr, statusCode)
	}

	// 优先使用学习到的成功值，否则用内置 SuccessValues
	successValues := pattern.SuccessValues
	if ra.valueLearner != nil {
		if learned := ra.valueLearner.GetLearnedSuccessValues(apiPath, pattern.FieldPath); len(learned) > 0 {
			successValues = learned
		}
	}

	// 检查值是否在成功列表中
	for _, successVal := range successValues {
		if ra.compareValues(value, successVal) {
			return &BusinessStatus{
				IsSuccess: true,
				Code:      ra.convertToInt(value),
				Message:   valueStr,
				Source:    pattern.FieldPath,
			}
		}
	}

	// 值存在但不在成功列表，认为失败
	return &BusinessStatus{
		IsSuccess: false,
		Code:      ra.convertToInt(value),
		Message:   valueStr,
		Source:    pattern.FieldPath,
	}
}

// extractFieldValue 从嵌套结构中提取字段值
func (ra *ResponseAnalyzer) extractFieldValue(data interface{}, fieldPath string) interface{} {
	parts := strings.Split(fieldPath, ".")
	current := data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case []interface{}:
			// 如果是数组，尝试获取第一个元素
			if len(v) > 0 {
				if firstMap, ok := v[0].(map[string]interface{}); ok {
					current = firstMap[part]
				} else {
					return nil
				}
			} else {
				return nil
			}
		default:
			return nil
		}

		if current == nil {
			return nil
		}
	}

	return current
}

// compareValues 比较两个值是否相等
func (ra *ResponseAnalyzer) compareValues(a, b interface{}) bool {
	// 类型转换处理
	switch va := a.(type) {
	case int:
		if vb, ok := b.(int); ok {
			return va == vb
		}
		if vb, ok := b.(float64); ok {
			return float64(va) == vb
		}
		if vb, ok := b.(string); ok {
			return ra.stringify(va) == vb
		}
	case float64:
		if vb, ok := b.(int); ok {
			return va == float64(vb)
		}
		if vb, ok := b.(float64); ok {
			return va == vb
		}
		if vb, ok := b.(string); ok {
			return ra.stringify(va) == vb
		}
	case string:
		if vb, ok := b.(string); ok {
			return va == vb
		}
		if vb, ok := b.(int); ok {
			return va == ra.stringify(vb)
		}
		if vb, ok := b.(float64); ok {
			return va == ra.stringify(vb)
		}
	case bool:
		if vb, ok := b.(bool); ok {
			return va == vb
		}
		if vb, ok := b.(string); ok {
			return ra.stringify(va) == vb
		}
	}
	return false
}

// convertToInt 转换为整数
func (ra *ResponseAnalyzer) convertToInt(value interface{}) int {
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		// 尝试解析字符串
		var f float64
		if err := json.Unmarshal([]byte(v), &f); err == nil {
			return int(f)
		}
		return 0
	case bool:
		if v {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// stringify 转换为字符串
func (ra *ResponseAnalyzer) stringify(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int, float64, bool:
		jsonBytes, _ := json.Marshal(value)
		return string(jsonBytes)
	case nil:
		return ""
	default:
		return ""
	}
}

// learnFromResponse 从响应中学习模式
func (ra *ResponseAnalyzer) learnFromResponse(apiPath string, body []byte, isJSON bool) {
	if !isJSON {
		return
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}

	ra.mutex.Lock()
	defer ra.mutex.Unlock()

	// 初始化统计数据
	if ra.patternLearning[apiPath] == nil {
		ra.patternLearning[apiPath] = &patternStats{
			fieldCounts: make(map[string]int),
			valueTypes:  make(map[string]string),
		}
	}

	stats := ra.patternLearning[apiPath]
	stats.sampleCount++

	// 递归分析JSON结构，收集常见字段
	ra.analyzeStructure(data, "", stats)

	// 如果样本足够，尝试生成新模式
	if stats.sampleCount >= 5 {
		ra.generateLearnedPattern(apiPath, stats)
	}
}

// analyzeStructure 递归分析JSON结构
func (ra *ResponseAnalyzer) analyzeStructure(data interface{}, prefix string, stats *patternStats) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fieldPath := key
			if prefix != "" {
				fieldPath = prefix + "." + key
			}

			// 记录字段出现
			stats.fieldCounts[fieldPath]++

			// 记录值类型
			var valueType string
			switch value.(type) {
			case int, float64:
				valueType = "number"
			case string:
				valueType = "string"
			case bool:
				valueType = "boolean"
			case map[string]interface{}, []interface{}:
				valueType = "object"
			default:
				valueType = "unknown"
			}
			stats.valueTypes[fieldPath] = valueType

			// 递归分析嵌套结构
			if nested, ok := value.(map[string]interface{}); ok {
				ra.analyzeStructure(nested, fieldPath, stats)
			}
		}
	case []interface{}:
		if len(v) > 0 {
			if first, ok := v[0].(map[string]interface{}); ok {
				ra.analyzeStructure(first, prefix, stats)
			}
		}
	}
}

// generateLearnedPattern 生成学习到的模式
func (ra *ResponseAnalyzer) generateLearnedPattern(apiPath string, stats *patternStats) {
	// 查找高频字段（可能是状态码字段）
	candidateFields := []string{}
	minCount := stats.sampleCount / 2 // 至少出现50%的时间

	for field, count := range stats.fieldCounts {
		if count >= minCount {
			// 检查是否是常见的状态字段名
			fieldName := field
			if idx := strings.LastIndex(field, "."); idx >= 0 {
				fieldName = field[idx+1:]
			}

			if ra.isStatusField(fieldName) {
				candidateFields = append(candidateFields, field)
			}
		}
	}

	if len(candidateFields) > 0 {
		// 选择第一个候选字段
		field := candidateFields[0]
		pattern := ResponsePattern{
			FieldPath:     field,
			SuccessValues: []interface{}{0, 1, "0", "1", "success", "ok", "true"},
			Enabled:       true,
		}

		// 避免重复
		for _, p := range ra.learnedPatterns[apiPath] {
			if p.FieldPath == field {
				return
			}
		}

		ra.learnedPatterns[apiPath] = append(ra.learnedPatterns[apiPath], pattern)
	}
}

// isStatusField 判断是否是状态字段
func (ra *ResponseAnalyzer) isStatusField(fieldName string) bool {
	lower := strings.ToLower(fieldName)
	statusFields := []string{"status", "code", "errcode", "error", "success", "result", "state"}
	for _, sf := range statusFields {
		if strings.Contains(lower, sf) {
			return true
		}
	}
	return false
}

// learnPattern 学习成功模式
func (ra *ResponseAnalyzer) learnPattern(apiPath string, pattern ResponsePattern) {
	ra.mutex.Lock()
	defer ra.mutex.Unlock()

	// 避免重复
	for _, p := range ra.learnedPatterns[apiPath] {
		if p.FieldPath == pattern.FieldPath {
			return
		}
	}

	ra.learnedPatterns[apiPath] = append(ra.learnedPatterns[apiPath], pattern)
}

// GetLearnedPatterns 获取学习到的模式
func (ra *ResponseAnalyzer) GetLearnedPatterns(apiPath string) []ResponsePattern {
	ra.mutex.RLock()
	defer ra.mutex.RUnlock()

	patterns, exists := ra.learnedPatterns[apiPath]
	if !exists {
		return []ResponsePattern{}
	}

	// 返回副本
	result := make([]ResponsePattern, len(patterns))
	copy(result, patterns)
	return result
}

// CopyResponseBody 复制响应体（用于分析）
func CopyResponseBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil || resp.Body == http.NoBody {
		return nil, nil
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 重新设置Body，以便后续读取
	resp.Body = io.NopCloser(bytes.NewReader(body))

	return body, nil
}

// IsAPIRequest 判断是否是API请求
func IsAPIRequest(r *http.Request) bool {
	// 检查Content-Type
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") ||
	   strings.Contains(contentType, "application/xml") ||
	   strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return true
	}

	// 检查Accept
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") ||
	   strings.Contains(accept, "application/xml") {
		return true
	}

	// 检查路径模式（常见API路径模式）
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/") ||
	   strings.HasPrefix(path, "/v1/") ||
	   strings.HasPrefix(path, "/v2/") ||
	   strings.Contains(path, "/api/") {
		return true
	}

	// 检查扩展名
	if strings.HasSuffix(path, ".json") ||
	   strings.HasSuffix(path, ".xml") {
		return true
	}

	// 检查查询参数（常见API参数）
	query := r.URL.Query()
	if query.Get("callback") != "" || // JSONP
	   query.Get("jsonp") != "" ||
	   query.Get("_format") == "json" {
		return true
	}

	return false
}

// IsJSONResponse 判断响应是否为 JSON 类型（用于自动识别代理转发的 API）
func IsJSONResponse(resp *http.Response) bool {
	if resp == nil || resp.Header == nil {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "application/json")
}
