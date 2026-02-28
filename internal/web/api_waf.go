package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/waf"
)

// WAFStatsResponse WAF统计响应
type WAFStatsResponse struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Data    map[string]interface{} `json:"data,omitempty"`
}

// WAFRulesResponse WAF规则列表响应
type WAFRulesResponse struct {
	Success bool                     `json:"success"`
	Message string                   `json:"message,omitempty"`
	Rules   []map[string]interface{} `json:"rules,omitempty"`
}

// WAFEventsResponse WAF事件列表响应
type WAFEventsResponse struct {
	Success bool                     `json:"success"`
	Message string                   `json:"message,omitempty"`
	Events  []map[string]interface{} `json:"events,omitempty"`
	Total   int                      `json:"total,omitempty"`
}

// WAFConfigRequest WAF配置请求
type WAFConfigRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// handleAPIWAFStats 获取WAF统计信息
func (s *Server) handleAPIWAFStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	// 获取WAF统计信息
	stats := s.wafEngine.Engine.GetStats()

	response := WAFStatsResponse{
		Success: true,
		Data:    stats,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF stats response")
	}
}

// handleAPIWAFRules 获取WAF规则列表
func (s *Server) handleAPIWAFRules(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	// 获取规则列表
	rules := s.wafEngine.Engine.GetRules()

	// 转换为JSON友好的格式
	var rulesList []map[string]interface{}
	for _, rule := range rules {
		rulesList = append(rulesList, map[string]interface{}{
			"id":          rule.ID,
			"name":        rule.Name,
			"type":        string(rule.Type),
			"pattern":     rule.Pattern,
			"action":      string(rule.Action),
			"enabled":     rule.Enabled,
			"description": rule.Description,
			"created_at":  rule.CreatedAt,
		})
	}

	response := WAFRulesResponse{
		Success: true,
		Rules:   rulesList,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF rules response")
	}
}

// handleAPIWAFEvents 获取WAF攻击事件
func (s *Server) handleAPIWAFEvents(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	// 获取limit参数
	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	// 获取事件列表
	events := s.wafEngine.Engine.GetEvents(limit)

	// 转换为JSON友好的格式
	var eventsList []map[string]interface{}
	for _, event := range events {
		eventsList = append(eventsList, map[string]interface{}{
			"id":         event.ID,
			"client_ip":  event.ClientIP,
			"user_agent": event.UserAgent,
			"url":        event.URL,
			"method":     event.Method,
			"rule_id":    event.RuleID,
			"rule_name":  event.RuleName,
			"rule_type":  string(event.RuleType),
			"action":     string(event.Action),
			"payload":    event.Payload,
			"timestamp":  event.Timestamp,
			"blocked":    event.Blocked,
		})
	}

	response := WAFEventsResponse{
		Success: true,
		Events:  eventsList,
		Total:   len(eventsList),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF events response")
	}
}

// handleAPIWAFConfig 更新WAF配置
func (s *Server) handleAPIWAFConfig(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	var req WAFConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// 更新WAF启用状态
	if req.Enabled != nil {
		s.wafEngine.Engine.SetEnabled(*req.Enabled)
		
		// 同时更新配置文件中的设置
		s.config.Security.EnableWAF = *req.Enabled
		
		// 保存配置（使用当前配置文件路径）
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			s.log.WithFields(logrus.Fields{
				"error": err,
			}).Error("Failed to save WAF config")
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to save configuration")
			return
		}

		s.log.WithFields(logrus.Fields{
			"enabled": *req.Enabled,
		}).Info("WAF configuration updated")
	}

	// 返回更新后的统计信息
	stats := s.wafEngine.Engine.GetStats()

	response := WAFStatsResponse{
		Success: true,
		Message: "WAF configuration updated successfully",
		Data:    stats,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF config response")
	}
}

// handleAPIWAFBlockedList 获取多维度封禁列表
func (s *Server) handleAPIWAFBlockedList(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	// 获取维度参数
	dimension := r.URL.Query().Get("dimension")
	
	var records interface{}
	switch dimension {
	case "ip":
		records = s.wafEngine.Engine.GetMultiDimBlockedList("ip")
	case "tls":
		records = s.wafEngine.Engine.GetMultiDimBlockedList("tls_fingerprint")
	case "subnet":
		records = s.wafEngine.Engine.GetMultiDimBlockedList("ip_subnet")
	case "":
		// 返回所有维度
		records = s.wafEngine.Engine.GetMultiDimBlockedList("")
	default:
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid dimension parameter")
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data":    records,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF blocked list response")
	}
}

// handleAPIWAFUnblock 解除多维度封禁
func (s *Server) handleAPIWAFUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) { // 需要写权限
		return
	}

	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	var req struct {
		Dimension string `json:"dimension"`
		Value     string `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	if req.Dimension == "" || req.Value == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Missing dimension or value")
		return
	}

	// 解除封禁（转换维度类型）
	s.wafEngine.Engine.UnblockMultiDim(waf.BlockDimension(req.Dimension), req.Value)

	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Successfully unblocked %s: %s", req.Dimension, req.Value),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF unblock response")
	}
}

// handleAPIWAFSubnetStats 获取 IP 段统计
func (s *Server) handleAPIWAFSubnetStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	stats := s.wafEngine.Engine.GetSubnetStats()

	response := map[string]interface{}{
		"success": true,
		"data":    stats,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF subnet stats response")
	}
}

// handleAPIWAFTLSStats 获取 TLS 指纹统计
func (s *Server) handleAPIWAFTLSStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	stats := s.wafEngine.Engine.GetTLSStats()

	response := map[string]interface{}{
		"success": true,
		"data":    stats,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF TLS stats response")
	}
}

// WAFRuleCreateRequest 创建WAF规则请求
type WAFRuleCreateRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Pattern     string   `json:"pattern"`
	Action      string   `json:"action"`
	Enabled     bool     `json:"enabled"`
	Description string   `json:"description"`
	Priority    int      `json:"priority"`
	Conditions  []map[string]interface{} `json:"conditions,omitempty"`
	Actions     []map[string]interface{} `json:"actions,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Category    string   `json:"category,omitempty"`
}

// WAFRuleUpdateRequest 更新WAF规则请求
type WAFRuleUpdateRequest struct {
	Pattern     string   `json:"pattern,omitempty"`
	Action      string   `json:"action,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	Description string   `json:"description,omitempty"`
	Priority    int      `json:"priority,omitempty"`
}

// WAFRuleTestRequest 测试WAF规则请求
type WAFRuleTestRequest struct {
	RuleID      string `json:"rule_id,omitempty"`
	Rule        WAFRuleCreateRequest `json:"rule,omitempty"`
	TestURL     string            `json:"test_url"`
	TestMethod  string            `json:"test_method"`
	TestHeaders map[string]string `json:"test_headers,omitempty"`
	TestBody    string            `json:"test_body,omitempty"`
}

// WAFRuleTestResponse 测试WAF规则响应
type WAFRuleTestResponse struct {
	Success      bool        `json:"success"`
	Message      string      `json:"message,omitempty"`
	Matched      bool        `json:"matched"`
	Blocked      bool        `json:"blocked"`
	Action       string      `json:"action,omitempty"`
	RuleName     string      `json:"rule_name,omitempty"`
	MatchDetails  string      `json:"match_details,omitempty"`
}

// handleAPIWAFCreateRule 创建WAF规则
func (s *Server) handleAPIWAFCreateRule(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	var req WAFRuleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// 验证必填字段
	if req.Name == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Rule name is required")
		return
	}
	if req.Type == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Rule type is required")
		return
	}
	if req.Pattern == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Rule pattern is required")
		return
	}
	if req.Action == "" {
		req.Action = "block"
	}

	// 生成ID（如果未提供）
	if req.ID == "" {
		req.ID = fmt.Sprintf("custom_%d", time.Now().Unix())
	}

	// 创建规则
	rule := &waf.Rule{
		ID:          req.ID,
		Name:        req.Name,
		Type:        waf.RuleType(req.Type),
		Pattern:     req.Pattern,
		Action:      waf.Action(req.Action),
		Enabled:     req.Enabled,
		Description: req.Description,
		CreatedAt:   time.Now(),
	}

	// 添加规则
	if err := s.wafEngine.Engine.AddRule(rule); err != nil {
		s.log.WithError(err).Error("Failed to create WAF rule")
		s.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create rule: %v", err))
		return
	}

	s.log.WithFields(logrus.Fields{
		"rule_id": req.ID,
		"rule_name": req.Name,
	}).Info("WAF rule created")

	response := map[string]interface{}{
		"success": true,
		"message": "WAF rule created successfully",
		"rule": map[string]interface{}{
			"id":          rule.ID,
			"name":        rule.Name,
			"type":        string(rule.Type),
			"pattern":     rule.Pattern,
			"action":      string(rule.Action),
			"enabled":     rule.Enabled,
			"description": rule.Description,
			"created_at":  rule.CreatedAt,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF create rule response")
	}
}

// handleAPIWAFUpdateRule 更新WAF规则
func (s *Server) handleAPIWAFUpdateRule(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	// 从URL获取规则ID
	ruleID := r.URL.Query().Get("id")
	if ruleID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Rule ID is required")
		return
	}

	var req WAFRuleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// 获取现有规则
	rules := s.wafEngine.Engine.GetRules()
	existingRule, exists := rules[ruleID]
	if !exists {
		s.writeErrorResponse(w, http.StatusNotFound, "Rule not found")
		return
	}

	// 更新规则字段
	if req.Pattern != "" {
		existingRule.Pattern = req.Pattern
		// 重新编译正则表达式
		if err := s.wafEngine.Engine.AddRule(existingRule); err != nil {
			s.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to update rule: %v", err))
			return
		}
	}
	if req.Action != "" {
		existingRule.Action = waf.Action(req.Action)
	}
	if req.Enabled != nil {
		existingRule.Enabled = *req.Enabled
	}
	if req.Description != "" {
		existingRule.Description = req.Description
	}

	s.log.WithFields(logrus.Fields{
		"rule_id": ruleID,
	}).Info("WAF rule updated")

	response := map[string]interface{}{
		"success": true,
		"message": "WAF rule updated successfully",
		"rule": map[string]interface{}{
			"id":          existingRule.ID,
			"name":        existingRule.Name,
			"type":        string(existingRule.Type),
			"pattern":     existingRule.Pattern,
			"action":      string(existingRule.Action),
			"enabled":     existingRule.Enabled,
			"description": existingRule.Description,
			"created_at":  existingRule.CreatedAt,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF update rule response")
	}
}

// handleAPIWAFDeleteRule 删除WAF规则
func (s *Server) handleAPIWAFDeleteRule(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	// 从URL获取规则ID
	ruleID := r.URL.Query().Get("id")
	if ruleID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Rule ID is required")
		return
	}

	// 删除规则
	s.wafEngine.Engine.RemoveRule(ruleID)

	s.log.WithFields(logrus.Fields{
		"rule_id": ruleID,
	}).Info("WAF rule deleted")

	response := map[string]interface{}{
		"success": true,
		"message": "WAF rule deleted successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF delete rule response")
	}
}

// handleAPIWAFTestRule 测试WAF规则
func (s *Server) handleAPIWAFTestRule(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	var req WAFRuleTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
		return
	}

	// 构建测试请求
	testURL := req.TestURL
	if testURL == "" {
		testURL = "/test"
	}

	testMethod := req.TestMethod
	if testMethod == "" {
		testMethod = "GET"
	}

	// 创建HTTP请求
	testReq, err := http.NewRequest(testMethod, testURL, nil)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid test request: %v", err))
		return
	}

	// 设置测试头
	if req.TestHeaders != nil {
		for k, v := range req.TestHeaders {
			testReq.Header.Set(k, v)
		}
	}

	// 设置测试体
	if req.TestBody != "" {
		testReq.Body = io.NopCloser(strings.NewReader(req.TestBody))
	}

	// 如果指定了现有规则ID，使用现有规则测试
	var matchedRule *waf.Rule
	var blocked bool

	if req.RuleID != "" {
		// 测试现有规则
		rules := s.wafEngine.Engine.GetRules()
		if rule, exists := rules[req.RuleID]; exists {
			testReq, _ = http.NewRequest(testMethod, testURL, nil)
			if req.TestHeaders != nil {
				for k, v := range req.TestHeaders {
					testReq.Header.Set(k, v)
				}
			}

			// 创建临时引擎进行单规则测试
			tempEngine := waf.NewEngine(nil, nil)
			tempEngine.AddRule(rule)

			if _, isBlocked := tempEngine.CheckRequest(testReq); isBlocked {
				matchedRule = rule
				blocked = isBlocked
			}
		} else {
			s.writeErrorResponse(w, http.StatusNotFound, "Rule not found")
			return
		}
	} else if req.Rule.Pattern != "" {
		// 测试新规则
		testRule := &waf.Rule{
			ID:          "test_rule",
			Name:        req.Rule.Name,
			Type:        waf.RuleType(req.Rule.Type),
			Pattern:     req.Rule.Pattern,
			Action:      waf.Action(req.Rule.Action),
			Enabled:     true,
			Description: req.Rule.Description,
			CreatedAt:   time.Now(),
		}

		// 创建临时引擎进行测试
		tempEngine := waf.NewEngine(nil, nil)
		tempEngine.AddRule(testRule)

		if _, isBlocked := tempEngine.CheckRequest(testReq); isBlocked {
			matchedRule = testRule
			blocked = isBlocked
		}
	} else {
		s.writeErrorResponse(w, http.StatusBadRequest, "Either rule_id or rule must be specified")
		return
	}

	response := WAFRuleTestResponse{
		Success:     true,
		Matched:     matchedRule != nil,
		Blocked:     blocked,
		MatchDetails: fmt.Sprintf("Rule: %s, Action: %s", matchedRule.Name, matchedRule.Action),
	}

	if matchedRule != nil {
		response.RuleName = matchedRule.Name
		response.Action = string(matchedRule.Action)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF test rule response")
	}
}

// handleAPIWAFExportRules 导出WAF规则
func (s *Server) handleAPIWAFExportRules(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	// 获取导出格式
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	rules := s.wafEngine.Engine.GetRules()

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=waf_rules.json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":     "1.0",
			"exported_at":  time.Now().Format(time.RFC3339),
			"total_rules":  len(rules),
			"rules":       rules,
		})

	case "yaml":
		w.Header().Set("Content-Type", "text/yaml")
		w.Header().Set("Content-Disposition", "attachment; filename=waf_rules.yaml")

		// 简单的YAML导出
		yaml := fmt.Sprintf("# WAF Rules Export\n# Exported at: %s\n# Total rules: %d\n\n",
			time.Now().Format(time.RFC3339), len(rules))

		for _, rule := range rules {
			yaml += fmt.Sprintf("- id: %s\n", rule.ID)
			yaml += fmt.Sprintf("  name: %s\n", rule.Name)
			yaml += fmt.Sprintf("  type: %s\n", rule.Type)
			yaml += fmt.Sprintf("  pattern: %s\n", rule.Pattern)
			yaml += fmt.Sprintf("  action: %s\n", rule.Action)
			yaml += fmt.Sprintf("  enabled: %t\n", rule.Enabled)
			yaml += fmt.Sprintf("  description: %s\n\n", rule.Description)
		}

		w.Write([]byte(yaml))

	default:
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid format. Supported formats: json, yaml")
	}
}

// handleAPIWAFImportRules 导入WAF规则
func (s *Server) handleAPIWAFImportRules(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}

	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// 检查WAF引擎是否可用
	if s.wafEngine == nil || s.wafEngine.Engine == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WAF engine not available")
		return
	}

	// 获取导入格式
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	var importedRules []*waf.Rule
	var failedRules []map[string]interface{}

	switch format {
	case "json":
		var data struct {
			Rules []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Type        string `json:"type"`
				Pattern     string `json:"pattern"`
				Action      string `json:"action"`
				Enabled     bool   `json:"enabled"`
				Description string `json:"description"`
				CreatedAt   string `json:"created_at"`
			} `json:"rules"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON format")
			return
		}

		for _, ruleData := range data.Rules {
			rule := &waf.Rule{
				ID:          ruleData.ID,
				Name:        ruleData.Name,
				Type:        waf.RuleType(ruleData.Type),
				Pattern:     ruleData.Pattern,
				Action:      waf.Action(ruleData.Action),
				Enabled:     ruleData.Enabled,
				Description: ruleData.Description,
			}

			if ruleData.CreatedAt != "" {
				if t, err := time.Parse(time.RFC3339, ruleData.CreatedAt); err == nil {
					rule.CreatedAt = t
				}
			}

			if err := s.wafEngine.Engine.AddRule(rule); err != nil {
				failedRules = append(failedRules, map[string]interface{}{
					"id":      rule.ID,
					"name":    rule.Name,
					"error":   err.Error(),
				})
			} else {
				importedRules = append(importedRules, rule)
			}
		}

	case "yaml":
		// 简单的YAML解析（实际项目应使用yaml库）
		lines := strings.Split(string(body), "\n")
		var currentRule *waf.Rule

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if strings.HasPrefix(line, "- id:") {
				if currentRule != nil {
					if err := s.wafEngine.Engine.AddRule(currentRule); err != nil {
						failedRules = append(failedRules, map[string]interface{}{
							"id":    currentRule.ID,
							"name":  currentRule.Name,
							"error": err.Error(),
						})
					} else {
						importedRules = append(importedRules, currentRule)
					}
				}

				currentRule = &waf.Rule{
					CreatedAt: time.Now(),
				}
			} else if currentRule != nil {
				if strings.HasPrefix(line, "id:") {
					currentRule.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
				} else if strings.HasPrefix(line, "name:") {
					currentRule.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
				} else if strings.HasPrefix(line, "type:") {
					currentRule.Type = waf.RuleType(strings.TrimSpace(strings.TrimPrefix(line, "type:")))
				} else if strings.HasPrefix(line, "pattern:") {
					currentRule.Pattern = strings.TrimSpace(strings.TrimPrefix(line, "pattern:"))
				} else if strings.HasPrefix(line, "action:") {
					currentRule.Action = waf.Action(strings.TrimSpace(strings.TrimPrefix(line, "action:")))
				} else if strings.HasPrefix(line, "enabled:") {
					currentRule.Enabled = strings.TrimSpace(strings.TrimPrefix(line, "enabled:")) == "true"
				} else if strings.HasPrefix(line, "description:") {
					currentRule.Description = strings.TrimSpace(strings.TrimPrefix(line, "description:"))
				}
			}
		}

		// 添加最后一个规则
		if currentRule != nil && currentRule.ID != "" {
			if err := s.wafEngine.Engine.AddRule(currentRule); err != nil {
				failedRules = append(failedRules, map[string]interface{}{
					"id":    currentRule.ID,
					"name":  currentRule.Name,
					"error": err.Error(),
				})
			} else {
				importedRules = append(importedRules, currentRule)
			}
		}

	default:
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid format. Supported formats: json, yaml")
		return
	}

	s.log.WithFields(logrus.Fields{
		"imported": len(importedRules),
		"failed":   len(failedRules),
	}).Info("WAF rules imported")

	response := map[string]interface{}{
		"success":        true,
		"message":        fmt.Sprintf("Imported %d rules, %d failed", len(importedRules), len(failedRules)),
		"imported_count": len(importedRules),
		"failed_count":   len(failedRules),
		"imported":       importedRules,
		"failed":         failedRules,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.WithError(err).Error("Failed to encode WAF import rules response")
	}
}

