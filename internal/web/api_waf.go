package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

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

