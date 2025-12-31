package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/report"
)

// handleAPIReportGenerate 处理手动触发报告生成请求
func (s *Server) handleAPIReportGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.reportGenerator == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "报告生成器未初始化")
		return
	}

	// 解析请求参数
	var req struct {
		Type      string `json:"type"`       // daily, weekly, monthly
		StartTime string `json:"start_time"` // 可选，格式: "2006-01-02 15:04:05"
		EndTime   string `json:"end_time"`   // 可选，格式: "2006-01-02 15:04:05"
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "解析请求参数失败: "+err.Error())
		return
	}

	// 确定报告类型
	var reportType report.ReportType
	switch req.Type {
	case "daily":
		reportType = report.ReportTypeDaily
	case "weekly":
		reportType = report.ReportTypeWeekly
	case "monthly":
		reportType = report.ReportTypeMonthly
	default:
		s.writeErrorResponse(w, http.StatusBadRequest, "无效的报告类型，支持: daily, weekly, monthly")
		return
	}

	// 解析时间范围
	var startTime, endTime time.Time
	var err error

	if req.StartTime != "" && req.EndTime != "" {
		// 使用指定的时间范围
		startTime, err = time.Parse("2006-01-02 15:04:05", req.StartTime)
		if err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "无效的开始时间格式，请使用: 2006-01-02 15:04:05")
			return
		}
		endTime, err = time.Parse("2006-01-02 15:04:05", req.EndTime)
		if err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "无效的结束时间格式，请使用: 2006-01-02 15:04:05")
			return
		}
	} else {
		// 使用默认时间范围（根据报告类型）
		now := time.Now()
		switch reportType {
		case report.ReportTypeDaily:
			startTime = time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, now.Location())
			endTime = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		case report.ReportTypeWeekly:
			weekday := int(now.Weekday())
			if weekday == 0 {
				weekday = 7
			}
			daysSinceMonday := weekday - 1
			lastMonday := now.AddDate(0, 0, -daysSinceMonday-7)
			startTime = time.Date(lastMonday.Year(), lastMonday.Month(), lastMonday.Day(), 0, 0, 0, 0, now.Location())
			endTime = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		case report.ReportTypeMonthly:
			lastMonth := now.AddDate(0, -1, 0)
			startTime = time.Date(lastMonth.Year(), lastMonth.Month(), 1, 0, 0, 0, 0, now.Location())
			endTime = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		}
	}

	// 验证时间范围
	if startTime.After(endTime) {
		s.writeErrorResponse(w, http.StatusBadRequest, "开始时间不能晚于结束时间")
		return
	}

	// 异步生成报告（避免阻塞）
	go func() {
		if err := s.reportGenerator.GenerateReport(reportType, startTime, endTime); err != nil {
			s.log.Errorf("手动触发报告生成失败: %v", err)
		} else {
			s.log.Infof("手动触发%s报告生成成功", reportType)
		}
	}()

	// 返回成功响应
	response := map[string]interface{}{
		"success":    true,
		"message":    "报告生成任务已启动",
		"type":       string(reportType),
		"start_time": startTime.Format("2006-01-02 15:04:05"),
		"end_time":   endTime.Format("2006-01-02 15:04:05"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// SetReportGenerator 设置报告生成器（用于从main.go注入）
func (s *Server) SetReportGenerator(generator *report.ReportGenerator) {
	s.reportGenerator = generator
}

