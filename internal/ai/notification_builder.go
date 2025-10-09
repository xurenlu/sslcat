package ai

import (
	"fmt"
	"strings"

	"github.com/xurenlu/sslcat/internal/notification"
)

// buildNotificationContent 根据语言设置构建通知内容
func (a *SecurityAnalyzer) buildNotificationContent(result *AnalysisResult, data *SecurityData) string {
	if a.language == "en-US" {
		return a.buildEnglishNotificationContent(result, data)
	}
	return a.buildChineseNotificationContent(result, data)
}

// buildChineseNotificationContent 构建中文通知内容
func (a *SecurityAnalyzer) buildChineseNotificationContent(result *AnalysisResult, data *SecurityData) string {
	var content strings.Builder

	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	content.WriteString("  🤖 AI 智能安全分析报告（自动生成）\n")
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString(fmt.Sprintf("📊 分析模型: %s\n", a.model))
	content.WriteString(fmt.Sprintf("⏰ 分析时段: %s\n", data.TimeRange))
	content.WriteString(fmt.Sprintf("🎯 威胁等级: %s\n", strings.ToUpper(result.ThreatLevel)))
	content.WriteString(fmt.Sprintf("📈 AI 置信度: %.0f%%\n\n", result.Confidence*100))
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// 总结
	var summary string
	if result.SummaryZh != "" {
		summary = result.SummaryZh
	} else if result.Summary != "" {
		summary = result.Summary
	}
	content.WriteString("💡 总结:\n")
	content.WriteString(fmt.Sprintf("%s\n\n", summary))

	if len(result.Threats) > 0 {
		content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		content.WriteString("🚨 发现的威胁:\n\n")

		for i, threat := range result.Threats {
			content.WriteString(fmt.Sprintf("【威胁 %d】[%s] %s\n\n", i+1, strings.ToUpper(threat.Severity), threat.Type))

			// 描述
			var desc string
			if threat.DescriptionZh != "" {
				desc = threat.DescriptionZh
			} else if threat.Description != "" {
				desc = threat.Description
			}
			if desc != "" {
				content.WriteString(fmt.Sprintf("📝 描述: %s\n", desc))
			}

			// 指标
			if len(threat.Indicators) > 0 {
				content.WriteString(fmt.Sprintf("🎯 指标: %s\n", strings.Join(threat.Indicators, ", ")))
			}

			// 建议
			var action string
			if threat.ActionZh != "" {
				action = threat.ActionZh
			} else if threat.Action != "" {
				action = threat.Action
			}
			if action != "" {
				content.WriteString(fmt.Sprintf("💡 建议: %s\n", action))
			}

			content.WriteString(fmt.Sprintf("📊 置信度: %.0f%%\n", threat.Confidence*100))
			content.WriteString("\n")
		}
	}

	// 安全建议
	recommendations := result.RecommendationsZh
	if len(recommendations) == 0 {
		recommendations = result.Recommendations
	}
	if len(recommendations) > 0 {
		content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		content.WriteString("💼 安全建议:\n\n")
		for i, rec := range recommendations {
			content.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		content.WriteString("\n")
	}

	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString(fmt.Sprintf("⏱️  分析完成时间: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("📊 数据来源: SSLcat 安全日志与 DDoS 防护记录\n"))
	content.WriteString(fmt.Sprintf("🤖 分析引擎: %s (OpenAI Compatible API)\n\n", a.model))
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString("ℹ️  重要提示:\n\n")
	content.WriteString("• 本报告由 AI 自动生成，仅供参考\n")
	content.WriteString("• 建议结合实际情况和人工判断做出决策\n")
	content.WriteString("• AI 分析可能存在误报或漏报\n")
	content.WriteString("• 如有疑问，请查看完整的安全日志进行确认\n\n")
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	return content.String()
}

// buildEnglishNotificationContent 构建英文通知内容
func (a *SecurityAnalyzer) buildEnglishNotificationContent(result *AnalysisResult, data *SecurityData) string {
	var content strings.Builder

	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	content.WriteString("  🤖 AI Security Analysis Report (Automated)\n")
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString(fmt.Sprintf("📊 Analysis Model: %s\n", a.model))
	content.WriteString(fmt.Sprintf("⏰ Time Range: %s\n", data.TimeRange))
	content.WriteString(fmt.Sprintf("🎯 Threat Level: %s\n", strings.ToUpper(result.ThreatLevel)))
	content.WriteString(fmt.Sprintf("📈 AI Confidence: %.0f%%\n\n", result.Confidence*100))
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// Summary
	var summary string
	if result.SummaryEn != "" {
		summary = result.SummaryEn
	} else if result.Summary != "" {
		summary = result.Summary
	}
	content.WriteString("💡 Summary:\n")
	content.WriteString(fmt.Sprintf("%s\n\n", summary))

	if len(result.Threats) > 0 {
		content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		content.WriteString("🚨 Detected Threats:\n\n")

		for i, threat := range result.Threats {
			content.WriteString(fmt.Sprintf("【Threat %d】[%s] %s\n\n", i+1, strings.ToUpper(threat.Severity), threat.Type))

			// Description
			var desc string
			if threat.DescriptionEn != "" {
				desc = threat.DescriptionEn
			} else if threat.Description != "" {
				desc = threat.Description
			}
			if desc != "" {
				content.WriteString(fmt.Sprintf("📝 Description: %s\n", desc))
			}

			// Indicators
			if len(threat.Indicators) > 0 {
				content.WriteString(fmt.Sprintf("🎯 Indicators: %s\n", strings.Join(threat.Indicators, ", ")))
			}

			// Action
			var action string
			if threat.ActionEn != "" {
				action = threat.ActionEn
			} else if threat.Action != "" {
				action = threat.Action
			}
			if action != "" {
				content.WriteString(fmt.Sprintf("💡 Recommended Action: %s\n", action))
			}

			content.WriteString(fmt.Sprintf("📊 Confidence: %.0f%%\n", threat.Confidence*100))
			content.WriteString("\n")
		}
	}

	// Security recommendations
	recommendations := result.RecommendationsEn
	if len(recommendations) == 0 {
		recommendations = result.Recommendations
	}
	if len(recommendations) > 0 {
		content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		content.WriteString("💼 Security Recommendations:\n\n")
		for i, rec := range recommendations {
			content.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		content.WriteString("\n")
	}

	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString(fmt.Sprintf("⏱️  Analysis Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("📊 Data Source: SSLcat Security Logs & DDoS Protection Records\n"))
	content.WriteString(fmt.Sprintf("🤖 AI Engine: %s (OpenAI Compatible API)\n\n", a.model))
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString("ℹ️  Important Notice:\n\n")
	content.WriteString("• This report is automatically generated by AI for reference only\n")
	content.WriteString("• Combine with actual situation and manual judgment for decisions\n")
	content.WriteString("• AI analysis may have false positives or false negatives\n")
	content.WriteString("• If in doubt, please review the complete security logs\n\n")
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	return content.String()
}

// buildNotificationTitle 根据语言设置构建通知标题
func (a *SecurityAnalyzer) buildNotificationTitle(result *AnalysisResult) string {
	if a.language == "en-US" {
		return fmt.Sprintf("🤖 AI Security Report - %s Threat (Confidence %.0f%%)",
			strings.ToUpper(result.ThreatLevel), result.Confidence*100)
	}
	return fmt.Sprintf("🤖 AI 安全分析报告 - %s 威胁 (置信度 %.0f%%)",
		strings.ToUpper(result.ThreatLevel), result.Confidence*100)
}

// buildNotificationMessage 根据语言设置构建通知消息
func (a *SecurityAnalyzer) buildNotificationMessage(result *AnalysisResult) string {
	if a.language == "en-US" {
		if result.SummaryEn != "" {
			return result.SummaryEn
		}
		return result.Summary
	}
	if result.SummaryZh != "" {
		return result.SummaryZh
	}
	return result.Summary
}

// SendNotification 发送通知（公开方法）
func (a *SecurityAnalyzer) SendNotification(result *AnalysisResult, data *SecurityData) {
	if a.notifier == nil {
		return
	}

	// 构建通知内容（根据语言设置）
	content := a.buildNotificationContent(result, data)
	title := a.buildNotificationTitle(result)
	message := a.buildNotificationMessage(result)

	// 确定通知级别
	level := notification.LevelWarning
	switch result.ThreatLevel {
	case "critical":
		level = notification.LevelCritical
	case "high":
		level = notification.LevelError
	case "medium":
		level = notification.LevelWarning
	}

	// 发送通知
	notif := &notification.Notification{
		Type:    notification.TypeSecurityAlert,
		Level:   level,
		Title:   title,
		Message: message,
		Details: map[string]any{
			"threat_level":    result.ThreatLevel,
			"confidence":      result.Confidence,
			"threats_count":   len(result.Threats),
			"time_range":      data.TimeRange,
			"total_requests":  data.TotalRequests,
			"blocked_ips":     data.BlockedIPs,
			"full_report":     content,
			"ai_model":        a.model,
			"analysis_type":   "ai_automated",
			"is_ai_generated": true,
			"language":        a.language,
		},
	}

	if err := a.notifier.GetManager().Send(notif); err != nil {
		a.log.Errorf("发送 AI 安全分析通知失败: %v", err)
	} else {
		a.log.Info("AI 安全分析通知已发送")
	}
}
