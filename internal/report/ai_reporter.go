package report

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/ai"
	"github.com/xurenlu/sslcat/internal/config"
)

// AIReporter AI报告生成器
type AIReporter struct {
	analyzer *ai.SecurityAnalyzer
	log      *logrus.Entry
	enabled  bool
}

// NewAIReporter 创建AI报告生成器
func NewAIReporter(cfg *config.ReportConfig) *AIReporter {
	if cfg == nil || !cfg.AI.Enabled {
		return &AIReporter{
			enabled: false,
			log: logrus.WithFields(logrus.Fields{
				"component": "ai_reporter",
			}),
		}
	}

	// 创建AI分析器（复用现有的SecurityAnalyzer）
	analyzer := ai.NewSecurityAnalyzer(config.AISecurityConfig{
		Enabled:     cfg.AI.Enabled,
		APIKey:      cfg.AI.APIKey,
		APIEndpoint: cfg.AI.APIEndpoint,
		Model:       cfg.AI.Model,
		MaxTokens:   cfg.AI.MaxTokens,
		Temperature: cfg.AI.Temperature,
		Language:    cfg.AI.Language,
	}, nil)

	return &AIReporter{
		analyzer: analyzer,
		enabled:   cfg.AI.Enabled,
		log: logrus.WithFields(logrus.Fields{
			"component": "ai_reporter",
		}),
	}
}

// Enabled 检查是否启用
func (ar *AIReporter) Enabled() bool {
	return ar.enabled && ar.analyzer != nil
}

// GenerateAIReport 生成AI报告
func (ar *AIReporter) GenerateAIReport(data *ReportData) (string, error) {
	if !ar.Enabled() {
		return "", fmt.Errorf("AI报告生成器未启用")
	}

	ar.log.Info("开始生成AI分析报告")

	// 构建安全数据（转换为SecurityAnalyzer需要的格式）
	securityData := ar.buildSecurityData(data)

	// 调用AI分析
	result, err := ar.analyzer.AnalyzeWithGPT(securityData)
	if err != nil {
		return "", fmt.Errorf("AI分析失败: %w", err)
	}

	// 格式化AI分析结果
	return ar.formatAIResult(result), nil
}

// buildSecurityData 构建安全数据
func (ar *AIReporter) buildSecurityData(data *ReportData) *ai.SecurityData {
	securityData := &ai.SecurityData{
		TimeRange:        data.TimeRange,
		TotalRequests:    data.ErrorRequests.TotalRequests,
		BlockedIPs:       0,
		SuspiciousIPs:    0,
		AttackEvents:     []ai.AttackSummary{},
		TopAttackers:     []ai.IPSummary{},
		AnomalousUA:      []ai.UASummary{},
		ErrorRate:        data.ErrorRequests.NonSuccessRate / 100.0,
		TrafficPatterns:  make(map[string]interface{}),
		CountryDistrib:   make(map[string]int),
		URLAccessPattern: make(map[string]int),
		TopTargetURLs:    []ai.URLSummary{},
	}

	// 转换攻击事件
	for _, event := range data.AttackEvents {
		attackSummary := ai.AttackSummary{
			Type:         event.Type,
			Count:        event.Count,
			Blocked:      event.Blocked,
			Severity:     event.Severity,
			FirstSeen:    event.FirstSeen,
			LastSeen:     event.LastSeen,
			TopIPs:       event.TopIPs,
			TopCountries: event.TopCountries,
			TopURLs:      event.TopURLs,
		}
		securityData.AttackEvents = append(securityData.AttackEvents, attackSummary)
	}

	// 统计被拦截的IP数量
	blockedIPSet := make(map[string]bool)
	for _, event := range data.AttackEvents {
		for _, ip := range event.TopIPs {
			if !blockedIPSet[ip] {
				blockedIPSet[ip] = true
				securityData.BlockedIPs++
			}
		}
	}

	return securityData
}

// formatAIResult 格式化AI分析结果
func (ar *AIReporter) formatAIResult(result *ai.AnalysisResult) string {
	var sb strings.Builder

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("  🤖 AI 智能分析总结\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// 威胁等级
	threatLevel := strings.ToUpper(result.ThreatLevel)
	sb.WriteString(fmt.Sprintf("🎯 威胁等级: %s\n", threatLevel))
	sb.WriteString(fmt.Sprintf("📈 AI 置信度: %.0f%%\n\n", result.Confidence*100))

	// 总结
	summary := result.Summary
	if summary == "" {
		if result.SummaryZh != "" {
			summary = result.SummaryZh
		} else if result.SummaryEn != "" {
			summary = result.SummaryEn
		}
	}

	if summary != "" {
		sb.WriteString("💡 分析总结:\n")
		sb.WriteString(fmt.Sprintf("%s\n\n", summary))
	}

	// 威胁详情
	if len(result.Threats) > 0 {
		sb.WriteString("⚠️  威胁详情:\n")
		for i, threat := range result.Threats {
			if i >= 5 { // 只显示前5个
				sb.WriteString(fmt.Sprintf("... 还有 %d 个威胁未显示\n", len(result.Threats)-5))
				break
			}

			description := threat.Description
			if description == "" {
				if threat.DescriptionZh != "" {
					description = threat.DescriptionZh
				} else if threat.DescriptionEn != "" {
					description = threat.DescriptionEn
				}
			}

			action := threat.Action
			if action == "" {
				if threat.ActionZh != "" {
					action = threat.ActionZh
				} else if threat.ActionEn != "" {
					action = threat.ActionEn
				}
			}

			sb.WriteString(fmt.Sprintf("  • [%s] %s\n", strings.ToUpper(threat.Severity), description))
			if action != "" {
				sb.WriteString(fmt.Sprintf("    建议: %s\n", action))
			}
			sb.WriteString("\n")
		}
	}

	// 建议
	if len(result.Recommendations) > 0 {
		sb.WriteString("💡 建议:\n")
		for i, rec := range result.Recommendations {
			if i >= 5 { // 只显示前5个
				sb.WriteString(fmt.Sprintf("... 还有 %d 条建议未显示\n", len(result.Recommendations)-5))
				break
			}
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, rec))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

