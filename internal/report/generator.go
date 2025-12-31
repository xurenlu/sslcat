package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/notification"
)

// ReportType 报告类型
type ReportType string

const (
	ReportTypeDaily   ReportType = "daily"
	ReportTypeWeekly  ReportType = "weekly"
	ReportTypeMonthly ReportType = "monthly"
)

// ReportGenerator 报告生成器
type ReportGenerator struct {
	collector    *DataCollector
	aiReporter   *AIReporter
	notifier     *notification.NotificationIntegrator
	log          *logrus.Entry
	enabled      bool
}

// NewReportGenerator 创建报告生成器
func NewReportGenerator(
	collector *DataCollector,
	aiReporter *AIReporter,
	notifier *notification.NotificationIntegrator,
	enabled bool,
) *ReportGenerator {
	return &ReportGenerator{
		collector:  collector,
		aiReporter: aiReporter,
		notifier:   notifier,
		log: logrus.WithFields(logrus.Fields{
			"component": "report_generator",
		}),
		enabled: enabled,
	}
}

// GenerateReport 生成报告
func (rg *ReportGenerator) GenerateReport(reportType ReportType, startTime, endTime time.Time) error {
	if !rg.enabled {
		rg.log.Debug("报告生成已禁用，跳过")
		return nil
	}

	rg.log.Infof("开始生成%s报告，时间范围: %s 至 %s", reportType, startTime.Format("2006-01-02 15:04:05"), endTime.Format("2006-01-02 15:04:05"))

	// 收集数据
	data, err := rg.collector.CollectReportData(startTime, endTime)
	if err != nil {
		return fmt.Errorf("收集报告数据失败: %w", err)
	}

	// 生成报告文本
	reportText := rg.generateReportText(reportType, data)

	// 使用AI生成分析总结（如果启用）
	if rg.aiReporter != nil && rg.aiReporter.Enabled() {
		aiSummary, err := rg.aiReporter.GenerateAIReport(data)
		if err != nil {
			rg.log.Warnf("AI报告生成失败: %v，继续使用基础报告", err)
		} else {
			// 将AI分析添加到报告末尾
			reportText += "\n\n" + aiSummary
		}
	}

	// 发送报告通知
	rg.SendReport(reportType, reportText, data)

	rg.log.Infof("%s报告生成完成", reportType)
	return nil
}

// generateReportText 生成报告文本
func (rg *ReportGenerator) generateReportText(reportType ReportType, data *ReportData) string {
	var sb strings.Builder

	// 报告标题
	title := "系统运行报告"
	switch reportType {
	case ReportTypeDaily:
		title = "每日系统运行报告"
	case ReportTypeWeekly:
		title = "每周系统运行报告"
	case ReportTypeMonthly:
		title = "每月系统运行报告"
	}

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString(fmt.Sprintf("  📊 %s\n", title))
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	sb.WriteString(fmt.Sprintf("📅 报告时间: %s\n", data.TimeRange))
	sb.WriteString(fmt.Sprintf("⏰ 生成时间: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// 系统负载情况
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("  💻 系统负载情况\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	if len(data.HighLoadEvents) > 0 {
		sb.WriteString(fmt.Sprintf("⚠️  检测到 %d 次高负载事件\n\n", len(data.HighLoadEvents)))
		sb.WriteString("高负载事件详情:\n")
		for i, event := range data.HighLoadEvents {
			if i >= 10 { // 只显示前10个
				sb.WriteString(fmt.Sprintf("... 还有 %d 个事件未显示\n", len(data.HighLoadEvents)-10))
				break
			}
			sb.WriteString(fmt.Sprintf("  • %s: CPU %.1f%%, 内存 %.1f%% (%.1f MB)\n",
				event.Timestamp.Format("15:04:05"), event.CPUPercent, event.MemoryPercent, event.MemoryMB))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("✅ 未检测到高负载事件\n\n")
	}

	// 系统统计
	if data.SystemStats.MaxCPUPercent > 0 {
		sb.WriteString("系统统计:\n")
		sb.WriteString(fmt.Sprintf("  • 平均CPU使用率: %.1f%%\n", data.SystemStats.AvgCPUPercent))
		sb.WriteString(fmt.Sprintf("  • 峰值CPU使用率: %.1f%%\n", data.SystemStats.MaxCPUPercent))
		sb.WriteString(fmt.Sprintf("  • 平均内存使用率: %.1f%%\n", data.SystemStats.AvgMemoryPercent))
		sb.WriteString(fmt.Sprintf("  • 峰值内存使用率: %.1f%%\n", data.SystemStats.MaxMemoryPercent))
		sb.WriteString(fmt.Sprintf("  • 平均内存占用: %.1f MB\n", data.SystemStats.AvgMemoryMB))
		sb.WriteString(fmt.Sprintf("  • 峰值内存占用: %.1f MB\n\n", data.SystemStats.MaxMemoryMB))
	}

	// 安全事件
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("  🔒 安全事件\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	if len(data.AttackEvents) > 0 {
		totalAttacks := 0
		totalBlocked := 0
		for _, event := range data.AttackEvents {
			totalAttacks += event.Count
			totalBlocked += event.Blocked
		}
		sb.WriteString(fmt.Sprintf("📊 总攻击次数: %d\n", totalAttacks))
		sb.WriteString(fmt.Sprintf("🛡️  成功拦截: %d (%.1f%%)\n\n", totalBlocked, float64(totalBlocked)/float64(totalAttacks)*100))

		for _, event := range data.AttackEvents {
			sb.WriteString(fmt.Sprintf("【%s】\n", strings.ToUpper(event.Type)))
			sb.WriteString(fmt.Sprintf("  • 攻击次数: %d\n", event.Count))
			sb.WriteString(fmt.Sprintf("  • 拦截次数: %d\n", event.Blocked))
			sb.WriteString(fmt.Sprintf("  • 严重程度: %s\n", event.Severity))
			sb.WriteString(fmt.Sprintf("  • 首次出现: %s\n", event.FirstSeen.Format("2006-01-02 15:04:05")))
			sb.WriteString(fmt.Sprintf("  • 最后出现: %s\n", event.LastSeen.Format("2006-01-02 15:04:05")))

			if len(event.TopIPs) > 0 {
				sb.WriteString(fmt.Sprintf("  • 主要攻击IP: %s\n", strings.Join(event.TopIPs[:min(5, len(event.TopIPs))], ", ")))
			}
			if len(event.TopCountries) > 0 {
				sb.WriteString(fmt.Sprintf("  • 主要来源国家: %s\n", strings.Join(event.TopCountries[:min(5, len(event.TopCountries))], ", ")))
			}
			if len(event.TopURLs) > 0 {
				sb.WriteString(fmt.Sprintf("  • 主要攻击目标: %s\n", strings.Join(event.TopURLs[:min(5, len(event.TopURLs))], ", ")))
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("✅ 未检测到安全事件\n\n")
	}

	// 证书状态
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("  🔐 证书状态\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	if len(data.CertIssues) > 0 {
		sb.WriteString(fmt.Sprintf("⚠️  发现 %d 个证书问题\n\n", len(data.CertIssues)))
		for _, cert := range data.CertIssues {
			statusIcon := "❌"
			statusText := "已过期"
			if cert.Status == "expiring_soon" {
				statusIcon = "⚠️"
				statusText = fmt.Sprintf("即将过期（%d天后）", cert.DaysLeft)
			}
			sb.WriteString(fmt.Sprintf("%s %s: %s\n", statusIcon, cert.Domain, statusText))
			sb.WriteString(fmt.Sprintf("   过期时间: %s\n", cert.ExpiresAt.Format("2006-01-02 15:04:05")))
			sb.WriteString(fmt.Sprintf("   颁发机构: %s\n", cert.Issuer))
			if cert.SelfSigned {
				sb.WriteString("   (自签名证书)\n")
			}
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("✅ 所有证书状态正常\n\n")
	}

	// 请求统计
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("  📈 请求统计\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	sb.WriteString(fmt.Sprintf("总请求数: %d\n", data.ErrorRequests.TotalRequests))
	sb.WriteString(fmt.Sprintf("非正常请求数: %d (%.2f%%)\n", data.ErrorRequests.NonSuccessCount, data.ErrorRequests.NonSuccessRate))

	if len(data.ErrorRequests.StatusCodes) > 0 {
		sb.WriteString("\n状态码分布:\n")
		for code, count := range data.ErrorRequests.StatusCodes {
			sb.WriteString(fmt.Sprintf("  • %d: %d 次\n", code, count))
		}
	}

	sb.WriteString("\n")

	return sb.String()
}

// SendReport 发送报告通知
func (rg *ReportGenerator) SendReport(reportType ReportType, reportText string, data *ReportData) {
	if rg.notifier == nil {
		rg.log.Warn("通知系统未配置，跳过发送报告")
		return
	}

	// 确定通知级别
	level := notification.LevelInfo
	if len(data.HighLoadEvents) > 10 || len(data.AttackEvents) > 0 || len(data.CertIssues) > 0 {
		level = notification.LevelWarning
	}
	if len(data.HighLoadEvents) > 50 || len(data.AttackEvents) > 5 {
		level = notification.LevelError
	}

	// 构建通知
	notif := &notification.Notification{
		Type:      notification.TypeSecurityAlert,
		Level:     level,
		Title:     fmt.Sprintf("%s报告", rg.getReportTypeName(reportType)),
		Message:   reportText,
		Timestamp: time.Now(),
		Source:    "report_generator",
		Details: map[string]any{
			"report_type": string(reportType),
			"time_range":  data.TimeRange,
			"start_time":  data.StartTime,
			"end_time":    data.EndTime,
		},
	}

	// 发送通知（通过NotificationManager）
	if mgr := rg.notifier.GetManager(); mgr != nil {
		if err := mgr.Send(notif); err != nil {
			rg.log.Errorf("发送报告通知失败: %v", err)
		}
	} else {
		rg.log.Warn("通知管理器未初始化，跳过发送报告")
	}
}

// getReportTypeName 获取报告类型名称
func (rg *ReportGenerator) getReportTypeName(reportType ReportType) string {
	switch reportType {
	case ReportTypeDaily:
		return "每日"
	case ReportTypeWeekly:
		return "每周"
	case ReportTypeMonthly:
		return "每月"
	default:
		return "系统"
	}
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

