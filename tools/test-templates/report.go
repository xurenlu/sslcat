package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReportGenerator 报告生成器
type ReportGenerator struct {
	outputDir string
}

// NewReportGenerator 创建报告生成器
func NewReportGenerator(outputDir string) *ReportGenerator {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("⚠️  创建输出目录失败: %v\n", err)
	}
	return &ReportGenerator{
		outputDir: outputDir,
	}
}

// GenerateReport 生成测试报告
func (rg *ReportGenerator) GenerateReport(results []TestResult, startTime time.Time) error {
	// 计算汇总
	summary := rg.calculateSummary(results, startTime)

	report := TestReport{
		Summary: summary,
		Results: results,
	}

	// 生成 JSON 报告
	jsonPath := filepath.Join(rg.outputDir, "test-results.json")
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 JSON 失败: %w", err)
	}

	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("写入 JSON 文件失败: %w", err)
	}

	// 输出控制台报告
	rg.printConsoleReport(report)

	return nil
}

// calculateSummary 计算汇总信息
func (rg *ReportGenerator) calculateSummary(results []TestResult, startTime time.Time) TestSummary {
	summary := TestSummary{
		Total: len(results),
	}

	for _, result := range results {
		switch result.Status {
		case StatusPassed:
			summary.Passed++
		case StatusFailed:
			summary.Failed++
		case StatusSkipped:
			summary.Skipped++
		}
	}

	summary.Duration = time.Since(startTime).String()
	return summary
}

// printConsoleReport 输出控制台报告
func (rg *ReportGenerator) printConsoleReport(report TestReport) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("📊 测试报告")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("总计: %d | ✅ 通过: %d | ❌ 失败: %d | ⏭️  跳过: %d\n",
		report.Summary.Total,
		report.Summary.Passed,
		report.Summary.Failed,
		report.Summary.Skipped)
	fmt.Printf("耗时: %s\n", report.Summary.Duration)
	fmt.Println(strings.Repeat("=", 80))

	// 按分类统计
	categoryStats := make(map[string]map[string]int)
	for _, result := range report.Results {
		if categoryStats[result.Category] == nil {
			categoryStats[result.Category] = make(map[string]int)
		}
		categoryStats[result.Category][string(result.Status)]++
	}

	if len(categoryStats) > 0 {
		fmt.Println("\n📦 按分类统计:")
		for category, stats := range categoryStats {
			fmt.Printf("  %s: 通过 %d, 失败 %d, 跳过 %d\n",
				category,
				stats[string(StatusPassed)],
				stats[string(StatusFailed)],
				stats[string(StatusSkipped)])
		}
	}

	// 失败的模板
	if report.Summary.Failed > 0 {
		fmt.Println("\n❌ 失败的模板:")
		for _, result := range report.Results {
			if result.Status == StatusFailed {
				fmt.Printf("  - %s (%s): %v\n", result.TemplateName, result.TemplateID, result.Errors)
			}
		}
	}

	fmt.Printf("\n📄 详细报告已保存: %s/test-results.json\n", rg.outputDir)
}

// GenerateMarkdownReport 从 JSON 结果生成 Markdown 报告
func GenerateMarkdownReport(jsonPath, markdownPath string) error {
	// 读取 JSON 文件
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("读取 JSON 文件失败: %w", err)
	}

	var report TestReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("解析 JSON 失败: %w", err)
	}

	// 生成 Markdown 内容
	markdown := generateMarkdownContent(&report)

	// 写入文件
	if err := os.WriteFile(markdownPath, []byte(markdown), 0644); err != nil {
		return fmt.Errorf("写入 Markdown 文件失败: %w", err)
	}

	fmt.Printf("✅ Markdown 报告已生成: %s\n", markdownPath)
	return nil
}

func generateMarkdownContent(report *TestReport) string {
	var buf strings.Builder

	// 计算统计信息
	now := time.Now()
	testDate := now.Format("2006-01-02 15:04:05")
	total := report.Summary.Total
	passed := report.Summary.Passed
	failed := report.Summary.Failed
	skipped := report.Summary.Skipped
	var successRate float64
	if total > 0 {
		successRate = float64(passed) / float64(total) * 100
	}

	// 按优先级统计
	priorityStats := calculatePriorityStats(report.Results)
	categoryStats := calculateCategoryStats(report.Results)

	// 生成报告
	buf.WriteString("# 模板测试结果报告\n\n")
	buf.WriteString("本文档记录 SSLcat 模板库的自动化测试结果。\n\n")

	// 测试概览
	buf.WriteString("## 测试概览\n\n")
	buf.WriteString(fmt.Sprintf("- **测试日期**: %s\n", testDate))
	buf.WriteString("- **测试服务器**: sg2.shifen.de\n")
	buf.WriteString(fmt.Sprintf("- **测试总数**: %d\n", total))
	buf.WriteString(fmt.Sprintf("- **通过数量**: %d\n", passed))
	buf.WriteString(fmt.Sprintf("- **失败数量**: %d\n", failed))
	buf.WriteString(fmt.Sprintf("- **跳过数量**: %d\n", skipped))
	buf.WriteString(fmt.Sprintf("- **成功率**: %.2f%%\n", successRate))
	buf.WriteString(fmt.Sprintf("- **总耗时**: %s\n\n", report.Summary.Duration))

	// 按优先级统计
	buf.WriteString("## 按优先级统计\n\n")
	buf.WriteString("| 优先级 | 总数 | 通过 | 失败 | 跳过 | 成功率 |\n")
	buf.WriteString("|--------|------|------|------|------|--------|\n")
	for _, ps := range priorityStats {
		var rate float64
		if ps.Total > 0 {
			rate = float64(ps.Passed) / float64(ps.Total) * 100
		}
		buf.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %.2f%% |\n",
			getPriorityName(ps.Priority), ps.Total, ps.Passed, ps.Failed, ps.Skipped, rate))
	}
	buf.WriteString("\n")

	// 按分类统计
	buf.WriteString("## 按分类统计\n\n")
	buf.WriteString("| 分类 | 总数 | 通过 | 失败 | 跳过 | 成功率 |\n")
	buf.WriteString("|------|------|------|------|------|--------|\n")
	for _, cs := range categoryStats {
		var rate float64
		if cs.Total > 0 {
			rate = float64(cs.Passed) / float64(cs.Total) * 100
		}
		buf.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %.2f%% |\n",
			cs.Category, cs.Total, cs.Passed, cs.Failed, cs.Skipped, rate))
	}
	buf.WriteString("\n")

	// 测试通过的模板
	buf.WriteString("## 测试通过的模板\n\n")
	passedTemplates := filterByStatus(report.Results, StatusPassed)
	for _, ps := range priorityStats {
		priorityTemplates := filterByPriority(passedTemplates, ps.Priority)
		if len(priorityTemplates) > 0 {
			buf.WriteString(fmt.Sprintf("### %s优先级模板\n\n", getPriorityName(ps.Priority)))
			for _, tpl := range priorityTemplates {
				buf.WriteString(fmt.Sprintf("- **%s** (%s) - %s\n", tpl.TemplateName, tpl.TemplateID, tpl.Category))
			}
			buf.WriteString("\n")
		}
	}

	// 测试失败的模板
	buf.WriteString("## 测试失败的模板\n\n")

	// 镜像不存在
	missingImages := filterMissingImages(report.Results)
	if len(missingImages) > 0 {
		buf.WriteString("### 镜像不存在\n\n")
		for _, tpl := range missingImages {
			buf.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", tpl.TemplateName, tpl.TemplateID, strings.Join(tpl.Errors, "; ")))
		}
		buf.WriteString("\n")
	}

	// 启动失败
	startupFailed := filterStartupFailed(report.Results)
	if len(startupFailed) > 0 {
		buf.WriteString("### 启动失败\n\n")
		for _, tpl := range startupFailed {
			buf.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", tpl.TemplateName, tpl.TemplateID, strings.Join(tpl.Errors, "; ")))
		}
		buf.WriteString("\n")
	}

	// 其他错误
	otherErrors := filterOtherErrors(report.Results)
	if len(otherErrors) > 0 {
		buf.WriteString("### 其他错误\n\n")
		for _, tpl := range otherErrors {
			buf.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", tpl.TemplateName, tpl.TemplateID, strings.Join(tpl.Errors, "; ")))
		}
		buf.WriteString("\n")
	}

	// 详细测试结果
	buf.WriteString("## 详细测试结果\n\n")
	buf.WriteString("详细的测试结果请查看 JSON 文件：`test-results.json`\n\n")

	// 更新记录
	buf.WriteString("## 更新记录\n\n")
	buf.WriteString(fmt.Sprintf("- %s: 测试报告生成\n\n", testDate))

	return buf.String()
}

type PriorityStats struct {
	Priority string
	Total    int
	Passed   int
	Failed   int
	Skipped  int
}

type CategoryStats struct {
	Category string
	Total    int
	Passed   int
	Failed   int
	Skipped  int
}

func calculatePriorityStats(results []TestResult) []PriorityStats {
	stats := make(map[string]*PriorityStats)

	for _, result := range results {
		priority := result.Priority
		if priority == "" {
			priority = "low"
		}

		if stats[priority] == nil {
			stats[priority] = &PriorityStats{Priority: priority}
		}

		stats[priority].Total++
		switch result.Status {
		case StatusPassed:
			stats[priority].Passed++
		case StatusFailed:
			stats[priority].Failed++
		case StatusSkipped:
			stats[priority].Skipped++
		}
	}

	// 转换为切片并排序
	var result []PriorityStats
	for _, s := range stats {
		result = append(result, *s)
	}

	sort.Slice(result, func(i, j int) bool {
		order := map[string]int{"high": 1, "medium": 2, "low": 3}
		return order[result[i].Priority] < order[result[j].Priority]
	})

	return result
}

func calculateCategoryStats(results []TestResult) []CategoryStats {
	stats := make(map[string]*CategoryStats)

	for _, result := range results {
		category := result.Category
		if category == "" {
			category = "uncategorized"
		}

		if stats[category] == nil {
			stats[category] = &CategoryStats{Category: category}
		}

		stats[category].Total++
		switch result.Status {
		case StatusPassed:
			stats[category].Passed++
		case StatusFailed:
			stats[category].Failed++
		case StatusSkipped:
			stats[category].Skipped++
		}
	}

	// 转换为切片并排序
	var result []CategoryStats
	for _, s := range stats {
		result = append(result, *s)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Category < result[j].Category
	})

	return result
}

func filterByStatus(results []TestResult, status TestStatus) []TestResult {
	var filtered []TestResult
	for _, r := range results {
		if r.Status == status {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func filterByPriority(results []TestResult, priority string) []TestResult {
	var filtered []TestResult
	for _, r := range results {
		if r.Priority == priority {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func filterMissingImages(results []TestResult) []TestResult {
	var filtered []TestResult
	for _, r := range results {
		for _, err := range r.Errors {
			if strings.Contains(err, "镜像不存在") {
				filtered = append(filtered, r)
				break
			}
		}
	}
	return filtered
}

func filterStartupFailed(results []TestResult) []TestResult {
	var filtered []TestResult
	for _, r := range results {
		if r.Status == StatusFailed {
			for _, err := range r.Errors {
				if strings.Contains(err, "启动") || strings.Contains(err, "容器") {
					filtered = append(filtered, r)
					break
				}
			}
		}
	}
	return filtered
}

func filterOtherErrors(results []TestResult) []TestResult {
	var filtered []TestResult
	missingImages := filterMissingImages(results)
	startupFailed := filterStartupFailed(results)

	for _, r := range results {
		if r.Status == StatusFailed || r.Status == StatusSkipped {
			// 排除已分类的错误
			isMissingImage := false
			for _, mi := range missingImages {
				if mi.TemplateID == r.TemplateID {
					isMissingImage = true
					break
				}
			}
			isStartupFailed := false
			for _, sf := range startupFailed {
				if sf.TemplateID == r.TemplateID {
					isStartupFailed = true
					break
				}
			}
			if !isMissingImage && !isStartupFailed {
				filtered = append(filtered, r)
			}
		}
	}
	return filtered
}

func getPriorityName(priority string) string {
	switch priority {
	case "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	default:
		return priority
	}
}

// PrintStageResult 打印阶段结果
func PrintStageResult(templateName, stage string, status TestStatus, duration time.Duration, err error) {
	icon := "✅"
	if status == StatusFailed {
		icon = "❌"
	} else if status == StatusSkipped {
		icon = "⏭️ "
	}

	msg := fmt.Sprintf("%s %s - %s (%s)", icon, templateName, stage, duration.Round(time.Second))
	if err != nil {
		msg += fmt.Sprintf(": %v", err)
	}
	fmt.Println("  " + msg)
}

