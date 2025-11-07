package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

