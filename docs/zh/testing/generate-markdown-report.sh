#!/bin/bash

# 从 JSON 测试结果生成 Markdown 报告

set -e

JSON_FILE="${1:-test-results.json}"
MARKDOWN_FILE="${2:-template-test-results.md}"

if [ ! -f "$JSON_FILE" ]; then
    echo "❌ JSON 文件不存在: $JSON_FILE"
    exit 1
fi

echo "📄 生成 Markdown 报告..."
echo "  输入: $JSON_FILE"
echo "  输出: $MARKDOWN_FILE"

# 使用 Go 工具生成报告
cd ../../../tools/test-templates

# 创建一个临时 Go 程序来生成报告
cat > /tmp/generate-report.go << 'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type TestStatus string
const (
	StatusPassed  TestStatus = "passed"
	StatusFailed  TestStatus = "failed"
	StatusSkipped TestStatus = "skipped"
)

type TestResult struct {
	TemplateID   string                 `json:"template_id"`
	TemplateName string                 `json:"template_name"`
	Category     string                 `json:"category"`
	Priority     string                 `json:"priority"`
	Status       TestStatus             `json:"status"`
	Errors       []string               `json:"errors"`
}

type TestSummary struct {
	Total    int    `json:"total"`
	Passed   int    `json:"passed"`
	Failed   int    `json:"failed"`
	Skipped  int    `json:"skipped"`
	Duration string `json:"duration"`
}

type TestReport struct {
	Summary TestSummary  `json:"summary"`
	Results []TestResult `json:"results"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("用法: generate-report <json-file> <markdown-file>")
		os.Exit(1)
	}

	jsonPath := os.Args[1]
	markdownPath := os.Args[2]

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		fmt.Printf("读取 JSON 失败: %v\n", err)
		os.Exit(1)
	}

	var report TestReport
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Printf("解析 JSON 失败: %v\n", err)
		os.Exit(1)
	}

	markdown := generateMarkdown(&report)
	if err := os.WriteFile(markdownPath, []byte(markdown), 0644); err != nil {
		fmt.Printf("写入 Markdown 失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Markdown 报告已生成: %s\n", markdownPath)
}

func generateMarkdown(report *TestReport) string {
	var buf strings.Builder
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

	buf.WriteString("# 模板测试结果报告\n\n")
	buf.WriteString("本文档记录 SSLcat 模板库的自动化测试结果。\n\n")
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
	priorityStats := calculatePriorityStats(report.Results)
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

	// 失败的模板
	if failed > 0 || skipped > 0 {
		buf.WriteString("## 测试失败的模板\n\n")
		for _, r := range report.Results {
			if r.Status == StatusFailed || r.Status == StatusSkipped {
				buf.WriteString(fmt.Sprintf("- **%s** (%s) - %s: %s\n",
					r.TemplateName, r.TemplateID, r.Category, strings.Join(r.Errors, "; ")))
			}
		}
		buf.WriteString("\n")
	}

	buf.WriteString("## 详细测试结果\n\n")
	buf.WriteString("详细的测试结果请查看 JSON 文件：`test-results.json`\n\n")
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

func calculatePriorityStats(results []TestResult) []PriorityStats {
	stats := make(map[string]*PriorityStats)
	for _, r := range results {
		priority := r.Priority
		if priority == "" {
			priority = "low"
		}
		if stats[priority] == nil {
			stats[priority] = &PriorityStats{Priority: priority}
		}
		stats[priority].Total++
		switch r.Status {
		case StatusPassed:
			stats[priority].Passed++
		case StatusFailed:
			stats[priority].Failed++
		case StatusSkipped:
			stats[priority].Skipped++
		}
	}
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
EOF

go run /tmp/generate-report.go "$JSON_FILE" "$MARKDOWN_FILE"
rm /tmp/generate-report.go

echo "✅ 完成！"

