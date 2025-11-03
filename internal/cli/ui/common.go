package ui

import (
	"github.com/charmbracelet/lipgloss"
)

// 定义颜色和样式
var (
	// 基础颜色
	primaryColor   = lipgloss.Color("39")
	secondaryColor = lipgloss.Color("242")
	successColor   = lipgloss.Color("46")
	warningColor   = lipgloss.Color("226")
	errorColor     = lipgloss.Color("196")
	infoColor      = lipgloss.Color("33")

	// 样式定义
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			MarginBottom(1)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			Background(lipgloss.Color("236"))

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250"))

	successStyle = lipgloss.NewStyle().
			Foreground(successColor)

	errorStyle = lipgloss.NewStyle().
			Foreground(errorColor)

	warningStyle = lipgloss.NewStyle().
			Foreground(warningColor)

	infoStyle = lipgloss.NewStyle().
			Foreground(infoColor)

	helpStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			MarginTop(1)

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(secondaryColor).
			Padding(1, 2)

	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(primaryColor).
				Padding(0, 1)

	tableCellStyle = lipgloss.NewStyle().
			Padding(0, 1)

	statusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("236")).
			Foreground(lipgloss.Color("250")).
			Padding(0, 1)
)

// renderBox 渲染一个带边框的框
func renderBox(title string, content string, width int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(secondaryColor).
		Padding(1, 2).
		Width(width - 4).
		MaxWidth(width - 4)

	titleBox := titleStyle.Render(title)
	contentBox := box.Render(content)

	return lipgloss.JoinVertical(lipgloss.Left, titleBox, contentBox)
}

// renderTable 渲染简单的表格
func renderTable(headers []string, rows [][]string, selectedRow int) string {
	if len(headers) == 0 {
		return ""
	}

	// 计算列宽
	colWidths := make([]int, len(headers))
	for i, header := range headers {
		colWidths[i] = len(header) + 2
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(colWidths) {
				if len(cell)+2 > colWidths[i] {
					colWidths[i] = len(cell) + 2
				}
			}
		}
	}

	// 渲染表头
	headerCells := make([]string, len(headers))
	for i, header := range headers {
		headerCells[i] = tableHeaderStyle.Width(colWidths[i]).Render(header)
	}
	headerRow := lipgloss.JoinHorizontal(lipgloss.Left, headerCells...)

	// 渲染数据行
	var bodyRows []string
	for i, row := range rows {
		cells := make([]string, len(headers))
		for j := 0; j < len(headers); j++ {
			cell := ""
			if j < len(row) {
				cell = row[j]
			}
			style := normalStyle
			if i == selectedRow {
				style = selectedStyle
			}
			cells[j] = style.Width(colWidths[j]).Render(cell)
		}
		bodyRows = append(bodyRows, lipgloss.JoinHorizontal(lipgloss.Left, cells...))
	}

	body := lipgloss.JoinVertical(lipgloss.Left, bodyRows...)
	return lipgloss.JoinVertical(lipgloss.Left, headerRow, body)
}

// renderStatusBar 渲染状态栏
func renderStatusBar(left, right string) string {
	leftStyle := statusBarStyle.Copy().Align(lipgloss.Left)
	rightStyle := statusBarStyle.Copy().Align(lipgloss.Right)

	leftText := leftStyle.Render(left)
	rightText := rightStyle.Render(right)

	width := lipgloss.Width(leftText) + lipgloss.Width(rightText)
	if width < 80 {
		width = 80
	}

	// 填充中间空白
	middleWidth := width - lipgloss.Width(leftText) - lipgloss.Width(rightText)
	if middleWidth > 0 {
		middle := statusBarStyle.Width(middleWidth).Render("")
		return lipgloss.JoinHorizontal(lipgloss.Left, leftText, middle, rightText)
	}

	return lipgloss.JoinHorizontal(lipgloss.Left, leftText, rightText)
}

// renderHelp 渲染帮助信息
func renderHelp(keys map[string]string) string {
	var items []string
	for key, desc := range keys {
		items = append(items, lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true).
			Render(key)+": "+desc)
	}
	return helpStyle.Render(lipgloss.JoinVertical(lipgloss.Left, items...))
}

