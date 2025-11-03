package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type MenuModel struct {
	choices  []string
	cursor   int
	selected string
	width    int
	height   int
}

func NewMenuModel() MenuModel {
	return MenuModel{
		choices: []string{
			"📊 仪表盘",
			"📋 配置管理",
			"🔀 代理规则管理",
			"🌐 站点管理",
			"🔒 SSL 证书管理",
			"🌍 DNS 管理",
			"🛡️  安全设置",
			"⚙️  系统设置",
			"💾 CDN 缓存管理",
			"📈 访问统计",
			"🐌 慢请求分析",
			"🔔 通知管理",
			"🔄 集群管理",
			"🤖 AI 安全分析",
			"🖼️  图片优化",
			"👥 用户管理",
			"❌ 退出",
		},
		cursor: 0,
	}
}

func (m MenuModel) Init() tea.Cmd {
	return nil
}

func (m MenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.selected = "exit"
			return m, tea.Quit

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			if m.cursor < len(m.choices)-1 {
				m.cursor++
			}

		case "enter", " ":
			m.selected = m.choices[m.cursor]
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m MenuModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	// 标题
	title := titleStyle.Render("SSLcat 控制台")
	subtitle := subtitleStyle.Render("使用方向键选择，按 Enter 确认，按 q 退出")

	// 菜单项
	var menuItems []string
	for i, choice := range m.choices {
		cursor := " "
		if m.cursor == i {
			cursor = ">"
			menuItems = append(menuItems, selectedStyle.Render(fmt.Sprintf("%s %s", cursor, choice)))
		} else {
			menuItems = append(menuItems, normalStyle.Render(fmt.Sprintf("%s %s", cursor, choice)))
		}
	}

	menu := lipgloss.JoinVertical(lipgloss.Left, menuItems...)

	// 帮助信息
	help := renderHelp(map[string]string{
		"↑↓/jk": "移动",
		"Enter": "选择",
		"q":     "退出",
	})

	// 组合所有内容
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		subtitle,
		"",
		menu,
		"",
		help,
	)

	// 居中显示
	box := lipgloss.NewStyle().
		Width(m.width).
		Height(m.height).
		Align(lipgloss.Center, lipgloss.Center).
		Render(content)

	return box
}

// GetSelected 获取选中的菜单项
func (m MenuModel) GetSelected() string {
	if m.selected == "" {
		return ""
	}

	// 提取功能名称（去掉图标和空格）
	parts := strings.Fields(m.selected)
	if len(parts) >= 2 {
		// 移除第一个元素（图标），合并剩余部分
		return strings.Join(parts[1:], "")
	}
	return m.selected
}

