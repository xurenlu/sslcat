package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/i18n"
)

type MenuModel struct {
	choices   []string
	cursor    int
	selected  string
	width     int
	height    int
	translator *i18n.Translator
}

func NewMenuModel(translator *i18n.Translator) MenuModel {
	if translator == nil {
		// 如果没有translator，创建一个默认的
		translator = i18n.NewTranslator(i18n.LangZhCN, "")
	}
	
	// 使用翻译键，如果翻译不存在则使用中文原文本作为后备
	getText := func(key, fallback string) string {
		if translator != nil {
			text := translator.T(key)
			if text != key {
				return text
			}
		}
		return fallback
	}
	
	return MenuModel{
		choices: []string{
			getText("tui.menu.dashboard", "📊 仪表盘"),
			getText("tui.menu.config", "📋 配置管理"),
			getText("tui.menu.proxy", "🔀 代理规则管理"),
			getText("tui.menu.sites", "🌐 站点管理"),
			getText("tui.menu.ssl", "🔒 SSL 证书管理"),
			getText("tui.menu.dns", "🌍 DNS 管理"),
			getText("tui.menu.security", "🛡️  安全设置"),
			getText("tui.menu.block_management", "🚫 封禁管理"),
			getText("tui.menu.settings", "⚙️  系统设置"),
			getText("tui.menu.cdn", "💾 CDN 缓存管理"),
			getText("tui.menu.statistics", "📈 访问统计"),
			getText("tui.menu.slow_requests", "🐌 慢请求分析"),
			getText("tui.menu.notifications", "🔔 通知管理"),
			getText("tui.menu.cluster", "🔄 集群管理"),
			getText("tui.menu.ai_security", "🤖 AI 安全分析"),
			getText("tui.menu.image_optimization", "🖼️  图片优化"),
			getText("tui.menu.user_management", "👥 用户管理"),
			getText("tui.menu.exit", "❌ 退出"),
		},
		cursor:    0,
		translator: translator,
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

	// 标题 - 使用翻译
	getText := func(key, fallback string) string {
		if m.translator != nil {
			text := m.translator.T(key)
			if text != key {
				return text
			}
		}
		return fallback
	}
	
	title := titleStyle.Render(getText("tui.console.title", "SSLcat 控制台"))
	subtitle := subtitleStyle.Render(getText("tui.console.subtitle", "使用方向键选择，按 Enter 确认，按 q 退出"))

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
		"↑↓/jk": getText("tui.help.navigate", "移动"),
		"Enter": getText("tui.help.select", "选择"),
		"q":     getText("tui.help.exit", "退出"),
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

