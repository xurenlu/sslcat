package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type proxyModel struct {
	config     *config.Config
	configFile string
	list       list.Model
	editing    bool
	adding     bool
	formInputs []textinput.Model
	formIndex  int
	selectedIndex int
	message    string
	width      int
	height     int
}

type proxyRuleItem struct {
	rule *config.ProxyRule
	index int
}

func NewProxyModel(cfg *config.Config, configFile string) proxyModel {
	items := make([]list.Item, len(cfg.Proxy.Rules))
	for i := range cfg.Proxy.Rules {
		items[i] = proxyRuleItem{
			rule:  &cfg.Proxy.Rules[i],
			index: i,
		}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "代理规则"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	// 初始化表单输入框
	formInputs := []textinput.Model{
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
	}

	formInputs[0].Placeholder = "域名 (例如: example.com)"
	formInputs[1].Placeholder = "目标地址 (例如: 127.0.0.1)"
	formInputs[2].Placeholder = "端口 (例如: 8080)"
	formInputs[3].Placeholder = "启用 (true/false)"
	formInputs[4].Placeholder = "SSL Only (true/false)"

	return proxyModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		formInputs: formInputs,
	}
}

func (m proxyModel) Init() tea.Cmd {
	return nil
}

func (m proxyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width - 4)
		m.list.SetHeight(msg.Height - 10)
		return m, nil

	case tea.KeyMsg:
		if m.editing || m.adding {
			switch msg.String() {
			case "tab":
				m.formIndex = (m.formIndex + 1) % len(m.formInputs)
				for i := range m.formInputs {
					if i == m.formIndex {
						m.formInputs[i].Focus()
					} else {
						m.formInputs[i].Blur()
					}
				}
				return m, textinput.Blink

			case "shift+tab":
				m.formIndex = (m.formIndex - 1 + len(m.formInputs)) % len(m.formInputs)
				for i := range m.formInputs {
					if i == m.formIndex {
						m.formInputs[i].Focus()
					} else {
						m.formInputs[i].Blur()
					}
				}
				return m, textinput.Blink

			case "enter":
				// 保存规则
				if err := m.saveRule(); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
					return m, nil
				}
				m.editing = false
				m.adding = false
				m.resetForm()
				// 重新构建列表
				m.refreshList()
				m.message = "✅ 规则已保存"
				return m, nil

			case "esc":
				m.editing = false
				m.adding = false
				m.resetForm()
				return m, nil
			}

			// 更新当前输入框
			var cmd tea.Cmd
			m.formInputs[m.formIndex], cmd = m.formInputs[m.formIndex].Update(msg)
			return m, cmd
		}

		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "esc":
			if m.message != "" {
				m.message = ""
				return m, nil
			}
			return m, tea.Quit

		case "a":
			// 添加新规则 - 使用高级配置视图
			advancedModel := NewProxyAdvancedModel(m.config, m.configFile, nil, -1)
			p := tea.NewProgram(advancedModel, tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				m.message = fmt.Sprintf("❌ 添加错误: %v", err)
			} else {
				m.refreshList()
				m.message = "✅ 规则已添加"
			}
			return m, nil

		case "A":
			// 简单添加模式（保留原有功能）
			m.adding = true
			m.resetForm()
			m.formInputs[0].Focus()
			m.formIndex = 0
			return m, textinput.Blink

		case "e":
			// 编辑选中的规则
			selected := m.list.SelectedItem()
			if selected != nil {
				item := selected.(proxyRuleItem)
				// 使用高级配置视图
				advancedModel := NewProxyAdvancedModel(m.config, m.configFile, item.rule, item.index)
				p := tea.NewProgram(advancedModel, tea.WithAltScreen())
				if _, err := p.Run(); err != nil {
					m.message = fmt.Sprintf("❌ 编辑错误: %v", err)
				} else {
					m.refreshList()
					m.message = "✅ 规则已更新"
				}
				return m, nil
			}

		case "E":
			// 高级编辑模式
			selected := m.list.SelectedItem()
			if selected != nil {
				item := selected.(proxyRuleItem)
				advancedModel := NewProxyAdvancedModel(m.config, m.configFile, item.rule, item.index)
				p := tea.NewProgram(advancedModel, tea.WithAltScreen())
				if _, err := p.Run(); err != nil {
					m.message = fmt.Sprintf("❌ 编辑错误: %v", err)
				} else {
					m.refreshList()
					m.message = "✅ 规则已更新"
				}
				return m, nil
			}

		case "d":
			// 删除选中的规则
			selected := m.list.SelectedItem()
			if selected != nil {
				item := selected.(proxyRuleItem)
				m.config.Proxy.Rules = append(
					m.config.Proxy.Rules[:item.index],
					m.config.Proxy.Rules[item.index+1:]...,
				)
				m.refreshList()
				m.message = "✅ 规则已删除"
			}
			return m, nil

		case "s":
			// 保存配置到文件
			if err := m.config.Save(m.configFile); err != nil {
				m.message = fmt.Sprintf("❌ 保存失败: %v", err)
			} else {
				m.message = "✅ 配置已保存到文件"
			}
			return m, nil
		}

		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m proxyModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("代理规则管理")

	var content string
	if m.editing || m.adding {
		action := "添加"
		if m.editing {
			action = "编辑"
		}

		formContent := []string{
			fmt.Sprintf("%s代理规则", action),
			"",
			fmt.Sprintf("域名: %s", m.formInputs[0].View()),
			fmt.Sprintf("目标: %s", m.formInputs[1].View()),
			fmt.Sprintf("端口: %s", m.formInputs[2].View()),
			fmt.Sprintf("启用: %s", m.formInputs[3].View()),
			fmt.Sprintf("SSL Only: %s", m.formInputs[4].View()),
			"",
			helpStyle.Render("Tab: 切换字段 | Enter: 保存 | Esc: 取消"),
		}

		content = lipgloss.JoinVertical(lipgloss.Left, append([]string{title, ""}, formContent...)...)
	} else {
		listView := m.list.View()
		messageView := ""
		if m.message != "" {
			if strings.HasPrefix(m.message, "❌") {
				messageView = errorStyle.Render(m.message)
			} else {
				messageView = successStyle.Render(m.message)
			}
		}

		help := renderHelp(map[string]string{
			"↑↓/jk":  "移动",
			"a":      "添加规则（高级）",
			"A":      "添加规则（简单）",
			"e":      "编辑规则（高级）",
			"d":      "删除规则",
			"s":      "保存配置",
			"q/Esc":  "返回",
		})

		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			listView,
			"",
			messageView,
			"",
			help,
		)
	}

	box := lipgloss.NewStyle().
		Width(m.width - 4).
		MaxWidth(m.width - 4).
		Render(content)

	return box
}

func (m proxyModel) resetForm() {
	for i := range m.formInputs {
		m.formInputs[i].SetValue("")
		m.formInputs[i].Blur()
	}
	m.formIndex = 0
}

func (m proxyModel) loadRule(rule *config.ProxyRule) {
	m.formInputs[0].SetValue(rule.Domain)
	m.formInputs[1].SetValue(rule.Target)
	m.formInputs[2].SetValue(strconv.Itoa(rule.Port))
	m.formInputs[3].SetValue(strconv.FormatBool(rule.Enabled))
	m.formInputs[4].SetValue(strconv.FormatBool(rule.SSLOnly))
}

func (m proxyModel) saveRule() error {
	domain := strings.TrimSpace(m.formInputs[0].Value())
	target := strings.TrimSpace(m.formInputs[1].Value())
	portStr := strings.TrimSpace(m.formInputs[2].Value())
	enabledStr := strings.TrimSpace(m.formInputs[3].Value())
	sslOnlyStr := strings.TrimSpace(m.formInputs[4].Value())

	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}
	if target == "" {
		return fmt.Errorf("目标地址不能为空")
	}

	port := 80
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("无效的端口号: %s", portStr)
		}
		port = p
	}

	enabled := true
	if enabledStr != "" {
		e, err := strconv.ParseBool(enabledStr)
		if err != nil {
			return fmt.Errorf("无效的启用值: %s", enabledStr)
		}
		enabled = e
	}

	sslOnly := false
	if sslOnlyStr != "" {
		s, err := strconv.ParseBool(sslOnlyStr)
		if err != nil {
			return fmt.Errorf("无效的 SSL Only 值: %s", sslOnlyStr)
		}
		sslOnly = s
	}

	rule := config.ProxyRule{
		Domain:  domain,
		Target:  target,
		Port:    port,
		Enabled: enabled,
		SSLOnly: sslOnly,
	}

	if m.adding {
		m.config.Proxy.Rules = append(m.config.Proxy.Rules, rule)
	} else {
		m.config.Proxy.Rules[m.selectedIndex] = rule
	}

	return nil
}

func (m proxyModel) refreshList() {
	items := make([]list.Item, len(m.config.Proxy.Rules))
	for i := range m.config.Proxy.Rules {
		items[i] = proxyRuleItem{
			rule:  &m.config.Proxy.Rules[i],
			index: i,
		}
	}
	m.list.SetItems(items)
}

// 实现 list.Item 接口
func (i proxyRuleItem) FilterValue() string {
	return i.rule.Domain + " " + i.rule.Target
}

func (i proxyRuleItem) Title() string {
	status := "✓"
	if !i.rule.Enabled {
		status = "✗"
	}
	ssl := ""
	if i.rule.SSLOnly {
		ssl = " [SSL]"
	}
	return fmt.Sprintf("%s %s%s -> %s:%d", status, i.rule.Domain, ssl, i.rule.Target, i.rule.Port)
}

func (i proxyRuleItem) Description() string {
	return fmt.Sprintf("启用: %v, SSL Only: %v", i.rule.Enabled, i.rule.SSLOnly)
}

