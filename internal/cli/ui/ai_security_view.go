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

type aiSecurityModel struct {
	config     *config.Config
	configFile string
	list       list.Model
	editing    bool
	editInput  textinput.Model
	editKey    string
	message    string
	width      int
	height     int
}

type aiSecurityItem struct {
	key   string
	value string
}

func NewAISecurityModel(cfg *config.Config, configFile string) aiSecurityModel {
	items := buildAISecurityItems(cfg)
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "AI 安全分析"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."

	return aiSecurityModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m aiSecurityModel) Init() tea.Cmd {
	return nil
}

func (m aiSecurityModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width - 4)
		m.list.SetHeight(msg.Height - 10)
		return m, nil

	case tea.KeyMsg:
		if m.editing {
			switch msg.String() {
			case "enter":
				newValue := m.editInput.Value()
				if err := m.setAISecurityValue(m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					items := buildAISecurityItems(m.config)
					listItems := make([]list.Item, len(items))
					for i, item := range items {
						listItems[i] = item
					}
					m.list.SetItems(listItems)
				}
				m.editing = false
				m.editInput.Blur()
				return m, nil

			case "esc":
				m.editing = false
				m.editInput.Blur()
				return m, nil
			}

			var cmd tea.Cmd
			m.editInput, cmd = m.editInput.Update(msg)
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

		case "enter", "e":
			selected := m.list.SelectedItem()
			if selected != nil {
				item := selected.(aiSecurityItem)
				if item.value != "" {
					m.editing = true
					m.editKey = item.key
					m.editInput.SetValue(item.value)
					m.editInput.Focus()
					return m, textinput.Blink
				}
			}

		case "s":
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

func (m aiSecurityModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("AI 安全分析")

	var content string
	if m.editing {
		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			fmt.Sprintf("编辑配置项: %s", infoStyle.Render(m.editKey)),
			"",
			m.editInput.View(),
			"",
			helpStyle.Render("Enter: 保存 | Esc: 取消"),
		)
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
			"Enter/e": "编辑",
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

func buildAISecurityItems(cfg *config.Config) []aiSecurityItem {
	var items []aiSecurityItem
	ai := &cfg.AISecurity

	items = append(items, aiSecurityItem{
		key:   "ai_security.enabled",
		value: strconv.FormatBool(ai.Enabled),
	})

	items = append(items, aiSecurityItem{
		key:   "ai_security.api_endpoint",
		value: ai.APIEndpoint,
	})

	items = append(items, aiSecurityItem{
		key:   "ai_security.model",
		value: ai.Model,
	})

	items = append(items, aiSecurityItem{
		key:   "ai_security.max_tokens",
		value: strconv.Itoa(ai.MaxTokens),
	})

	items = append(items, aiSecurityItem{
		key:   "ai_security.temperature",
		value: strconv.FormatFloat(ai.Temperature, 'f', 2, 64),
	})

	items = append(items, aiSecurityItem{
		key:   "ai_security.language",
		value: ai.Language,
	})

	items = append(items, aiSecurityItem{
		key:   "ai_security.notify_on_threat",
		value: strconv.FormatBool(ai.NotifyOnThreat),
	})

	items = append(items, aiSecurityItem{
		key:   "ai_security.min_threat_level",
		value: ai.MinThreatLevel,
	})

	return items
}

func (m aiSecurityModel) setAISecurityValue(keyPath string, value string) error {
	parts := strings.Split(keyPath, ".")
	if len(parts) < 2 || parts[0] != "ai_security" {
		return fmt.Errorf("无效的配置路径: %s", keyPath)
	}

	field := parts[1]
	ai := &m.config.AISecurity

	switch field {
	case "enabled":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		ai.Enabled = val

	case "api_endpoint":
		ai.APIEndpoint = value

	case "model":
		ai.Model = value

	case "max_tokens":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		ai.MaxTokens = val

	case "temperature":
		val, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("无效的浮点数值: %v", err)
		}
		ai.Temperature = val

	case "language":
		ai.Language = value

	case "notify_on_threat":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		ai.NotifyOnThreat = val

	case "min_threat_level":
		ai.MinThreatLevel = value

	default:
		return fmt.Errorf("不支持的配置项: %s", field)
	}

	return nil
}

// 实现 list.Item 接口
func (i aiSecurityItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i aiSecurityItem) Title() string {
	return i.key
}

func (i aiSecurityItem) Description() string {
	return i.value
}

