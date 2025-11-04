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

type securityModel struct {
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

type securityItem struct {
	key   string
	value string
	path  []string
}

func NewSecurityModel(cfg *config.Config, configFile string) securityModel {
	items := buildSecurityItems(cfg)
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "安全设置"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."

	return securityModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m securityModel) Init() tea.Cmd {
	return nil
}

func (m securityModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				if err := m.setSecurityValue(m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					items := buildSecurityItems(m.config)
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

		case "ctrl+s":
			// Ctrl+S 总是可以保存，即使输入框处于焦点状态
			if err := m.config.Save(m.configFile); err != nil {
				m.message = fmt.Sprintf("❌ 保存失败: %v", err)
			} else {
				m.message = "✅ 配置已保存到文件"
			}
			return m, nil

		case "esc":
			if m.message != "" {
				m.message = ""
				return m, nil
			}
			return m, tea.Quit

		case "enter", "e":
			selected := m.list.SelectedItem()
			if selected != nil {
				item := selected.(securityItem)
				if item.value != "" {
					m.editing = true
					m.editKey = item.key
					m.editInput.SetValue(item.value)
					m.editInput.Focus()
					return m, textinput.Blink
				}
			}

		case "s":
			// 只有在非编辑模式下才保存
			if m.editing {
				// 编辑模式下，将按键传递给输入框
				var cmd tea.Cmd
				m.editInput, cmd = m.editInput.Update(msg)
				return m, cmd
			}
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

func (m securityModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("安全设置")

	var content string
	if m.editing {
		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			fmt.Sprintf("编辑配置项: %s", infoStyle.Render(m.editKey)),
			fmt.Sprintf("当前值: %s", m.editKey),
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

func buildSecurityItems(cfg *config.Config) []securityItem {
	var items []securityItem
	sec := &cfg.Security

	items = append(items, securityItem{
		key:   "security.enable_waf",
		value: strconv.FormatBool(sec.EnableWAF),
		path:  []string{"security", "enable_waf"},
	})

	items = append(items, securityItem{
		key:   "security.enable_ddos",
		value: strconv.FormatBool(sec.EnableDDOS),
		path:  []string{"security", "enable_ddos"},
	})

	items = append(items, securityItem{
		key:   "security.enable_ua_filter",
		value: strconv.FormatBool(sec.EnableUAFilter),
		path:  []string{"security", "enable_ua_filter"},
	})

	items = append(items, securityItem{
		key:   "security.enable_captcha",
		value: strconv.FormatBool(sec.EnableCaptcha),
		path:  []string{"security", "enable_captcha"},
	})

	items = append(items, securityItem{
		key:   "security.max_attempts",
		value: strconv.Itoa(sec.MaxAttempts),
		path:  []string{"security", "max_attempts"},
	})

	items = append(items, securityItem{
		key:   "security.max_attempts_5min",
		value: strconv.Itoa(sec.MaxAttempts5Min),
		path:  []string{"security", "max_attempts_5min"},
	})

	items = append(items, securityItem{
		key:   "security.block_duration",
		value: sec.BlockDurationStr,
		path:  []string{"security", "block_duration"},
	})

	items = append(items, securityItem{
		key:   "security.block_file",
		value: sec.BlockFile,
		path:  []string{"security", "block_file"},
	})

	items = append(items, securityItem{
		key:   "security.ua_invalid_max_1min",
		value: strconv.Itoa(sec.UAInvalidMax1Min),
		path:  []string{"security", "ua_invalid_max_1min"},
	})

	items = append(items, securityItem{
		key:   "security.ua_invalid_max_5min",
		value: strconv.Itoa(sec.UAInvalidMax5Min),
		path:  []string{"security", "ua_invalid_max_5min"},
	})

	items = append(items, securityItem{
		key:   "security.min_form_ms",
		value: strconv.Itoa(sec.MinFormMs),
		path:  []string{"security", "min_form_ms"},
	})

	// IP 白名单/黑名单显示
	whitelistStr := fmt.Sprintf("[%d 项]", len(sec.IPWhitelist))
	if len(sec.IPWhitelist) > 0 && len(sec.IPWhitelist) <= 3 {
		whitelistStr = strings.Join(sec.IPWhitelist, ", ")
	}
	items = append(items, securityItem{
		key:   "security.ip_whitelist",
		value: whitelistStr,
		path:  []string{"security", "ip_whitelist"},
	})

	blacklistStr := fmt.Sprintf("[%d 项]", len(sec.IPBlacklist))
	if len(sec.IPBlacklist) > 0 && len(sec.IPBlacklist) <= 3 {
		blacklistStr = strings.Join(sec.IPBlacklist, ", ")
	}
	items = append(items, securityItem{
		key:   "security.ip_blacklist",
		value: blacklistStr,
		path:  []string{"security", "ip_blacklist"},
	})

	return items
}

func (m securityModel) setSecurityValue(keyPath string, value string) error {
	parts := strings.Split(keyPath, ".")
	if len(parts) < 2 || parts[0] != "security" {
		return fmt.Errorf("无效的配置路径: %s", keyPath)
	}

	field := parts[1]
	sec := &m.config.Security

	switch field {
	case "enable_waf":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		sec.EnableWAF = val

	case "enable_ddos":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		sec.EnableDDOS = val

	case "enable_ua_filter":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		sec.EnableUAFilter = val

	case "enable_captcha":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		sec.EnableCaptcha = val

	case "max_attempts":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		sec.MaxAttempts = val

	case "max_attempts_5min":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		sec.MaxAttempts5Min = val

	case "block_duration":
		sec.BlockDurationStr = value

	case "block_file":
		sec.BlockFile = value

	case "ua_invalid_max_1min":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		sec.UAInvalidMax1Min = val

	case "ua_invalid_max_5min":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		sec.UAInvalidMax5Min = val

	case "min_form_ms":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		sec.MinFormMs = val

	default:
		return fmt.Errorf("不支持的配置项: %s", field)
	}

	return nil
}

// 实现 list.Item 接口
func (i securityItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i securityItem) Title() string {
	return i.key
}

func (i securityItem) Description() string {
	return i.value
}

