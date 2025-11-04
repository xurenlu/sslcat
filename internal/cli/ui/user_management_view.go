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

type userManagementModel struct {
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

type userConfigItem struct {
	key   string
	value string
}

func NewUserManagementModel(cfg *config.Config, configFile string) userManagementModel {
	items := buildUserManagementItems(cfg)
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "用户管理"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."

	return userManagementModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m userManagementModel) Init() tea.Cmd {
	return nil
}

func (m userManagementModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				if err := m.setUserManagementValue(m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					items := buildUserManagementItems(m.config)
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
			if m.config == nil {
				m.message = "❌ 配置未初始化"
				return m, nil
			}
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
				item := selected.(userConfigItem)
				if item.value != "" {
					m.editing = true
					m.editKey = item.key
					// 如果当前值是 "***"（密码），清空输入框让用户输入新密码
					if item.value == "***" {
						m.editInput.SetValue("")
					} else {
						m.editInput.SetValue(item.value)
					}
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
			if m.config == nil {
				m.message = "❌ 配置未初始化"
				return m, nil
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

func (m userManagementModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("用户管理")

	var content string
	if m.editing {
		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			fmt.Sprintf("编辑配置项: %s", infoStyle.Render(m.editKey)),
			fmt.Sprintf("当前值: %s", m.editInput.Value()),
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

func buildUserManagementItems(cfg *config.Config) []userConfigItem {
	if cfg == nil {
		return []userConfigItem{}
	}

	items := []userConfigItem{
		{
			key:   "admin.username",
			value: cfg.Admin.Username,
		},
		{
			key:   "admin.password_file",
			value: cfg.Admin.PasswordFile,
		},
		{
			key:   "admin.enable_totp",
			value: strconv.FormatBool(cfg.Admin.EnableTOTP),
		},
		{
			key:   "admin.totp_secret_file",
			value: cfg.Admin.TOTPSecretFile,
		},
	}

	// 如果密码不为空，显示（但不显示明文）
	if cfg.Admin.Password != "" {
		items = append(items, userConfigItem{
			key:   "admin.password",
			value: "***",
		})
	}

	return items
}

func (m *userManagementModel) setUserManagementValue(key string, value string) error {
	if m.config == nil {
		return fmt.Errorf("配置未初始化")
	}

	keys := strings.Split(key, ".")
	if len(keys) != 2 {
		return fmt.Errorf("无效的配置键: %s", key)
	}

	section := keys[0]
	field := keys[1]

	switch section {
	case "admin":
		switch field {
		case "username":
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("用户名不能为空")
			}
			m.config.Admin.Username = strings.TrimSpace(value)

		case "password":
			if strings.TrimSpace(value) != "" {
				m.config.Admin.Password = strings.TrimSpace(value)
			}

		case "password_file":
			m.config.Admin.PasswordFile = strings.TrimSpace(value)

		case "enable_totp":
			val, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("启用值必须是 true 或 false: %v", err)
			}
			m.config.Admin.EnableTOTP = val

		case "totp_secret_file":
			m.config.Admin.TOTPSecretFile = strings.TrimSpace(value)

		default:
			return fmt.Errorf("未知的配置字段: %s", field)
		}

	default:
		return fmt.Errorf("未知的配置段: %s", section)
	}

	return nil
}

// 实现 list.Item 接口
func (i userConfigItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i userConfigItem) Title() string {
	return i.key
}

func (i userConfigItem) Description() string {
	return i.value
}

