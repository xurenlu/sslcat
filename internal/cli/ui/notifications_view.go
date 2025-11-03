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

type notificationsModel struct {
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

type notificationItem struct {
	key   string
	value string
}

func NewNotificationsModel(cfg *config.Config, configFile string) notificationsModel {
	items := buildNotificationItems(cfg)
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "通知管理"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."

	return notificationsModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m notificationsModel) Init() tea.Cmd {
	return nil
}

func (m notificationsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				if err := m.setNotificationValue(m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					items := buildNotificationItems(m.config)
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
				item := selected.(notificationItem)
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

func (m notificationsModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("通知管理")

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

func buildNotificationItems(cfg *config.Config) []notificationItem {
	var items []notificationItem
	notif := &cfg.Notification

	items = append(items, notificationItem{
		key:   "notification.enabled",
		value: strconv.FormatBool(notif.Enabled),
	})

	items = append(items, notificationItem{
		key:   "notification.min_notification_level",
		value: notif.MinNotificationLevel,
	})

	// Email 通知
	items = append(items, notificationItem{
		key:   "notification.channels.email.enabled",
		value: strconv.FormatBool(notif.Channels.Email.Enabled),
	})

	items = append(items, notificationItem{
		key:   "notification.channels.email.smtp_host",
		value: notif.Channels.Email.SMTPHost,
	})

	items = append(items, notificationItem{
		key:   "notification.channels.email.smtp_port",
		value: strconv.Itoa(notif.Channels.Email.SMTPPort),
	})

	// Webhook 通知
	items = append(items, notificationItem{
		key:   "notification.channels.webhook.enabled",
		value: strconv.FormatBool(notif.Channels.Webhook.Enabled),
	})

	// Syslog 通知
	items = append(items, notificationItem{
		key:   "notification.channels.syslog.enabled",
		value: strconv.FormatBool(notif.Channels.Syslog.Enabled),
	})

	// Console 通知
	items = append(items, notificationItem{
		key:   "notification.channels.console.enabled",
		value: strconv.FormatBool(notif.Channels.Console.Enabled),
	})

	return items
}

func (m notificationsModel) setNotificationValue(keyPath string, value string) error {
	parts := strings.Split(keyPath, ".")
	if len(parts) < 2 || parts[0] != "notification" {
		return fmt.Errorf("无效的配置路径: %s", keyPath)
	}

	notif := &m.config.Notification

	if len(parts) == 2 {
		// 直接字段
		switch parts[1] {
		case "enabled":
			val, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("无效的布尔值: %v", err)
			}
			notif.Enabled = val
		case "min_notification_level":
			notif.MinNotificationLevel = value
		default:
			return fmt.Errorf("不支持的配置项: %s", parts[1])
		}
	} else if len(parts) >= 3 && parts[1] == "channels" {
		// 渠道配置
		if len(parts) < 4 {
			return fmt.Errorf("无效的配置路径: %s", keyPath)
		}
		channel := parts[2]
		field := parts[3]

		switch channel {
		case "email":
			switch field {
			case "enabled":
				val, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("无效的布尔值: %v", err)
				}
				notif.Channels.Email.Enabled = val
			case "smtp_host":
				notif.Channels.Email.SMTPHost = value
			case "smtp_port":
				val, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("无效的整数值: %v", err)
				}
				notif.Channels.Email.SMTPPort = val
			default:
				return fmt.Errorf("不支持的配置项: %s", field)
			}

		case "webhook":
			if field == "enabled" {
				val, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("无效的布尔值: %v", err)
				}
				notif.Channels.Webhook.Enabled = val
			} else {
				return fmt.Errorf("不支持的配置项: %s", field)
			}

		case "syslog":
			if field == "enabled" {
				val, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("无效的布尔值: %v", err)
				}
				notif.Channels.Syslog.Enabled = val
			} else {
				return fmt.Errorf("不支持的配置项: %s", field)
			}

		case "console":
			if field == "enabled" {
				val, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("无效的布尔值: %v", err)
				}
				notif.Channels.Console.Enabled = val
			} else {
				return fmt.Errorf("不支持的配置项: %s", field)
			}

		default:
			return fmt.Errorf("不支持的通知渠道: %s", channel)
		}
	}

	return nil
}

// 实现 list.Item 接口
func (i notificationItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i notificationItem) Title() string {
	return i.key
}

func (i notificationItem) Description() string {
	return i.value
}

