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

type settingsModel struct {
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

type settingsItem struct {
	key   string
	value string
}

func NewSettingsModel(cfg *config.Config, configFile string) settingsModel {
	items := buildSettingsItems(cfg)
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "系统设置"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."

	return settingsModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m settingsModel) Init() tea.Cmd {
	return nil
}

func (m settingsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				if err := m.setSettingsValue(m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					items := buildSettingsItems(m.config)
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
				item := selected.(settingsItem)
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

func (m settingsModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("系统设置")

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

func buildSettingsItems(cfg *config.Config) []settingsItem {
	var items []settingsItem
	srv := &cfg.Server

	items = append(items, settingsItem{
		key:   "server.host",
		value: srv.Host,
	})

	items = append(items, settingsItem{
		key:   "server.port",
		value: strconv.Itoa(srv.Port),
	})

	items = append(items, settingsItem{
		key:   "server.port_mode",
		value: srv.PortMode,
	})

	items = append(items, settingsItem{
		key:   "server.custom_port",
		value: strconv.Itoa(srv.CustomPort),
	})

	items = append(items, settingsItem{
		key:   "server.enable_https",
		value: strconv.FormatBool(srv.EnableHTTPS),
	})

	items = append(items, settingsItem{
		key:   "server.debug",
		value: strconv.FormatBool(srv.Debug),
	})

	items = append(items, settingsItem{
		key:   "server.log_level",
		value: srv.LogLevel,
	})

	items = append(items, settingsItem{
		key:   "server.enable_pprof",
		value: strconv.FormatBool(srv.EnablePprof),
	})

	items = append(items, settingsItem{
		key:   "server.access_log_enabled",
		value: strconv.FormatBool(srv.AccessLogEnabled),
	})

	items = append(items, settingsItem{
		key:   "server.access_log_format",
		value: srv.AccessLogFormat,
	})

	items = append(items, settingsItem{
		key:   "server.access_log_path",
		value: srv.AccessLogPath,
	})

	items = append(items, settingsItem{
		key:   "server.read_timeout_sec",
		value: strconv.Itoa(srv.ReadTimeoutSec),
	})

	items = append(items, settingsItem{
		key:   "server.write_timeout_sec",
		value: strconv.Itoa(srv.WriteTimeoutSec),
	})

	items = append(items, settingsItem{
		key:   "server.idle_timeout_sec",
		value: strconv.Itoa(srv.IdleTimeoutSec),
	})

	items = append(items, settingsItem{
		key:   "server.max_upload_bytes",
		value: strconv.FormatInt(srv.MaxUploadBytes, 10),
	})

	items = append(items, settingsItem{
		key:   "server.session_storage",
		value: srv.SessionStorage,
	})

	items = append(items, settingsItem{
		key:   "server.data_dir",
		value: srv.DataDir,
	})

	items = append(items, settingsItem{
		key:   "admin_prefix",
		value: cfg.AdminPrefix,
	})

	return items
}

func (m settingsModel) setSettingsValue(keyPath string, value string) error {
	parts := strings.Split(keyPath, ".")
	if len(parts) < 1 {
		return fmt.Errorf("无效的配置路径: %s", keyPath)
	}

	if parts[0] == "server" {
		if len(parts) < 2 {
			return fmt.Errorf("无效的配置路径: %s", keyPath)
		}
		return m.setServerValue(parts[1], value)
	} else if keyPath == "admin_prefix" {
		m.config.AdminPrefix = value
		return nil
	}

	return fmt.Errorf("不支持的配置项: %s", keyPath)
}

func (m settingsModel) setServerValue(field string, value string) error {
	srv := &m.config.Server

	switch field {
	case "host":
		srv.Host = value

	case "port":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		srv.Port = val

	case "port_mode":
		srv.PortMode = value

	case "custom_port":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		srv.CustomPort = val

	case "enable_https":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		srv.EnableHTTPS = val

	case "debug":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		srv.Debug = val

	case "log_level":
		srv.LogLevel = value

	case "enable_pprof":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		srv.EnablePprof = val

	case "access_log_enabled":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		srv.AccessLogEnabled = val

	case "access_log_format":
		srv.AccessLogFormat = value

	case "access_log_path":
		srv.AccessLogPath = value

	case "read_timeout_sec":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		srv.ReadTimeoutSec = val

	case "write_timeout_sec":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		srv.WriteTimeoutSec = val

	case "idle_timeout_sec":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		srv.IdleTimeoutSec = val

	case "max_upload_bytes":
		val, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		srv.MaxUploadBytes = val

	case "session_storage":
		srv.SessionStorage = value

	case "data_dir":
		srv.DataDir = value

	default:
		return fmt.Errorf("不支持的配置项: %s", field)
	}

	return nil
}

// 实现 list.Item 接口
func (i settingsItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i settingsItem) Title() string {
	return i.key
}

func (i settingsItem) Description() string {
	return i.value
}

