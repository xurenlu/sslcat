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

type cdnModel struct {
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

type cdnItem struct {
	key   string
	value string
}

func NewCDNModel(cfg *config.Config, configFile string) cdnModel {
	items := buildCDNItems(cfg)
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "CDN 缓存管理"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."

	return cdnModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m cdnModel) Init() tea.Cmd {
	return nil
}

func (m cdnModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				if err := m.setCDNValue(m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					items := buildCDNItems(m.config)
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
				item := selected.(cdnItem)
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

func (m cdnModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("CDN 缓存管理")

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

func buildCDNItems(cfg *config.Config) []cdnItem {
	var items []cdnItem
	cdn := &cfg.CDNCache

	items = append(items, cdnItem{
		key:   "cdn_cache.enabled",
		value: strconv.FormatBool(cdn.Enabled),
	})

	items = append(items, cdnItem{
		key:   "cdn_cache.cache_dir",
		value: cdn.CacheDir,
	})

	items = append(items, cdnItem{
		key:   "cdn_cache.max_size_bytes",
		value: strconv.FormatInt(cdn.MaxSizeBytes, 10),
	})

	items = append(items, cdnItem{
		key:   "cdn_cache.default_ttl_seconds",
		value: strconv.Itoa(cdn.DefaultTTLSeconds),
	})

	items = append(items, cdnItem{
		key:   "cdn_cache.clean_interval_sec",
		value: strconv.Itoa(cdn.CleanIntervalSec),
	})

	items = append(items, cdnItem{
		key:   "cdn_cache.max_object_bytes",
		value: strconv.FormatInt(cdn.MaxObjectBytes, 10),
	})

	items = append(items, cdnItem{
		key:   "cdn_cache.rules",
		value: fmt.Sprintf("[%d 条规则]", len(cdn.Rules)),
	})

	return items
}

func (m cdnModel) setCDNValue(keyPath string, value string) error {
	parts := strings.Split(keyPath, ".")
	if len(parts) < 2 || parts[0] != "cdn_cache" {
		return fmt.Errorf("无效的配置路径: %s", keyPath)
	}

	field := parts[1]
	cdn := &m.config.CDNCache

	switch field {
	case "enabled":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		cdn.Enabled = val

	case "cache_dir":
		cdn.CacheDir = value

	case "max_size_bytes":
		val, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		cdn.MaxSizeBytes = val

	case "default_ttl_seconds":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		cdn.DefaultTTLSeconds = val

	case "clean_interval_sec":
		val, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		cdn.CleanIntervalSec = val

	case "max_object_bytes":
		val, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("无效的整数值: %v", err)
		}
		cdn.MaxObjectBytes = val

	default:
		return fmt.Errorf("不支持的配置项: %s", field)
	}

	return nil
}

// 实现 list.Item 接口
func (i cdnItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i cdnItem) Title() string {
	return i.key
}

func (i cdnItem) Description() string {
	return i.value
}

