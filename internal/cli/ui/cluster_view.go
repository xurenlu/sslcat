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

type clusterModel struct {
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

type clusterItem struct {
	key   string
	value string
}

func NewClusterModel(cfg *config.Config, configFile string) clusterModel {
	items := buildClusterItems(cfg)
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "集群管理"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."

	return clusterModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m clusterModel) Init() tea.Cmd {
	return nil
}

func (m clusterModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				if err := m.setClusterValue(m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					items := buildClusterItems(m.config)
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
				item := selected.(clusterItem)
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

func (m clusterModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("集群管理")

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

func buildClusterItems(cfg *config.Config) []clusterItem {
	var items []clusterItem
	cluster := &cfg.Cluster

	items = append(items, clusterItem{
		key:   "cluster.mode",
		value: cluster.Mode,
	})

	items = append(items, clusterItem{
		key:   "cluster.node_id",
		value: cluster.NodeID,
	})

	items = append(items, clusterItem{
		key:   "cluster.node_name",
		value: cluster.NodeName,
	})

	items = append(items, clusterItem{
		key:   "cluster.port",
		value: strconv.Itoa(cluster.Port),
	})

	items = append(items, clusterItem{
		key:   "cluster.master.timeout",
		value: strconv.Itoa(cluster.Master.Timeout),
	})

	items = append(items, clusterItem{
		key:   "cluster.sync.config_enabled",
		value: strconv.FormatBool(cluster.Sync.ConfigEnabled),
	})

	items = append(items, clusterItem{
		key:   "cluster.sync.cert_enabled",
		value: strconv.FormatBool(cluster.Sync.CertEnabled),
	})

	items = append(items, clusterItem{
		key:   "cluster.sync.interval",
		value: strconv.Itoa(cluster.Sync.Interval),
	})

	return items
}

func (m clusterModel) setClusterValue(keyPath string, value string) error {
	parts := strings.Split(keyPath, ".")
	if len(parts) < 2 || parts[0] != "cluster" {
		return fmt.Errorf("无效的配置路径: %s", keyPath)
	}

	cluster := &m.config.Cluster

	if len(parts) == 2 {
		// 直接字段
		switch parts[1] {
		case "mode":
			cluster.Mode = value
		case "node_id":
			cluster.NodeID = value
		case "node_name":
			cluster.NodeName = value
		case "port":
			val, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("无效的整数值: %v", err)
			}
			cluster.Port = val
		default:
			return fmt.Errorf("不支持的配置项: %s", parts[1])
		}
	} else if len(parts) >= 3 {
		// 嵌套字段
		switch parts[1] {
		case "master":
			if parts[2] == "timeout" {
				val, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("无效的整数值: %v", err)
				}
				cluster.Master.Timeout = val
			} else {
				return fmt.Errorf("不支持的配置项: %s", parts[2])
			}
		case "sync":
			switch parts[2] {
			case "config_enabled":
				val, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("无效的布尔值: %v", err)
				}
				cluster.Sync.ConfigEnabled = val
			case "cert_enabled":
				val, err := strconv.ParseBool(value)
				if err != nil {
					return fmt.Errorf("无效的布尔值: %v", err)
				}
				cluster.Sync.CertEnabled = val
			case "interval":
				val, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("无效的整数值: %v", err)
				}
				cluster.Sync.Interval = val
			default:
				return fmt.Errorf("不支持的配置项: %s", parts[2])
			}
		default:
			return fmt.Errorf("不支持的配置项: %s", parts[1])
		}
	}

	return nil
}

// 实现 list.Item 接口
func (i clusterItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i clusterItem) Title() string {
	return i.key
}

func (i clusterItem) Description() string {
	return i.value
}

