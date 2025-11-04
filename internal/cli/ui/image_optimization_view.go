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

type imageOptimizationModel struct {
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

type imageOptimizationItem struct {
	key   string
	value string
}

func NewImageOptimizationModel(cfg *config.Config, configFile string) imageOptimizationModel {
	items := buildImageOptimizationItems(cfg)
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "图片优化"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."

	return imageOptimizationModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m imageOptimizationModel) Init() tea.Cmd {
	return nil
}

func (m imageOptimizationModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				if err := m.setImageOptimizationValue(m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					items := buildImageOptimizationItems(m.config)
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
				item := selected.(imageOptimizationItem)
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

func (m imageOptimizationModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("图片优化")

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

func buildImageOptimizationItems(cfg *config.Config) []imageOptimizationItem {
	var items []imageOptimizationItem
	img := &cfg.ImageOptimization

	items = append(items, imageOptimizationItem{
		key:   "image_optimization.enabled",
		value: strconv.FormatBool(img.Enabled),
	})

	// 可以根据 ImageOptimizationConfig 的实际字段添加更多配置项
	return items
}

func (m imageOptimizationModel) setImageOptimizationValue(keyPath string, value string) error {
	parts := strings.Split(keyPath, ".")
	if len(parts) < 2 || parts[0] != "image_optimization" {
		return fmt.Errorf("无效的配置路径: %s", keyPath)
	}

	field := parts[1]
	img := &m.config.ImageOptimization

	switch field {
	case "enabled":
		val, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %v", err)
		}
		img.Enabled = val

	default:
		return fmt.Errorf("不支持的配置项: %s", field)
	}

	return nil
}

// 实现 list.Item 接口
func (i imageOptimizationItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i imageOptimizationItem) Title() string {
	return i.key
}

func (i imageOptimizationItem) Description() string {
	return i.value
}

