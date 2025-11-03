package ui

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type configModel struct {
	config     *config.Config
	configFile string
	list       list.Model
	editing    bool
	editInput  textinput.Model
	editKey    string
	editValue  string
	message    string
	width      int
	height     int
}

type configItem struct {
	key   string
	value string
	path  []string
}

func NewConfigModel(cfg *config.Config, configFile string) configModel {
	items := buildConfigItems(cfg, []string{})
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "配置项"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	ti := textinput.New()
	ti.Placeholder = "输入新值..."
	ti.Focus()

	return configModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		editInput:  ti,
	}
}

func (m configModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m configModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				// 保存编辑
				newValue := m.editInput.Value()
				if err := m.setConfigValue(m.config, m.editKey, newValue); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ 配置已更新: %s = %s", m.editKey, newValue)
					// 重新构建列表
					items := buildConfigItems(m.config, []string{})
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
				item := selected.(configItem)
				if item.value != "" {
					m.editing = true
					m.editKey = item.key
					m.editValue = item.value
					m.editInput.SetValue(item.value)
					m.editInput.Focus()
					return m, textinput.Blink
				}
			}

		case "s":
			// 保存配置
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

func (m configModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("配置管理")

	var content string
	if m.editing {
		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			fmt.Sprintf("编辑配置项: %s", infoStyle.Render(m.editKey)),
			fmt.Sprintf("当前值: %s", m.editValue),
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

func buildConfigItems(cfg interface{}, prefix []string) []configItem {
	var items []configItem
	v := reflect.ValueOf(cfg)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// 跳过非导出字段和 ConfigFile 字段
		if !field.CanInterface() || fieldType.Name == "ConfigFile" {
			continue
		}

		jsonTag := fieldType.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			continue
		}

		jsonTag = strings.Split(jsonTag, ",")[0]
		currentPath := append(prefix, jsonTag)

		key := strings.Join(currentPath, ".")

		switch field.Kind() {
		case reflect.String:
			items = append(items, configItem{
				key:   key,
				value: field.String(),
				path:  currentPath,
			})

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			items = append(items, configItem{
				key:   key,
				value: strconv.FormatInt(field.Int(), 10),
				path:  currentPath,
			})

		case reflect.Bool:
			items = append(items, configItem{
				key:   key,
				value: strconv.FormatBool(field.Bool()),
				path:  currentPath,
			})

		case reflect.Slice:
			// 对于切片，显示长度和预览
			len := field.Len()
			preview := "[]"
			if len > 0 {
				if field.Type().Elem().Kind() == reflect.String {
					// 字符串切片，显示前几个元素
					previewElems := make([]string, 0, 3)
					for j := 0; j < len && j < 3; j++ {
						previewElems = append(previewElems, field.Index(j).String())
					}
					preview = fmt.Sprintf("[%s]", strings.Join(previewElems, ", "))
					if len > 3 {
						preview += fmt.Sprintf(" ... (%d 项)", len)
					}
				} else {
					preview = fmt.Sprintf("[%d 项]", len)
				}
			}
			items = append(items, configItem{
				key:   key,
				value: preview,
				path:  currentPath,
			})

		case reflect.Struct:
			// 递归处理嵌套结构
			subItems := buildConfigItems(field.Interface(), currentPath)
			items = append(items, subItems...)
		}
	}

	return items
}

func (m configModel) setConfigValue(obj interface{}, keyPath string, value string) error {
	keys := strings.Split(keyPath, ".")
	return setConfigValueByPath(obj, keys, value)
}

// findFieldByJSONTag 通过 JSON tag 查找字段
func findFieldByJSONTag(v reflect.Value, jsonTag string) reflect.Value {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" {
			continue
		}
		// 提取 JSON tag 名称（去除 omitempty 等选项）
		tagName := strings.Split(tag, ",")[0]
		if tagName == jsonTag {
			return v.Field(i)
		}
	}
	return reflect.Value{}
}

func setConfigValueByPath(obj interface{}, keys []string, value string) error {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// 遍历路径，找到目标字段
	for _, key := range keys[:len(keys)-1] {
		field := findFieldByJSONTag(v, key)
		if !field.IsValid() {
			return fmt.Errorf("字段 %s 未找到", key)
		}

		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				field.Set(reflect.New(field.Type().Elem()))
			}
			field = field.Elem()
		}

		v = field
	}

	// 设置最后一个字段的值
	lastKey := keys[len(keys)-1]
	field := findFieldByJSONTag(v, lastKey)
	if !field.IsValid() {
		return fmt.Errorf("字段 %s 未找到", lastKey)
	}

	if !field.CanSet() {
		return fmt.Errorf("字段 %s 无法设置", lastKey)
	}

	// 根据字段类型转换值
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("无效的整数值: %s", value)
		}
		field.SetInt(intVal)
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("无效的布尔值: %s", value)
		}
		field.SetBool(boolVal)
	default:
		return fmt.Errorf("不支持的类型: %s", field.Kind())
	}

	return nil
}

// 实现 list.Item 接口
func (i configItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i configItem) Title() string {
	return i.key
}

func (i configItem) Description() string {
	return i.value
}

