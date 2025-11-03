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

type dnsModel struct {
	config     *config.Config
	configFile string
	list       list.Model
	editing    bool
	adding     bool
	formInputs []textinput.Model
	formIndex  int
	editingIndex int // -1 表示添加新服务商
	width      int
	height     int
	message    string
}

type dnsProviderItem struct {
	provider *config.DNSProvider
	index    int
}

func NewDNSModel(cfg *config.Config, configFile string) dnsModel {
	var items []list.Item
	if cfg != nil && cfg.SSL.DNSProviders != nil {
		items = make([]list.Item, len(cfg.SSL.DNSProviders))
		for i := range cfg.SSL.DNSProviders {
			items[i] = dnsProviderItem{
				provider: &cfg.SSL.DNSProviders[i],
				index:    i,
			}
		}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "DNS 服务商"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	// 初始化表单输入框
	formInputs := []textinput.Model{
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
	}

	formInputs[0].Placeholder = "服务商名称 (例如: Cloudflare)"
	formInputs[1].Placeholder = "类型 (cloudflare/aliyun/tencent/aws/godaddy/custom)"
	formInputs[2].Placeholder = "API Key"
	formInputs[3].Placeholder = "API Secret (可选)"
	formInputs[4].Placeholder = "Zone ID (可选)"
	formInputs[5].Placeholder = "Endpoint (可选)"
	formInputs[6].Placeholder = "优先级 (数字越小优先级越高，默认: 0)"
	formInputs[7].Placeholder = "启用 (true/false)"

	return dnsModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
		formInputs: formInputs,
		editingIndex: -1,
	}
}

func (m dnsModel) Init() tea.Cmd {
	return nil
}

func (m dnsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				// 保存服务商
				if err := m.saveProvider(); err != nil {
					m.message = fmt.Sprintf("❌ 错误: %v", err)
					return m, nil
				}
				m.editing = false
				m.adding = false
				m.resetForm()
				// 重新构建列表
				m.refreshList()
				m.message = "✅ DNS 服务商已保存"
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
			// 添加新服务商
			m.adding = true
			m.editingIndex = -1
			m.resetForm()
			m.formInputs[0].Focus()
			m.formIndex = 0
			return m, textinput.Blink

		case "e":
			// 编辑选中的服务商
			selected := m.list.SelectedItem()
			if selected != nil {
				item := selected.(dnsProviderItem)
				m.editing = true
				m.editingIndex = item.index
				m.loadProviderToForm(item.provider)
				m.formInputs[0].Focus()
				m.formIndex = 0
				return m, textinput.Blink
			}

		case "d":
			// 删除选中的服务商
			selected := m.list.SelectedItem()
			if selected != nil && m.config != nil {
				item := selected.(dnsProviderItem)
				if item.index >= 0 && item.index < len(m.config.SSL.DNSProviders) {
					m.config.SSL.DNSProviders = append(
						m.config.SSL.DNSProviders[:item.index],
						m.config.SSL.DNSProviders[item.index+1:]...,
					)
					m.refreshList()
					m.message = "✅ DNS 服务商已删除"
				}
			}
			return m, nil

		case "s":
			// 只有在非编辑模式下才保存
			if m.editing || m.adding {
				// 编辑模式下，将按键传递给输入框
				var cmd tea.Cmd
				m.formInputs[m.formIndex], cmd = m.formInputs[m.formIndex].Update(msg)
				return m, cmd
			}
			if m.config == nil {
				m.message = "❌ 配置未初始化"
				return m, nil
			}
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

func (m dnsModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("DNS 管理")

	var content string
	if m.editing || m.adding {
		// 编辑/添加模式
		mode := "添加"
		if m.editing {
			mode = "编辑"
		}
		formTitle := fmt.Sprintf("%s DNS 服务商", mode)

		var formFields []string
		labels := []string{
			"服务商名称:",
			"类型:",
			"API Key:",
			"API Secret:",
			"Zone ID:",
			"Endpoint:",
			"优先级:",
			"启用:",
		}

		for i, label := range labels {
			style := normalStyle
			if i == m.formIndex {
				style = selectedStyle
			}
			formFields = append(formFields, style.Render(fmt.Sprintf("%s %s", label, m.formInputs[i].View())))
		}

		help := renderHelp(map[string]string{
			"Tab/Shift+Tab": "切换字段",
			"Enter":         "保存",
			"Esc":           "取消",
		})

		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			formTitle,
			"",
			strings.Join(formFields, "\n"),
			"",
			help,
		)
	} else {
		// 列表模式
		listView := m.list.View()
		messageView := ""
		if m.message != "" {
			if strings.HasPrefix(m.message, "❌") {
				messageView = errorStyle.Render(m.message)
			} else {
				messageView = successStyle.Render(m.message)
			}
		}

		info := []string{
			fmt.Sprintf("DNS 服务商数量: %d", len(m.config.SSL.DNSProviders)),
			fmt.Sprintf("默认服务商: %s", m.config.SSL.DefaultDNSProvider),
		}
		infoBox := renderBox("DNS 配置信息", strings.Join(info, "\n"), m.width)

		help := renderHelp(map[string]string{
			"↑↓/jk":  "移动",
			"a":      "添加服务商",
			"e":      "编辑服务商",
			"d":      "删除服务商",
			"s":      "保存配置",
			"q/Esc":  "返回",
		})

		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			infoBox,
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

func (m *dnsModel) resetForm() {
	for i := range m.formInputs {
		m.formInputs[i].SetValue("")
		m.formInputs[i].Blur()
	}
	m.formIndex = 0
}

func (m *dnsModel) loadProviderToForm(provider *config.DNSProvider) {
	m.formInputs[0].SetValue(provider.Name)
	m.formInputs[1].SetValue(provider.Type)
	m.formInputs[2].SetValue(provider.APIKey)
	m.formInputs[3].SetValue(provider.APISecret)
	m.formInputs[4].SetValue(provider.ZoneID)
	m.formInputs[5].SetValue(provider.Endpoint)
	m.formInputs[6].SetValue(strconv.Itoa(provider.Priority))
	m.formInputs[7].SetValue(strconv.FormatBool(provider.Enabled))
}

func (m *dnsModel) saveProvider() error {
	if m.config == nil {
		return fmt.Errorf("配置未初始化")
	}

	name := strings.TrimSpace(m.formInputs[0].Value())
	typeStr := strings.TrimSpace(m.formInputs[1].Value())
	apiKey := strings.TrimSpace(m.formInputs[2].Value())
	apiSecret := strings.TrimSpace(m.formInputs[3].Value())
	zoneID := strings.TrimSpace(m.formInputs[4].Value())
	endpoint := strings.TrimSpace(m.formInputs[5].Value())
	priorityStr := strings.TrimSpace(m.formInputs[6].Value())
	enabledStr := strings.TrimSpace(m.formInputs[7].Value())

	if name == "" {
		return fmt.Errorf("服务商名称不能为空")
	}
	if typeStr == "" {
		return fmt.Errorf("类型不能为空")
	}

	priority := 0
	if priorityStr != "" {
		var err error
		priority, err = strconv.Atoi(priorityStr)
		if err != nil {
			return fmt.Errorf("优先级必须是数字: %v", err)
		}
	}

	enabled := true
	if enabledStr != "" {
		var err error
		enabled, err = strconv.ParseBool(enabledStr)
		if err != nil {
			return fmt.Errorf("启用值必须是 true 或 false: %v", err)
		}
	}

	provider := config.DNSProvider{
		Name:      name,
		Type:      typeStr,
		APIKey:    apiKey,
		APISecret: apiSecret,
		ZoneID:    zoneID,
		Endpoint:  endpoint,
		Priority:  priority,
		Enabled:   enabled,
	}

	if m.editingIndex >= 0 && m.editingIndex < len(m.config.SSL.DNSProviders) {
		// 编辑现有服务商
		m.config.SSL.DNSProviders[m.editingIndex] = provider
	} else {
		// 添加新服务商
		if m.config.SSL.DNSProviders == nil {
			m.config.SSL.DNSProviders = []config.DNSProvider{}
		}
		m.config.SSL.DNSProviders = append(m.config.SSL.DNSProviders, provider)
	}

	return nil
}

func (m *dnsModel) refreshList() {
	var items []list.Item
	if m.config != nil && m.config.SSL.DNSProviders != nil {
		items = make([]list.Item, len(m.config.SSL.DNSProviders))
		for i := range m.config.SSL.DNSProviders {
			items[i] = dnsProviderItem{
				provider: &m.config.SSL.DNSProviders[i],
				index:    i,
			}
		}
	}
	m.list.SetItems(items)
}

// 实现 list.Item 接口
func (i dnsProviderItem) FilterValue() string {
	return i.provider.Name + " " + i.provider.Type
}

func (i dnsProviderItem) Title() string {
	status := "❌"
	if i.provider.Enabled {
		status = "✅"
	}
	return fmt.Sprintf("%s %s (%s)", status, i.provider.Name, i.provider.Type)
}

func (i dnsProviderItem) Description() string {
	parts := []string{}
	if i.provider.APIKey != "" {
		parts = append(parts, "API Key: ***")
	}
	if i.provider.ZoneID != "" {
		parts = append(parts, fmt.Sprintf("Zone ID: %s", i.provider.ZoneID))
	}
	if i.provider.Priority > 0 {
		parts = append(parts, fmt.Sprintf("优先级: %d", i.provider.Priority))
	}
	return strings.Join(parts, " | ")
}

