package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type dnsModel struct {
	config     *config.Config
	configFile string
	list       list.Model
	width      int
	height     int
	message    string
}

type dnsProviderItem struct {
	provider *config.DNSProvider
	index    int
}

func NewDNSModel(cfg *config.Config, configFile string) dnsModel {
	items := make([]list.Item, len(cfg.SSL.DNSProviders))
	for i := range cfg.SSL.DNSProviders {
		items[i] = dnsProviderItem{
			provider: &cfg.SSL.DNSProviders[i],
			index:    i,
		}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "DNS 服务商"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	return dnsModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
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
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "esc":
			if m.message != "" {
				m.message = ""
				return m, nil
			}
			return m, tea.Quit

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

func (m dnsModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("DNS 管理")

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
		"↑↓/jk": "移动",
		"s":     "保存配置",
		"q/Esc": "返回",
	})

	content := lipgloss.JoinVertical(
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

	box := lipgloss.NewStyle().
		Width(m.width - 4).
		MaxWidth(m.width - 4).
		Render(content)

	return box
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

