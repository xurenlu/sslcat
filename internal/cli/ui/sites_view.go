package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type sitesModel struct {
	config     *config.Config
	configFile string
	list       list.Model
	siteType   string // "static" 或 "php"
	width      int
	height     int
	message    string
}

type siteItem struct {
	site      interface{} // *StaticSite 或 *PHPSite
	siteType  string
	index     int
	isStatic  bool
}

func NewSitesModel(cfg *config.Config, configFile string) sitesModel {
	// 合并静态站点和PHP站点
	var items []list.Item
	if cfg != nil {
		for i := range cfg.StaticSites {
			items = append(items, siteItem{
				site:     &cfg.StaticSites[i],
				siteType: "static",
				index:    i,
				isStatic: true,
			})
		}
		for i := range cfg.PHPSites {
			items = append(items, siteItem{
				site:     &cfg.PHPSites[i],
				siteType: "php",
				index:    i,
				isStatic: false,
			})
		}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "站点管理"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	return sitesModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
	}
}

func (m sitesModel) Init() tea.Cmd {
	return nil
}

func (m sitesModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			// 注意：sites_view 目前没有编辑模式，所以直接保存
			// 如果将来添加编辑功能，需要在这里添加检查
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

func (m sitesModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("站点管理")

	listView := m.list.View()
	messageView := ""
	if m.message != "" {
		if strings.HasPrefix(m.message, "❌") {
			messageView = errorStyle.Render(m.message)
		} else {
			messageView = successStyle.Render(m.message)
		}
	}

	var info []string
	if m.config != nil {
		info = []string{
			fmt.Sprintf("静态站点数量: %d", len(m.config.StaticSites)),
			fmt.Sprintf("PHP 站点数量: %d", len(m.config.PHPSites)),
		}
	} else {
		info = []string{
			"静态站点数量: 0",
			"PHP 站点数量: 0",
		}
	}
	infoBox := renderBox("站点统计", strings.Join(info, "\n"), m.width)

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
func (i siteItem) FilterValue() string {
	if i.isStatic {
		site := i.site.(*config.StaticSite)
		return site.Domain + " " + site.Root + " " + i.siteType
	}
	site := i.site.(*config.PHPSite)
	return site.Domain + " " + site.Root + " " + i.siteType
}

func (i siteItem) Title() string {
	status := "❌"
	var domain string
	if i.isStatic {
		site := i.site.(*config.StaticSite)
		domain = site.Domain
		if site.Enabled {
			status = "✅"
		}
	} else {
		site := i.site.(*config.PHPSite)
		domain = site.Domain
		if site.Enabled {
			status = "✅"
		}
	}
	return fmt.Sprintf("%s %s [%s]", status, domain, strings.ToUpper(i.siteType))
}

func (i siteItem) Description() string {
	if i.isStatic {
		site := i.site.(*config.StaticSite)
		return fmt.Sprintf("根目录: %s | 索引: %s", site.Root, site.Index)
	}
	site := i.site.(*config.PHPSite)
	return fmt.Sprintf("根目录: %s | FCGI: %s", site.Root, site.FCGIAddr)
}

