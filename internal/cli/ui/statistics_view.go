package ui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type statisticsModel struct {
	config     *config.Config
	configFile string
	width      int
	height     int
}

func NewStatisticsModel(cfg *config.Config, configFile string) statisticsModel {
	return statisticsModel{
		config:     cfg,
		configFile: configFile,
	}
}

func (m statisticsModel) Init() tea.Cmd {
	return nil
}

func (m statisticsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m statisticsModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("访问统计")

	// 读取访问日志统计信息
	stats := m.getStatistics()

	help := renderHelp(map[string]string{
		"q/Esc": "返回",
	})

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		"",
		stats,
		"",
		help,
	)

	box := lipgloss.NewStyle().
		Width(m.width - 4).
		MaxWidth(m.width - 4).
		Render(content)

	return box
}

func (m statisticsModel) getStatistics() string {
	logPath := m.config.Server.AccessLogPath
	if logPath == "" {
		logPath = "./data/access.log"
	}

	info := []string{
		"访问日志路径: " + logPath,
	}

	// 检查日志文件是否存在
	if stat, err := os.Stat(logPath); err == nil {
		info = append(info, fmt.Sprintf("文件大小: %d 字节", stat.Size()))
		info = append(info, fmt.Sprintf("最后修改: %s", stat.ModTime().Format("2006-01-02 15:04:05")))
	} else {
		info = append(info, "日志文件不存在")
	}

	// 代理规则统计
	info = append(info, "")
	info = append(info, fmt.Sprintf("代理规则总数: %d", len(m.config.Proxy.Rules)))
	enabledRules := 0
	for _, rule := range m.config.Proxy.Rules {
		if rule.Enabled {
			enabledRules++
		}
	}
	info = append(info, fmt.Sprintf("启用的规则: %d", enabledRules))

	return renderBox("统计信息", strings.Join(info, "\n"), m.width)
}

