package ui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type slowRequestsModel struct {
	config     *config.Config
	configFile string
	width      int
	height     int
}

func NewSlowRequestsModel(cfg *config.Config, configFile string) slowRequestsModel {
	return slowRequestsModel{
		config:     cfg,
		configFile: configFile,
	}
}

func (m slowRequestsModel) Init() tea.Cmd {
	return nil
}

func (m slowRequestsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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

func (m slowRequestsModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("慢请求分析")

	logPath := m.config.Server.AccessLogPath
	if logPath == "" {
		logPath = "./data/access.log"
	}

	info := []string{
		"访问日志路径: " + logPath,
		"",
		"提示: 慢请求分析功能需要从访问日志中读取数据。",
		"当前版本仅显示日志文件信息。",
	}

	if stat, err := os.Stat(logPath); err == nil {
		info = append(info, "")
		info = append(info, fmt.Sprintf("文件大小: %d 字节", stat.Size()))
		info = append(info, fmt.Sprintf("最后修改: %s", stat.ModTime().Format("2006-01-02 15:04:05")))
	} else {
		info = append(info, "")
		info = append(info, "日志文件不存在")
	}

	contentBox := renderBox("慢请求日志", strings.Join(info, "\n"), m.width)

	help := renderHelp(map[string]string{
		"q/Esc": "返回",
	})

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		"",
		contentBox,
		"",
		help,
	)

	box := lipgloss.NewStyle().
		Width(m.width - 4).
		MaxWidth(m.width - 4).
		Render(content)

	return box
}

