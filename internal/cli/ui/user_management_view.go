package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type userManagementModel struct {
	config     *config.Config
	configFile string
	width      int
	height     int
}

func NewUserManagementModel(cfg *config.Config, configFile string) userManagementModel {
	return userManagementModel{
		config:     cfg,
		configFile: configFile,
	}
}

func (m userManagementModel) Init() tea.Cmd {
	return nil
}

func (m userManagementModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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

func (m userManagementModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("用户管理")

	info := []string{
		"管理用户名: " + m.config.Admin.Username,
		"密码文件: " + m.config.Admin.PasswordFile,
		fmt.Sprintf("TOTP 二次验证: %v", m.config.Admin.EnableTOTP),
		"",
		"提示: 用户管理功能需要修改配置文件或使用命令行工具。",
		"当前版本仅显示管理用户信息。",
	}

	contentBox := renderBox("用户信息", strings.Join(info, "\n"), m.width)

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

