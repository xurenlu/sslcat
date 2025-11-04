package ui

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type statusModel struct {
	config     *config.Config
	configFile string
	width      int
	height     int
}

func NewStatusModel(cfg *config.Config, configFile string) statusModel {
	return statusModel{
		config:     cfg,
		configFile: configFile,
	}
}

func (m statusModel) Init() tea.Cmd {
	return nil
}

func (m statusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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

func (m statusModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	// 标题
	title := titleStyle.Render("状态监控")

	// 系统信息
	systemInfo := m.renderSystemInfo()

	// 配置信息
	configInfo := m.renderConfigInfo()

	// 统计信息
	statsInfo := m.renderStatsInfo()

	// 帮助信息
	help := renderHelp(map[string]string{
		"q/Esc": "返回",
	})

	// 组合内容
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		"",
		systemInfo,
		"",
		configInfo,
		"",
		statsInfo,
		"",
		help,
	)

	// 限制宽度
	maxWidth := m.width - 4
	if maxWidth > 100 {
		maxWidth = 100
	}

	box := lipgloss.NewStyle().
		Width(maxWidth).
		Render(content)

	return box
}

func (m statusModel) renderSystemInfo() string {
	// 检查配置文件是否存在
	configExists := "✅"
	configStat, err := os.Stat(m.configFile)
	if err != nil {
		configExists = "❌"
	}

	configModTime := "未知"
	if configStat != nil {
		configModTime = configStat.ModTime().Format("2006-01-02 15:04:05")
	}

	info := []string{
		fmt.Sprintf("Go 版本: %s", runtime.Version()),
		fmt.Sprintf("操作系统: %s/%s", runtime.GOOS, runtime.GOARCH),
		fmt.Sprintf("配置文件: %s %s", m.configFile, configExists),
		fmt.Sprintf("最后修改: %s", configModTime),
	}

	return renderBox("系统信息", strings.Join(info, "\n"), m.width)
}

func (m statusModel) renderConfigInfo() string {
	if m.config == nil {
		return renderBox("配置信息", "❌ 配置未加载", m.width)
	}

	// 验证配置
	validationResult := "✅ 有效"
	if err := m.config.Validate(); err != nil {
		validationResult = fmt.Sprintf("❌ %v", err)
	}

	info := []string{
		fmt.Sprintf("配置验证: %s", validationResult),
		fmt.Sprintf("服务器地址: %s", m.config.Server.Host),
		fmt.Sprintf("服务器端口: %d", m.config.Server.Port),
		fmt.Sprintf("端口模式: %s", m.config.Server.PortMode),
		fmt.Sprintf("HTTPS: %v", m.config.Server.EnableHTTPS),
		fmt.Sprintf("SSL 邮箱: %s", m.config.SSL.Email),
		fmt.Sprintf("SSL 测试环境: %v", m.config.SSL.Staging),
		fmt.Sprintf("管理面板前缀: %s", m.config.AdminPrefix),
	}

	return renderBox("配置信息", strings.Join(info, "\n"), m.width)
}

func (m statusModel) renderStatsInfo() string {
	if m.config == nil {
		return renderBox("统计信息", "❌ 配置未加载", m.width)
	}

	// 代理规则统计
	proxyRulesCount := len(m.config.Proxy.Rules)
	enabledProxyRules := 0
	for _, rule := range m.config.Proxy.Rules {
		if rule.Enabled {
			enabledProxyRules++
		}
	}

	// SSL 证书统计（从证书目录读取）
	certCount := 0
	certDir := m.config.SSL.CertDir
	if certDir == "" {
		certDir = "./data/certs"
	}

	if entries, err := os.ReadDir(certDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".crt") {
				certCount++
			}
		}
	}

	// 静态站点和 PHP 站点统计
	staticSitesCount := len(m.config.StaticSites)
	phpSitesCount := len(m.config.PHPSites)

	info := []string{
		fmt.Sprintf("代理规则总数: %d", proxyRulesCount),
		fmt.Sprintf("启用的代理规则: %d", enabledProxyRules),
		fmt.Sprintf("SSL 证书数量: %d", certCount),
		fmt.Sprintf("静态站点数量: %d", staticSitesCount),
		fmt.Sprintf("PHP 站点数量: %d", phpSitesCount),
		fmt.Sprintf("安全功能 (WAF): %v", m.config.Security.EnableWAF),
		fmt.Sprintf("安全功能 (DDoS): %v", m.config.Security.EnableDDOS),
		fmt.Sprintf("CDN 缓存: %v", m.config.CDNCache.Enabled),
	}

	return renderBox("统计信息", strings.Join(info, "\n"), m.width)
}

