package cli

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/xurenlu/sslcat/internal/cli/ui"
	"github.com/xurenlu/sslcat/internal/config"
)

// ConsoleModel 控制台主模型
type ConsoleModel struct {
	config      *config.Config
	configFile  string
	currentView string
	menuModel   ui.MenuModel
	width       int
	height      int
}

// RunConsole 启动控制台
func RunConsole(cfg *config.Config, configFile string) error {
	// 创建初始模型
	model := ConsoleModel{
		config:     cfg,
		configFile: configFile,
		menuModel:  ui.NewMenuModel(),
	}

	// 启动 bubbletea 程序
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("启动控制台失败: %w", err)
	}

	return nil
}

// Init 初始化模型
func (m ConsoleModel) Init() tea.Cmd {
	return nil
}

// Update 更新模型
func (m ConsoleModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	// 如果没有当前视图，显示菜单
	if m.currentView == "" {
		updatedMenu, cmd := m.menuModel.Update(msg)
		
		menuModel, ok := updatedMenu.(ui.MenuModel)
		if ok {
			m.menuModel = menuModel
		}

		// 检查是否选择了菜单项
		selected := m.menuModel.GetSelected()
		if selected != "" {
			return m.handleMenuSelection(selected)
		}

		return m, cmd
	}

	return m, nil
}

// View 渲染视图
func (m ConsoleModel) View() string {
	if m.currentView == "" {
		return m.menuModel.View()
	}

	return ""
}

// handleMenuSelection 处理菜单选择
func (m ConsoleModel) handleMenuSelection(selected string) (tea.Model, tea.Cmd) {
	switch selected {
	case "仪表盘":
		return m.runDashboardView()

	case "配置管理":
		return m.runConfigView()

	case "状态监控":
		return m.runStatusView()

	case "代理规则管理":
		return m.runProxyView()

	case "站点管理":
		return m.runSitesView()

	case "SSL证书管理":
		return m.runSSLView()

	case "DNS管理":
		return m.runDNSView()

	case "安全设置":
		return m.runSecurityView()

	case "系统设置":
		return m.runSettingsView()

	case "CDN缓存管理":
		return m.runCDNView()

	case "访问统计":
		return m.runStatisticsView()

	case "慢请求分析":
		return m.runSlowRequestsView()

	case "通知管理":
		return m.runNotificationsView()

	case "集群管理":
		return m.runClusterView()

	case "AI安全分析":
		return m.runAISecurityView()

	case "图片优化":
		return m.runImageOptimizationView()

	case "用户管理":
		return m.runUserManagementView()

	case "退出", "exit":
		return m, tea.Quit

	default:
		return m, nil
	}
}

// runDashboardView 运行仪表盘视图
func (m ConsoleModel) runDashboardView() (tea.Model, tea.Cmd) {
	statusModel := ui.NewStatusModel(m.config, m.configFile)
	p := tea.NewProgram(statusModel, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "仪表盘视图错误: %v\n", err)
	}
	return m, nil
}

// runConfigView 运行配置管理视图
func (m ConsoleModel) runConfigView() (tea.Model, tea.Cmd) {
	configModel := ui.NewConfigModel(m.config, m.configFile)
	p := tea.NewProgram(configModel, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "配置视图错误: %v\n", err)
	}
	return m, nil
}

// runStatusView 运行状态监控视图（保留兼容）
func (m ConsoleModel) runStatusView() (tea.Model, tea.Cmd) {
	return m.runDashboardView()
}

// runProxyView 运行代理规则管理视图
func (m ConsoleModel) runProxyView() (tea.Model, tea.Cmd) {
	proxyModel := ui.NewProxyModel(m.config, m.configFile)
	p := tea.NewProgram(proxyModel, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "代理视图错误: %v\n", err)
	}
	return m, nil
}

// runSitesView 运行站点管理视图
func (m ConsoleModel) runSitesView() (tea.Model, tea.Cmd) {
	// TODO: 实现站点管理视图
	fmt.Fprintf(os.Stderr, "站点管理功能开发中...\n")
	return m, nil
}

// runSSLView 运行 SSL 证书管理视图
func (m ConsoleModel) runSSLView() (tea.Model, tea.Cmd) {
	sslModel := ui.NewSSLModel(m.config, m.configFile)
	p := tea.NewProgram(sslModel, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "SSL视图错误: %v\n", err)
	}
	return m, nil
}

// runDNSView 运行 DNS 管理视图
func (m ConsoleModel) runDNSView() (tea.Model, tea.Cmd) {
	// TODO: 实现 DNS 管理视图
	fmt.Fprintf(os.Stderr, "DNS管理功能开发中...\n")
	return m, nil
}

// runSecurityView 运行安全设置视图
func (m ConsoleModel) runSecurityView() (tea.Model, tea.Cmd) {
	// TODO: 实现安全设置视图
	fmt.Fprintf(os.Stderr, "安全设置功能开发中...\n")
	return m, nil
}

// runSettingsView 运行系统设置视图
func (m ConsoleModel) runSettingsView() (tea.Model, tea.Cmd) {
	// TODO: 实现系统设置视图
	fmt.Fprintf(os.Stderr, "系统设置功能开发中...\n")
	return m, nil
}

// runCDNView 运行 CDN 缓存管理视图
func (m ConsoleModel) runCDNView() (tea.Model, tea.Cmd) {
	// TODO: 实现 CDN 缓存管理视图
	fmt.Fprintf(os.Stderr, "CDN缓存管理功能开发中...\n")
	return m, nil
}

// runStatisticsView 运行访问统计视图
func (m ConsoleModel) runStatisticsView() (tea.Model, tea.Cmd) {
	// TODO: 实现访问统计视图
	fmt.Fprintf(os.Stderr, "访问统计功能开发中...\n")
	return m, nil
}

// runSlowRequestsView 运行慢请求分析视图
func (m ConsoleModel) runSlowRequestsView() (tea.Model, tea.Cmd) {
	// TODO: 实现慢请求分析视图
	fmt.Fprintf(os.Stderr, "慢请求分析功能开发中...\n")
	return m, nil
}

// runNotificationsView 运行通知管理视图
func (m ConsoleModel) runNotificationsView() (tea.Model, tea.Cmd) {
	// TODO: 实现通知管理视图
	fmt.Fprintf(os.Stderr, "通知管理功能开发中...\n")
	return m, nil
}

// runClusterView 运行集群管理视图
func (m ConsoleModel) runClusterView() (tea.Model, tea.Cmd) {
	// TODO: 实现集群管理视图
	fmt.Fprintf(os.Stderr, "集群管理功能开发中...\n")
	return m, nil
}

// runAISecurityView 运行 AI 安全分析视图
func (m ConsoleModel) runAISecurityView() (tea.Model, tea.Cmd) {
	// TODO: 实现 AI 安全分析视图
	fmt.Fprintf(os.Stderr, "AI安全分析功能开发中...\n")
	return m, nil
}

// runImageOptimizationView 运行图片优化视图
func (m ConsoleModel) runImageOptimizationView() (tea.Model, tea.Cmd) {
	// TODO: 实现图片优化视图
	fmt.Fprintf(os.Stderr, "图片优化功能开发中...\n")
	return m, nil
}

// runUserManagementView 运行用户管理视图
func (m ConsoleModel) runUserManagementView() (tea.Model, tea.Cmd) {
	// TODO: 实现用户管理视图
	fmt.Fprintf(os.Stderr, "用户管理功能开发中...\n")
	return m, nil
}

