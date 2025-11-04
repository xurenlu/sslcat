package cli

import (
	"fmt"
	"strings"

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
	
	// 当前子视图模型
	currentViewModel tea.Model
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
		if m.currentViewModel != nil {
			updated, cmd := m.currentViewModel.Update(msg)
			// 确保 updated 不为 nil
			if updated != nil {
				m.currentViewModel = updated
				return m, cmd
			}
			// 如果 updated 为 nil，清除子视图
			m.currentViewModel = nil
			m.currentView = ""
		}
		updatedMenu, cmd := m.menuModel.Update(msg)
		if menuModel, ok := updatedMenu.(ui.MenuModel); ok {
			m.menuModel = menuModel
		}
		return m, cmd
		
	case BackToMenuMsg:
		// 接收到返回到主菜单的消息
		m.currentViewModel = nil
		m.currentView = ""
		m.menuModel = ui.NewMenuModel()
		return m, nil

	case tea.KeyMsg:
		// 如果当前有子视图，先让子视图处理
		if m.currentViewModel != nil {
			// 检查是否是退出键（q 或 esc）
			if msg.String() == "q" || msg.String() == "esc" {
				// 清除子视图，返回到主菜单
				m.currentViewModel = nil
				m.currentView = ""
				// 重新初始化菜单
				m.menuModel = ui.NewMenuModel()
				return m, nil
			}
			
			updated, cmd := m.currentViewModel.Update(msg)
			
			// 确保 updated 不为 nil
			if updated == nil {
				m.currentViewModel = nil
				m.currentView = ""
				m.menuModel = ui.NewMenuModel()
				return m, nil
			}
			
			// 检查子视图返回的命令是否是 tea.Quit
			if cmd != nil {
				// 尝试执行命令，检查是否是 QuitMsg
				cmdResult := cmd()
				if _, isQuit := cmdResult.(tea.QuitMsg); isQuit {
					// 子视图请求退出，但不退出程序，而是返回到主菜单
					m.currentViewModel = nil
					m.currentView = ""
					m.menuModel = ui.NewMenuModel()
					return m, nil
				}
			}
			
			// 更新子视图模型
			m.currentViewModel = updated
			return m, cmd
		}
		
		// 处理主菜单
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
	}

		updatedMenu, cmd := m.menuModel.Update(msg)
		if menuModel, ok := updatedMenu.(ui.MenuModel); ok {
			m.menuModel = menuModel
		}

		// 检查是否选择了菜单项
		selected := m.menuModel.GetSelected()
		if selected != "" {
			return m.handleMenuSelection(selected)
		}

		return m, cmd
	}

	// 如果没有当前视图，处理菜单消息
	if m.currentViewModel == nil {
		updatedMenu, cmd := m.menuModel.Update(msg)
		if menuModel, ok := updatedMenu.(ui.MenuModel); ok {
			m.menuModel = menuModel
		}
		return m, cmd
	}

	return m, nil
}

// View 渲染视图
func (m ConsoleModel) View() string {
	if m.currentViewModel != nil {
		// 使用安全的方式调用 View，捕获可能的 panic
		view := func() (result string) {
			defer func() {
				if r := recover(); r != nil {
					result = fmt.Sprintf("视图渲染错误: %v", r)
				}
			}()
			return m.currentViewModel.View()
		}()
		// 如果出错，返回错误信息并清除视图
		if strings.Contains(view, "视图渲染错误") {
			// 注意：这里不能直接修改 m，因为 View() 是值接收者
			// 需要在下一次 Update 时清除
			return view + "\n\n按任意键返回主菜单..."
		}
		return view
	}
		return m.menuModel.View()
	}

// BackToMenuMsg 返回到主菜单的消息
type BackToMenuMsg struct{}

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
	m.currentView = "status"
	viewModel := ui.NewStatusModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, _ := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
	} else {
		m.currentViewModel = viewModel
	}
	return m, nil
}

// runConfigView 运行配置管理视图
func (m ConsoleModel) runConfigView() (tea.Model, tea.Cmd) {
	m.currentView = "config"
	viewModel := ui.NewConfigModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runStatusView 运行状态监控视图（保留兼容）
func (m ConsoleModel) runStatusView() (tea.Model, tea.Cmd) {
	return m.runDashboardView()
}

// runProxyView 运行代理规则管理视图
func (m ConsoleModel) runProxyView() (tea.Model, tea.Cmd) {
	m.currentView = "proxy"
	viewModel := ui.NewProxyModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runSitesView 运行站点管理视图
func (m ConsoleModel) runSitesView() (tea.Model, tea.Cmd) {
	m.currentView = "sites"
	viewModel := ui.NewSitesModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runSSLView 运行 SSL 证书管理视图
func (m ConsoleModel) runSSLView() (tea.Model, tea.Cmd) {
	m.currentView = "ssl"
	viewModel := ui.NewSSLModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runDNSView 运行 DNS 管理视图
func (m ConsoleModel) runDNSView() (tea.Model, tea.Cmd) {
	m.currentView = "dns"
	viewModel := ui.NewDNSModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runSecurityView 运行安全设置视图
func (m ConsoleModel) runSecurityView() (tea.Model, tea.Cmd) {
	m.currentView = "security"
	viewModel := ui.NewSecurityModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runSettingsView 运行系统设置视图
func (m ConsoleModel) runSettingsView() (tea.Model, tea.Cmd) {
	m.currentView = "settings"
	viewModel := ui.NewSettingsModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runCDNView 运行 CDN 缓存管理视图
func (m ConsoleModel) runCDNView() (tea.Model, tea.Cmd) {
	m.currentView = "cdn"
	viewModel := ui.NewCDNModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runStatisticsView 运行访问统计视图
func (m ConsoleModel) runStatisticsView() (tea.Model, tea.Cmd) {
	m.currentView = "statistics"
	viewModel := ui.NewStatisticsModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runSlowRequestsView 运行慢请求分析视图
func (m ConsoleModel) runSlowRequestsView() (tea.Model, tea.Cmd) {
	m.currentView = "slowrequests"
	viewModel := ui.NewSlowRequestsModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runNotificationsView 运行通知管理视图
func (m ConsoleModel) runNotificationsView() (tea.Model, tea.Cmd) {
	m.currentView = "notifications"
	viewModel := ui.NewNotificationsModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runClusterView 运行集群管理视图
func (m ConsoleModel) runClusterView() (tea.Model, tea.Cmd) {
	m.currentView = "cluster"
	viewModel := ui.NewClusterModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runAISecurityView 运行 AI 安全分析视图
func (m ConsoleModel) runAISecurityView() (tea.Model, tea.Cmd) {
	m.currentView = "aisecurity"
	viewModel := ui.NewAISecurityModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runImageOptimizationView 运行图片优化视图
func (m ConsoleModel) runImageOptimizationView() (tea.Model, tea.Cmd) {
	m.currentView = "imageoptimization"
	viewModel := ui.NewImageOptimizationModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

// runUserManagementView 运行用户管理视图
func (m ConsoleModel) runUserManagementView() (tea.Model, tea.Cmd) {
	m.currentView = "usermanagement"
	viewModel := ui.NewUserManagementModel(m.config, m.configFile)
	// 如果窗口大小已设置，立即更新子视图
	if m.width > 0 && m.height > 0 {
		updated, cmd := viewModel.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.currentViewModel = updated
		return m, cmd
	}
	m.currentViewModel = viewModel
	return m, nil
}

