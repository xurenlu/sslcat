package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

// proxyAdvancedModel 代理规则高级配置模型
type proxyAdvancedModel struct {
	config        *config.Config
	configFile    string
	rule          *config.ProxyRule
	editingIndex  int // -1 表示添加新规则
	step          int // 当前步骤：0=基础, 1=后端, 2=负载均衡, 3=健康检查, 4=会话保持, 5=故障转移, 6=高级选项
	message       string
	width         int
	height        int

	// 基础配置输入框
	domainInput      textinput.Model
	enabledInput     textinput.Model
	sslOnlyInput     textinput.Model
	
	// 后端列表
	backendMgr *backendManager
	
	// 负载均衡配置
	lbAlgorithmInput textinput.Model
	
	// 健康检查配置
	healthCheckEnabledInput textinput.Model
	healthCheckPathInput    textinput.Model
	healthCheckIntervalInput textinput.Model
	healthCheckTimeoutInput  textinput.Model
	healthCheckMethodInput   textinput.Model
	expectedStatusCodeInput  textinput.Model
	
	// 会话保持配置
	sessionAffinityEnabledInput textinput.Model
	sessionAffinityMethodInput   textinput.Model
	sessionAffinityCookieInput    textinput.Model
	sessionAffinityTTLInput       textinput.Model
	
	// 故障转移配置
	failoverEnabledInput     textinput.Model
	maxRetriesInput          textinput.Model
	retryIntervalInput       textinput.Model
	failureThresholdInput    textinput.Model
	recoveryThresholdInput   textinput.Model
	
	// 高级选项
	optimizeHostHeaderInput textinput.Model
	cdnEnabledInput         textinput.Model
	cdnPresetInput          textinput.Model
	cdnTTLInput             textinput.Model
	websocketOptimizedInput textinput.Model
	
	// 路径前缀规则管理器
	pathPrefixRuleMgr *pathPrefixRuleManager
	
	// 自定义头部管理器
	headersMgr *headersManager
	
	// 访问控制管理器
	authMgr *authManager
	
	// 简单路径前缀配置
	pathPrefixesInput textinput.Model
	pathExactInput    textinput.Model
	
	// 代理超时配置
	connectTimeoutInput        textinput.Model
	keepAliveTimeoutInput      textinput.Model
	idleTimeoutInput           textinput.Model
	tlsHandshakeTimeoutInput   textinput.Model
	expectContinueTimeoutInput textinput.Model
	healthCheckTimeoutSecInput textinput.Model
	
	// WebSocket 详细配置
	websocketBufferSizeInput textinput.Model
	websocketReadTimeoutInput textinput.Model
	websocketWriteTimeoutInput textinput.Model
	websocketPingIntervalInput textinput.Model
	websocketTimeoutInput     textinput.Model
	
	// 性能监控配置
	enableTracingInput textinput.Model
	enableMetricsInput textinput.Model
}

// 步骤名称
var proxySteps = []string{
	"基础配置",
	"后端服务器",
	"负载均衡",
	"健康检查",
	"会话保持",
	"故障转移",
	"高级选项",
	"路径前缀规则",
	"自定义头部",
	"访问控制",
}

func NewProxyAdvancedModel(cfg *config.Config, configFile string, rule *config.ProxyRule, editingIndex int) proxyAdvancedModel {
	m := proxyAdvancedModel{
		config:       cfg,
		configFile:   configFile,
		rule:         rule,
		editingIndex: editingIndex,
		step:         0,
	}

	// 初始化基础配置输入框
	m.domainInput = textinput.New()
	m.domainInput.Placeholder = "域名 (例如: example.com)"
	m.domainInput.Focus()

	m.enabledInput = textinput.New()
	m.enabledInput.Placeholder = "启用 (true/false)"

	m.sslOnlyInput = textinput.New()
	m.sslOnlyInput.Placeholder = "SSL Only (true/false)"

	// 初始化负载均衡配置
	m.lbAlgorithmInput = textinput.New()
	m.lbAlgorithmInput.Placeholder = "算法 (round_robin/weighted_round_robin/least_conn/ip_hash/random/consistent_hash)"

	// 初始化健康检查配置
	m.healthCheckEnabledInput = textinput.New()
	m.healthCheckPathInput = textinput.New()
	m.healthCheckIntervalInput = textinput.New()
	m.healthCheckTimeoutInput = textinput.New()
	m.healthCheckMethodInput = textinput.New()
	m.expectedStatusCodeInput = textinput.New()

	// 初始化会话保持配置
	m.sessionAffinityEnabledInput = textinput.New()
	m.sessionAffinityMethodInput = textinput.New()
	m.sessionAffinityCookieInput = textinput.New()
	m.sessionAffinityTTLInput = textinput.New()

	// 初始化故障转移配置
	m.failoverEnabledInput = textinput.New()
	m.maxRetriesInput = textinput.New()
	m.retryIntervalInput = textinput.New()
	m.failureThresholdInput = textinput.New()
	m.recoveryThresholdInput = textinput.New()

	// 初始化高级选项
	m.optimizeHostHeaderInput = textinput.New()
	m.cdnEnabledInput = textinput.New()
	m.cdnPresetInput = textinput.New()
	m.cdnTTLInput = textinput.New()
	m.websocketOptimizedInput = textinput.New()

	// 加载规则数据
	m.loadRule()

	return m
}

func (m proxyAdvancedModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m proxyAdvancedModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.backendMgr != nil {
			m.backendMgr.Update(msg, m.width, m.height)
		}
		if m.pathPrefixRuleMgr != nil {
			m.pathPrefixRuleMgr.Update(msg, m.width, m.height)
		}
		if m.headersMgr != nil {
			m.headersMgr.Update(msg, m.width, m.height)
		}
		return m, nil

	case tea.KeyMsg:
		// 处理步骤导航
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "esc":
			if m.backendMgr != nil && m.backendMgr.editing {
				m.backendMgr.editing = false
				return m, nil
			}
			if m.pathPrefixRuleMgr != nil && m.pathPrefixRuleMgr.editing {
				m.pathPrefixRuleMgr.editing = false
				return m, nil
			}
			if m.headersMgr != nil && m.headersMgr.editing {
				m.headersMgr.editing = false
				return m, nil
			}
			if m.authMgr != nil && m.authMgr.editing {
				m.authMgr.editing = false
				return m, nil
			}
			return m, tea.Quit

		case "left", "h":
			if m.step > 0 && !(m.backendMgr != nil && m.backendMgr.editing) && !(m.pathPrefixRuleMgr != nil && m.pathPrefixRuleMgr.editing) && !(m.headersMgr != nil && m.headersMgr.editing) && !(m.authMgr != nil && m.authMgr.editing) {
				m.step--
				return m, nil
			}

		case "right", "l":
			if m.step < len(proxySteps)-1 && !(m.backendMgr != nil && m.backendMgr.editing) && !(m.pathPrefixRuleMgr != nil && m.pathPrefixRuleMgr.editing) && !(m.headersMgr != nil && m.headersMgr.editing) && !(m.authMgr != nil && m.authMgr.editing) {
				m.step++
				return m, nil
			}

		case "s":
			// 保存规则
			if err := m.saveRule(); err != nil {
				m.message = fmt.Sprintf("❌ 错误: %v", err)
				return m, nil
			}
			if err := m.config.Save(m.configFile); err != nil {
				m.message = fmt.Sprintf("❌ 保存失败: %v", err)
				return m, nil
			}
			m.message = "✅ 规则已保存"
			return m, tea.Quit
		}

		// 根据当前步骤处理输入
		return m.handleStepInput(msg)
	}

	return m, nil
}

func (m proxyAdvancedModel) handleStepInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.step {
	case 0: // 基础配置
		return m.handleBasicStep(msg)
	case 1: // 后端服务器
		return m.handleBackendStep(msg)
	case 2: // 负载均衡
		return m.handleLoadBalancerStep(msg)
	case 3: // 健康检查
		return m.handleHealthCheckStep(msg)
	case 4: // 会话保持
		return m.handleSessionAffinityStep(msg)
	case 5: // 故障转移
		return m.handleFailoverStep(msg)
	case 6: // 高级选项
		return m.handleAdvancedStep(msg)
	case 7: // 路径前缀规则
		return m.handlePathPrefixRulesStep(msg)
	case 8: // 自定义头部
		return m.handleHeadersStep(msg)
	case 9: // 访问控制
		return m.handleAuthStep(msg)
	}

	return m, nil
}

func (m proxyAdvancedModel) handleBasicStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "tab":
		// 切换到下一个输入框
		if m.domainInput.Focused() {
			m.domainInput.Blur()
			m.enabledInput.Focus()
			return m, textinput.Blink
		} else if m.enabledInput.Focused() {
			m.enabledInput.Blur()
			m.sslOnlyInput.Focus()
			return m, textinput.Blink
		} else {
			m.sslOnlyInput.Blur()
			m.domainInput.Focus()
			return m, textinput.Blink
		}
	}

	var cmd tea.Cmd
	if m.domainInput.Focused() {
		m.domainInput, cmd = m.domainInput.Update(msg)
	} else if m.enabledInput.Focused() {
		m.enabledInput, cmd = m.enabledInput.Update(msg)
	} else if m.sslOnlyInput.Focused() {
		m.sslOnlyInput, cmd = m.sslOnlyInput.Update(msg)
	} else {
		// 默认聚焦到域名输入框
		m.domainInput.Focus()
		m.domainInput, cmd = m.domainInput.Update(msg)
	}

	return m, cmd
}

func (m proxyAdvancedModel) handleBackendStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a":
		return m, m.backendMgr.handleAdd()

	case "e":
		return m, m.backendMgr.handleEdit()

	case "d":
		if err := m.backendMgr.handleDelete(); err != nil {
			m.message = fmt.Sprintf("❌ %v", err)
		} else {
			m.message = "✅ 后端已删除"
		}
		return m, nil
	}

	return m, m.backendMgr.Update(msg, m.width, m.height)
}

func (m proxyAdvancedModel) handleLoadBalancerStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.lbAlgorithmInput, cmd = m.lbAlgorithmInput.Update(msg)
	return m, cmd
}

func (m proxyAdvancedModel) handleHealthCheckStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// 切换输入框焦点
	if msg.String() == "tab" {
		// TODO: 实现 Tab 切换
	}

	var cmd tea.Cmd
	if m.healthCheckEnabledInput.Focused() {
		m.healthCheckEnabledInput, cmd = m.healthCheckEnabledInput.Update(msg)
	} else if m.healthCheckPathInput.Focused() {
		m.healthCheckPathInput, cmd = m.healthCheckPathInput.Update(msg)
	} else {
		m.healthCheckEnabledInput.Focus()
		m.healthCheckEnabledInput, cmd = m.healthCheckEnabledInput.Update(msg)
	}
	return m, cmd
}

func (m proxyAdvancedModel) handleSessionAffinityStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.sessionAffinityEnabledInput, cmd = m.sessionAffinityEnabledInput.Update(msg)
	return m, cmd
}

func (m proxyAdvancedModel) handleFailoverStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.failoverEnabledInput, cmd = m.failoverEnabledInput.Update(msg)
	return m, cmd
}

func (m proxyAdvancedModel) handleAdvancedStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.optimizeHostHeaderInput, cmd = m.optimizeHostHeaderInput.Update(msg)
	return m, cmd
}

func (m proxyAdvancedModel) handlePathPrefixRulesStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a":
		return m, m.pathPrefixRuleMgr.handleAdd()

	case "e":
		return m, m.pathPrefixRuleMgr.handleEdit()

	case "d":
		if err := m.pathPrefixRuleMgr.handleDelete(); err != nil {
			m.message = fmt.Sprintf("❌ %v", err)
		} else {
			m.message = "✅ 规则已删除"
		}
		return m, nil
	}

	return m, m.pathPrefixRuleMgr.Update(msg, m.width, m.height)
}

func (m proxyAdvancedModel) handleHeadersStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a":
		return m, m.headersMgr.handleAdd()

	case "e":
		return m, m.headersMgr.handleEdit()

	case "d":
		if err := m.headersMgr.handleDelete(); err != nil {
			m.message = fmt.Sprintf("❌ %v", err)
		} else {
			m.message = "✅ 头部已删除"
		}
		return m, nil
	}

	return m, m.headersMgr.Update(msg, m.width, m.height)
}

func (m proxyAdvancedModel) handleAuthStep(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a":
		return m, m.authMgr.handleAdd()

	case "e":
		return m, m.authMgr.handleEdit()

	case "d":
		if err := m.authMgr.handleDelete(); err != nil {
			m.message = fmt.Sprintf("❌ %v", err)
		} else {
			m.message = "✅ 用户已删除"
		}
		return m, nil
	}

	// 处理访问控制配置输入
	var cmd tea.Cmd
	if m.authMgr.enabledInput.Focused() {
		m.authMgr.enabledInput, cmd = m.authMgr.enabledInput.Update(msg)
	} else if m.authMgr.timeoutInput.Focused() {
		m.authMgr.timeoutInput, cmd = m.authMgr.timeoutInput.Update(msg)
	} else if m.authMgr.cookieDomainInput.Focused() {
		m.authMgr.cookieDomainInput, cmd = m.authMgr.cookieDomainInput.Update(msg)
	} else {
		// 让 authManager 处理其他消息
		return m, m.authMgr.Update(msg, m.width, m.height)
	}

	return m, cmd
}

func (m proxyAdvancedModel) renderAuthStep() string {
	return m.authMgr.View()
}

func (m proxyAdvancedModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("代理规则高级配置")

	// 步骤导航
	stepNav := m.renderStepNavigation()

	// 当前步骤内容
	stepContent := m.renderCurrentStep()

	// 消息提示
	messageView := ""
	if m.message != "" {
		if strings.HasPrefix(m.message, "❌") {
			messageView = errorStyle.Render(m.message)
		} else {
			messageView = successStyle.Render(m.message)
		}
	}

	// 帮助信息
	help := renderHelp(map[string]string{
		"←→/hl":  "切换步骤",
		"Tab":    "切换输入框",
		"s":      "保存并退出",
		"q/Esc":  "退出",
	})

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		"",
		stepNav,
		"",
		stepContent,
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

func (m proxyAdvancedModel) renderStepNavigation() string {
	var steps []string
	for i, stepName := range proxySteps {
		style := normalStyle
		if i == m.step {
			style = selectedStyle
		}
		marker := " "
		if i == m.step {
			marker = "●"
		} else if i < m.step {
			marker = "✓"
		}
		steps = append(steps, style.Render(fmt.Sprintf("%s %s", marker, stepName)))
	}
	return strings.Join(steps, " | ")
}

func (m proxyAdvancedModel) renderCurrentStep() string {
	switch m.step {
	case 0:
		return m.renderBasicStep()
	case 1:
		return m.renderBackendStep()
	case 2:
		return m.renderLoadBalancerStep()
	case 3:
		return m.renderHealthCheckStep()
	case 4:
		return m.renderSessionAffinityStep()
	case 5:
		return m.renderFailoverStep()
	case 6:
		return m.renderAdvancedStep()
	case 7:
		return m.renderPathPrefixRulesStep()
	case 8:
		return m.renderHeadersStep()
	case 9:
		return m.renderAuthStep()
	}
	return ""
}

func (m proxyAdvancedModel) renderBasicStep() string {
	return lipgloss.JoinVertical(
		lipgloss.Left,
		subtitleStyle.Render("基础配置"),
		"",
		fmt.Sprintf("域名: %s", m.domainInput.View()),
		fmt.Sprintf("启用: %s", m.enabledInput.View()),
		fmt.Sprintf("SSL Only: %s", m.sslOnlyInput.View()),
	)
}

func (m proxyAdvancedModel) renderBackendStep() string {
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		subtitleStyle.Render("后端服务器配置"),
		"",
		m.backendMgr.View(),
		"",
		helpStyle.Render("a: 添加 | e: 编辑 | d: 删除"),
	)
	return content
}

func (m proxyAdvancedModel) renderLoadBalancerStep() string {
	backends := m.rule.GetEffectiveBackends()
	isLB := len(backends) > 1

	content := []string{
		subtitleStyle.Render("负载均衡配置"),
		"",
	}

	if !isLB {
		content = append(content, infoStyle.Render("提示: 当前只有1个后端服务器，无需负载均衡配置"))
		content = append(content, "添加更多后端服务器后，将自动启用负载均衡")
	} else {
		content = append(content, fmt.Sprintf("当前后端数量: %d", len(backends)))
		content = append(content, fmt.Sprintf("负载均衡算法: %s", m.lbAlgorithmInput.View()))
		content = append(content, "")
		content = append(content, infoStyle.Render("支持的算法: round_robin, weighted_round_robin, least_conn, ip_hash, random, consistent_hash"))
	}

	return strings.Join(content, "\n")
}

func (m proxyAdvancedModel) renderHealthCheckStep() string {
	content := []string{
		subtitleStyle.Render("健康检查配置"),
		"",
		fmt.Sprintf("启用: %s", m.healthCheckEnabledInput.View()),
		fmt.Sprintf("检查路径: %s", m.healthCheckPathInput.View()),
		fmt.Sprintf("检查间隔(秒): %s", m.healthCheckIntervalInput.View()),
		fmt.Sprintf("超时时间(秒): %s", m.healthCheckTimeoutInput.View()),
		fmt.Sprintf("HTTP方法: %s", m.healthCheckMethodInput.View()),
		fmt.Sprintf("期望状态码: %s", m.expectedStatusCodeInput.View()),
	}
	return strings.Join(content, "\n")
}

func (m proxyAdvancedModel) renderSessionAffinityStep() string {
	content := []string{
		subtitleStyle.Render("会话保持配置"),
		"",
		fmt.Sprintf("启用: %s", m.sessionAffinityEnabledInput.View()),
		fmt.Sprintf("方法: %s", m.sessionAffinityMethodInput.View()),
		fmt.Sprintf("Cookie名称: %s", m.sessionAffinityCookieInput.View()),
		fmt.Sprintf("TTL(秒): %s", m.sessionAffinityTTLInput.View()),
		"",
		infoStyle.Render("支持的方法: cookie, header, ip"),
	}
	return strings.Join(content, "\n")
}

func (m proxyAdvancedModel) renderFailoverStep() string {
	content := []string{
		subtitleStyle.Render("故障转移配置"),
		"",
		fmt.Sprintf("启用: %s", m.failoverEnabledInput.View()),
		fmt.Sprintf("最大重试次数: %s", m.maxRetriesInput.View()),
		fmt.Sprintf("重试间隔(秒): %s", m.retryIntervalInput.View()),
		fmt.Sprintf("故障阈值: %s", m.failureThresholdInput.View()),
		fmt.Sprintf("恢复阈值: %s", m.recoveryThresholdInput.View()),
	}
	return strings.Join(content, "\n")
}

func (m proxyAdvancedModel) renderAdvancedStep() string {
	content := []string{
		subtitleStyle.Render("高级选项"),
		"",
		"CDN 配置:",
		fmt.Sprintf("HTTP Host 头部优化: %s", m.optimizeHostHeaderInput.View()),
		fmt.Sprintf("CDN 启用: %s", m.cdnEnabledInput.View()),
		fmt.Sprintf("CDN 预设: %s", m.cdnPresetInput.View()),
		fmt.Sprintf("CDN TTL(秒): %s", m.cdnTTLInput.View()),
		"",
		"WebSocket 配置:",
		fmt.Sprintf("WebSocket 优化: %s", m.websocketOptimizedInput.View()),
		fmt.Sprintf("缓冲区大小: %s", m.websocketBufferSizeInput.View()),
		fmt.Sprintf("读取超时(秒): %s", m.websocketReadTimeoutInput.View()),
		fmt.Sprintf("写入超时(秒): %s", m.websocketWriteTimeoutInput.View()),
		fmt.Sprintf("心跳间隔(秒): %s", m.websocketPingIntervalInput.View()),
		fmt.Sprintf("连接总超时(秒): %s", m.websocketTimeoutInput.View()),
		"",
		"代理超时配置:",
		fmt.Sprintf("连接超时(秒): %s", m.connectTimeoutInput.View()),
		fmt.Sprintf("连接保持超时(秒): %s", m.keepAliveTimeoutInput.View()),
		fmt.Sprintf("空闲连接超时(秒): %s", m.idleTimeoutInput.View()),
		fmt.Sprintf("TLS握手超时(秒): %s", m.tlsHandshakeTimeoutInput.View()),
		fmt.Sprintf("Expect-Continue超时(秒): %s", m.expectContinueTimeoutInput.View()),
		fmt.Sprintf("健康检查超时(秒): %s", m.healthCheckTimeoutSecInput.View()),
		"",
		"性能监控:",
		fmt.Sprintf("请求追踪: %s", m.enableTracingInput.View()),
		fmt.Sprintf("指标收集: %s", m.enableMetricsInput.View()),
	}
	return strings.Join(content, "\n")
}

func (m proxyAdvancedModel) renderPathPrefixRulesStep() string {
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		subtitleStyle.Render("路径前缀规则"),
		"",
		m.pathPrefixRuleMgr.View(),
		"",
		helpStyle.Render("a: 添加 | e: 编辑 | d: 删除"),
	)
	return content
}

func (m proxyAdvancedModel) renderHeadersStep() string {
	return m.headersMgr.View()
}

func (m proxyAdvancedModel) loadRule() {
	if m.rule == nil {
		// 创建新规则
		m.rule = &config.ProxyRule{
			Domain:  "",
			Enabled: true,
			SSLOnly: false,
			Backends: []config.ProxyBackend{},
		}
		// 设置默认值
		m.domainInput.SetValue("")
		m.enabledInput.SetValue("true")
		m.sslOnlyInput.SetValue("false")
		m.lbAlgorithmInput.SetValue("round_robin")
		m.healthCheckEnabledInput.SetValue("false")
		m.healthCheckPathInput.SetValue("/health")
		m.healthCheckIntervalInput.SetValue("30")
		m.healthCheckTimeoutInput.SetValue("5")
		m.healthCheckMethodInput.SetValue("GET")
		m.expectedStatusCodeInput.SetValue("200")
		m.sessionAffinityEnabledInput.SetValue("false")
		m.sessionAffinityMethodInput.SetValue("cookie")
		m.sessionAffinityCookieInput.SetValue("")
		m.sessionAffinityTTLInput.SetValue("3600")
		m.failoverEnabledInput.SetValue("false")
		m.maxRetriesInput.SetValue("3")
		m.retryIntervalInput.SetValue("1")
		m.failureThresholdInput.SetValue("3")
		m.recoveryThresholdInput.SetValue("2")
		m.optimizeHostHeaderInput.SetValue("false")
		m.cdnEnabledInput.SetValue("false")
		m.cdnPresetInput.SetValue("none")
		m.cdnTTLInput.SetValue("0")
		m.websocketOptimizedInput.SetValue("true")
		m.pathPrefixRuleMgr = newPathPrefixRuleManager(m.rule)
		return
	}

	// 加载现有规则数据
	m.domainInput.SetValue(m.rule.Domain)
	m.enabledInput.SetValue(strconv.FormatBool(m.rule.Enabled))
	m.sslOnlyInput.SetValue(strconv.FormatBool(m.rule.SSLOnly))

	// 加载负载均衡配置
	if m.rule.LoadBalancerAlgorithm != "" {
		m.lbAlgorithmInput.SetValue(m.rule.LoadBalancerAlgorithm)
	} else {
		m.lbAlgorithmInput.SetValue("round_robin")
	}

	// 加载健康检查配置
	m.healthCheckEnabledInput.SetValue(strconv.FormatBool(m.rule.HealthCheckEnabled))
	m.healthCheckPathInput.SetValue(m.rule.HealthCheckPath)
	m.healthCheckIntervalInput.SetValue(strconv.Itoa(m.rule.HealthCheckInterval))
	m.healthCheckTimeoutInput.SetValue(strconv.Itoa(m.rule.HealthCheckTimeout))
	m.healthCheckMethodInput.SetValue(m.rule.HealthCheckMethod)
	m.expectedStatusCodeInput.SetValue(strconv.Itoa(m.rule.ExpectedStatusCode))

	// 加载会话保持配置
	m.sessionAffinityEnabledInput.SetValue(strconv.FormatBool(m.rule.SessionAffinityEnabled))
	m.sessionAffinityMethodInput.SetValue(m.rule.SessionAffinityMethod)
	m.sessionAffinityCookieInput.SetValue(m.rule.SessionAffinityCookie)
	m.sessionAffinityTTLInput.SetValue(strconv.Itoa(m.rule.SessionAffinityTTL))

	// 加载故障转移配置
	m.failoverEnabledInput.SetValue(strconv.FormatBool(m.rule.FailoverEnabled))
	m.maxRetriesInput.SetValue(strconv.Itoa(m.rule.MaxRetries))
	m.retryIntervalInput.SetValue(strconv.Itoa(m.rule.RetryInterval))
	m.failureThresholdInput.SetValue(strconv.Itoa(m.rule.FailureThreshold))
	m.recoveryThresholdInput.SetValue(strconv.Itoa(m.rule.RecoveryThreshold))

	// 加载高级选项
	m.optimizeHostHeaderInput.SetValue(strconv.FormatBool(m.rule.OptimizeHostHeader))
	m.cdnEnabledInput.SetValue(strconv.FormatBool(m.rule.CDNEnabled))
	m.cdnPresetInput.SetValue(m.rule.CDNPreset)
	m.cdnTTLInput.SetValue(strconv.Itoa(m.rule.CDNDefaultTTLSeconds))
	m.websocketOptimizedInput.SetValue(strconv.FormatBool(m.rule.WebSocketOptimized))

	// 加载 WebSocket 详细配置
	m.websocketBufferSizeInput.SetValue(strconv.Itoa(m.rule.WebSocketBufferSize))
	m.websocketReadTimeoutInput.SetValue(strconv.Itoa(m.rule.WebSocketReadTimeout))
	m.websocketWriteTimeoutInput.SetValue(strconv.Itoa(m.rule.WebSocketWriteTimeout))
	m.websocketPingIntervalInput.SetValue(strconv.Itoa(m.rule.WebSocketPingInterval))
	m.websocketTimeoutInput.SetValue(strconv.Itoa(m.rule.WebSocketTimeout))

	// 加载代理超时配置
	m.connectTimeoutInput.SetValue(strconv.Itoa(m.rule.ConnectTimeoutSec))
	m.keepAliveTimeoutInput.SetValue(strconv.Itoa(m.rule.KeepAliveTimeoutSec))
	m.idleTimeoutInput.SetValue(strconv.Itoa(m.rule.IdleTimeoutSec))
	m.tlsHandshakeTimeoutInput.SetValue(strconv.Itoa(m.rule.TLSHandshakeTimeoutSec))
	m.expectContinueTimeoutInput.SetValue(strconv.Itoa(m.rule.ExpectContinueTimeoutSec))
	m.healthCheckTimeoutSecInput.SetValue(strconv.Itoa(m.rule.HealthCheckTimeoutSec))

	// 加载性能监控配置
	m.enableTracingInput.SetValue(strconv.FormatBool(m.rule.EnableTracing))
	m.enableMetricsInput.SetValue(strconv.FormatBool(m.rule.EnableMetrics))

	// 加载自定义头部
	var requestHeaders, responseHeaders map[string]string
	if m.rule.UpstreamRequestHeaders != nil {
		requestHeaders = m.rule.UpstreamRequestHeaders
	}
	if m.rule.ResponseHeaders != nil {
		responseHeaders = m.rule.ResponseHeaders
	}
	m.headersMgr = newHeadersManager(requestHeaders, responseHeaders)

	// 初始化访问控制管理器
	m.authMgr = newAuthManager(m.rule)
	m.authMgr.LoadAuthConfig()

	// 初始化后端管理器
	if m.rule == nil {
		m.rule = &config.ProxyRule{
			Domain:   "",
			Enabled:  true,
			SSLOnly:  false,
			Backends: []config.ProxyBackend{},
		}
	}
	m.backendMgr = newBackendManager(m.rule)

	m.pathPrefixRuleMgr = newPathPrefixRuleManager(m.rule)
}


func (m proxyAdvancedModel) saveRule() error {
	// 保存基础配置
	m.rule.Domain = strings.TrimSpace(m.domainInput.Value())
	if m.rule.Domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	enabledStr := strings.TrimSpace(m.enabledInput.Value())
	if enabledStr != "" {
		enabled, err := strconv.ParseBool(enabledStr)
		if err != nil {
			return fmt.Errorf("无效的启用值: %s", enabledStr)
		}
		m.rule.Enabled = enabled
	}

	sslOnlyStr := strings.TrimSpace(m.sslOnlyInput.Value())
	if sslOnlyStr != "" {
		sslOnly, err := strconv.ParseBool(sslOnlyStr)
		if err != nil {
			return fmt.Errorf("无效的 SSL Only 值: %s", sslOnlyStr)
		}
		m.rule.SSLOnly = sslOnly
	}

	// 保存负载均衡配置
	lbAlgorithm := strings.TrimSpace(m.lbAlgorithmInput.Value())
	if lbAlgorithm != "" {
		m.rule.LoadBalancerAlgorithm = lbAlgorithm
	}

	// 保存健康检查配置
	healthCheckEnabled, _ := strconv.ParseBool(strings.TrimSpace(m.healthCheckEnabledInput.Value()))
	m.rule.HealthCheckEnabled = healthCheckEnabled
	m.rule.HealthCheckPath = strings.TrimSpace(m.healthCheckPathInput.Value())
	if intervalStr := strings.TrimSpace(m.healthCheckIntervalInput.Value()); intervalStr != "" {
		if interval, err := strconv.Atoi(intervalStr); err == nil {
			m.rule.HealthCheckInterval = interval
		}
	}
	if timeoutStr := strings.TrimSpace(m.healthCheckTimeoutInput.Value()); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil {
			m.rule.HealthCheckTimeout = timeout
		}
	}
	m.rule.HealthCheckMethod = strings.TrimSpace(m.healthCheckMethodInput.Value())
	if statusCodeStr := strings.TrimSpace(m.expectedStatusCodeInput.Value()); statusCodeStr != "" {
		if statusCode, err := strconv.Atoi(statusCodeStr); err == nil {
			m.rule.ExpectedStatusCode = statusCode
		}
	}

	// 保存会话保持配置
	sessionAffinityEnabled, _ := strconv.ParseBool(strings.TrimSpace(m.sessionAffinityEnabledInput.Value()))
	m.rule.SessionAffinityEnabled = sessionAffinityEnabled
	m.rule.SessionAffinityMethod = strings.TrimSpace(m.sessionAffinityMethodInput.Value())
	m.rule.SessionAffinityCookie = strings.TrimSpace(m.sessionAffinityCookieInput.Value())
	if ttlStr := strings.TrimSpace(m.sessionAffinityTTLInput.Value()); ttlStr != "" {
		if ttl, err := strconv.Atoi(ttlStr); err == nil {
			m.rule.SessionAffinityTTL = ttl
		}
	}

	// 保存故障转移配置
	failoverEnabled, _ := strconv.ParseBool(strings.TrimSpace(m.failoverEnabledInput.Value()))
	m.rule.FailoverEnabled = failoverEnabled
	if maxRetriesStr := strings.TrimSpace(m.maxRetriesInput.Value()); maxRetriesStr != "" {
		if maxRetries, err := strconv.Atoi(maxRetriesStr); err == nil {
			m.rule.MaxRetries = maxRetries
		}
	}
	if retryIntervalStr := strings.TrimSpace(m.retryIntervalInput.Value()); retryIntervalStr != "" {
		if retryInterval, err := strconv.Atoi(retryIntervalStr); err == nil {
			m.rule.RetryInterval = retryInterval
		}
	}
	if failureThresholdStr := strings.TrimSpace(m.failureThresholdInput.Value()); failureThresholdStr != "" {
		if failureThreshold, err := strconv.Atoi(failureThresholdStr); err == nil {
			m.rule.FailureThreshold = failureThreshold
		}
	}
	if recoveryThresholdStr := strings.TrimSpace(m.recoveryThresholdInput.Value()); recoveryThresholdStr != "" {
		if recoveryThreshold, err := strconv.Atoi(recoveryThresholdStr); err == nil {
			m.rule.RecoveryThreshold = recoveryThreshold
		}
	}

	// 保存高级选项
	optimizeHostHeader, _ := strconv.ParseBool(strings.TrimSpace(m.optimizeHostHeaderInput.Value()))
	m.rule.OptimizeHostHeader = optimizeHostHeader
	cdnEnabled, _ := strconv.ParseBool(strings.TrimSpace(m.cdnEnabledInput.Value()))
	m.rule.CDNEnabled = cdnEnabled
	m.rule.CDNPreset = strings.TrimSpace(m.cdnPresetInput.Value())
	if cdnTTLStr := strings.TrimSpace(m.cdnTTLInput.Value()); cdnTTLStr != "" {
		if cdnTTL, err := strconv.Atoi(cdnTTLStr); err == nil {
			m.rule.CDNDefaultTTLSeconds = cdnTTL
		}
	}
	websocketOptimized, _ := strconv.ParseBool(strings.TrimSpace(m.websocketOptimizedInput.Value()))
	m.rule.WebSocketOptimized = websocketOptimized

	// 保存 WebSocket 详细配置
	if bufferSizeStr := strings.TrimSpace(m.websocketBufferSizeInput.Value()); bufferSizeStr != "" {
		if bufferSize, err := strconv.Atoi(bufferSizeStr); err == nil && bufferSize > 0 {
			m.rule.WebSocketBufferSize = bufferSize
		}
	}
	if readTimeoutStr := strings.TrimSpace(m.websocketReadTimeoutInput.Value()); readTimeoutStr != "" {
		if readTimeout, err := strconv.Atoi(readTimeoutStr); err == nil && readTimeout > 0 {
			m.rule.WebSocketReadTimeout = readTimeout
		}
	}
	if writeTimeoutStr := strings.TrimSpace(m.websocketWriteTimeoutInput.Value()); writeTimeoutStr != "" {
		if writeTimeout, err := strconv.Atoi(writeTimeoutStr); err == nil && writeTimeout > 0 {
			m.rule.WebSocketWriteTimeout = writeTimeout
		}
	}
	if pingIntervalStr := strings.TrimSpace(m.websocketPingIntervalInput.Value()); pingIntervalStr != "" {
		if pingInterval, err := strconv.Atoi(pingIntervalStr); err == nil && pingInterval > 0 {
			m.rule.WebSocketPingInterval = pingInterval
		}
	}
	if timeoutStr := strings.TrimSpace(m.websocketTimeoutInput.Value()); timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			m.rule.WebSocketTimeout = timeout
		}
	}

	// 保存代理超时配置
	if connectTimeoutStr := strings.TrimSpace(m.connectTimeoutInput.Value()); connectTimeoutStr != "" {
		if connectTimeout, err := strconv.Atoi(connectTimeoutStr); err == nil && connectTimeout > 0 {
			m.rule.ConnectTimeoutSec = connectTimeout
		}
	}
	if keepAliveTimeoutStr := strings.TrimSpace(m.keepAliveTimeoutInput.Value()); keepAliveTimeoutStr != "" {
		if keepAliveTimeout, err := strconv.Atoi(keepAliveTimeoutStr); err == nil && keepAliveTimeout > 0 {
			m.rule.KeepAliveTimeoutSec = keepAliveTimeout
		}
	}
	if idleTimeoutStr := strings.TrimSpace(m.idleTimeoutInput.Value()); idleTimeoutStr != "" {
		if idleTimeout, err := strconv.Atoi(idleTimeoutStr); err == nil && idleTimeout > 0 {
			m.rule.IdleTimeoutSec = idleTimeout
		}
	}
	if tlsHandshakeTimeoutStr := strings.TrimSpace(m.tlsHandshakeTimeoutInput.Value()); tlsHandshakeTimeoutStr != "" {
		if tlsHandshakeTimeout, err := strconv.Atoi(tlsHandshakeTimeoutStr); err == nil && tlsHandshakeTimeout > 0 {
			m.rule.TLSHandshakeTimeoutSec = tlsHandshakeTimeout
		}
	}
	if expectContinueTimeoutStr := strings.TrimSpace(m.expectContinueTimeoutInput.Value()); expectContinueTimeoutStr != "" {
		if expectContinueTimeout, err := strconv.Atoi(expectContinueTimeoutStr); err == nil && expectContinueTimeout > 0 {
			m.rule.ExpectContinueTimeoutSec = expectContinueTimeout
		}
	}
	if healthCheckTimeoutSecStr := strings.TrimSpace(m.healthCheckTimeoutSecInput.Value()); healthCheckTimeoutSecStr != "" {
		if healthCheckTimeoutSec, err := strconv.Atoi(healthCheckTimeoutSecStr); err == nil && healthCheckTimeoutSec > 0 {
			m.rule.HealthCheckTimeoutSec = healthCheckTimeoutSec
		}
	}

	// 保存性能监控配置
	enableTracing, _ := strconv.ParseBool(strings.TrimSpace(m.enableTracingInput.Value()))
	m.rule.EnableTracing = enableTracing
	enableMetrics, _ := strconv.ParseBool(strings.TrimSpace(m.enableMetricsInput.Value()))
	m.rule.EnableMetrics = enableMetrics

	// 保存自定义头部
	m.rule.UpstreamRequestHeaders = m.headersMgr.GetRequestHeaders()
	m.rule.ResponseHeaders = m.headersMgr.GetResponseHeaders()

	// 保存访问控制配置
	if err := m.authMgr.SaveAuthConfig(); err != nil {
		return fmt.Errorf("保存访问控制配置失败: %v", err)
	}

	// 更新或添加到配置
	if m.editingIndex >= 0 && m.editingIndex < len(m.config.Proxy.Rules) {
		m.config.Proxy.Rules[m.editingIndex] = *m.rule
	} else {
		m.config.Proxy.Rules = append(m.config.Proxy.Rules, *m.rule)
	}

	return nil
}

