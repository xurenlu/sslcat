package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/google/uuid"
	"github.com/xurenlu/sslcat/internal/config"
)

// pathPrefixRuleManager 路径前缀规则管理器
type pathPrefixRuleManager struct {
	rule          *config.ProxyRule
	list          list.Model
	editing       bool
	editingIndex  int // -1 表示添加新规则
	formIndex     int
	formInputs    []textinput.Model
	initialValues []string // 保存编辑前的初始值，用于 ESC 恢复
	message       string
}

// pathPrefixRuleItem 路径前缀规则列表项
type pathPrefixRuleItem struct {
	rule  *config.PathPrefixRule
	index int
}

func (i pathPrefixRuleItem) FilterValue() string {
	return i.rule.Name + " " + strings.Join(i.rule.Prefixes, " ")
}

func (i pathPrefixRuleItem) Title() string {
	status := "✓"
	if !i.rule.Enabled {
		status = "✗"
	}
	name := i.rule.Name
	if name == "" {
		name = fmt.Sprintf("规则 %d", i.index+1)
	}
	return fmt.Sprintf("%s %s", status, name)
}

func (i pathPrefixRuleItem) Description() string {
	return fmt.Sprintf("路径: %s", strings.Join(i.rule.Prefixes, ", "))
}

func newPathPrefixRuleManager(rule *config.ProxyRule) *pathPrefixRuleManager {
	pm := &pathPrefixRuleManager{
		rule:         rule,
		editingIndex: -1,
	}
	pm.refreshList()
	return pm
}

func (pm *pathPrefixRuleManager) refreshList() {
	items := make([]list.Item, len(pm.rule.PathPrefixRules))
	for i := range pm.rule.PathPrefixRules {
		items[i] = pathPrefixRuleItem{rule: &pm.rule.PathPrefixRules[i], index: i}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "路径前缀规则"
	l.SetShowStatusBar(false)
	pm.list = l
}

func (pm *pathPrefixRuleManager) initForm() {
	// 初始化表单：名称、描述、路径前缀（逗号分隔）、精确匹配、启用
	pm.formInputs = []textinput.Model{
		textinput.New(), // 名称
		textinput.New(), // 描述
		textinput.New(), // 路径前缀（逗号分隔）
		textinput.New(), // 精确匹配（true/false）
		textinput.New(), // 启用（true/false）
	}
	pm.formInputs[0].Placeholder = "规则名称"
	pm.formInputs[1].Placeholder = "规则描述"
	pm.formInputs[2].Placeholder = "路径前缀（逗号分隔，如: /api/v1/,/api/v2/）"
	pm.formInputs[3].Placeholder = "精确匹配 (空格键切换 true/false)"
	pm.formInputs[4].Placeholder = "启用 (空格键切换 true/false)"
	pm.formIndex = 0
	if len(pm.formInputs) > 0 {
		pm.formInputs[0].Focus()
	}
}

// resetForm 重置表单到默认值或初始值
func (pm *pathPrefixRuleManager) resetForm() {
	if len(pm.formInputs) == 0 {
		pm.initForm()
	}
	
	if pm.editingIndex >= 0 && len(pm.initialValues) == len(pm.formInputs) {
		// 编辑模式：恢复到编辑前的值
		for i := range pm.formInputs {
			pm.formInputs[i].SetValue(pm.initialValues[i])
		}
	} else {
		// 添加模式：设置默认值
		for i := range pm.formInputs {
			pm.formInputs[i].SetValue("")
		}
		pm.formInputs[3].SetValue("false") // 默认精确匹配
		pm.formInputs[4].SetValue("true") // 默认启用
	}
	pm.formIndex = 0
	if len(pm.formInputs) > 0 {
		pm.formInputs[0].Focus()
	}
}

func (pm *pathPrefixRuleManager) loadRule(rule *config.PathPrefixRule) {
	pm.formInputs[0].SetValue(rule.Name)
	pm.formInputs[1].SetValue(rule.Description)
	pm.formInputs[2].SetValue(strings.Join(rule.Prefixes, ","))
	pm.formInputs[3].SetValue(strconv.FormatBool(rule.Exact))
	pm.formInputs[4].SetValue(strconv.FormatBool(rule.Enabled))
}

func (pm *pathPrefixRuleManager) saveRule() error {
	name := strings.TrimSpace(pm.formInputs[0].Value())
	description := strings.TrimSpace(pm.formInputs[1].Value())
	prefixesStr := strings.TrimSpace(pm.formInputs[2].Value())
	exactStr := strings.TrimSpace(pm.formInputs[3].Value())
	enabledStr := strings.TrimSpace(pm.formInputs[4].Value())

	if prefixesStr == "" {
		return fmt.Errorf("路径前缀不能为空")
	}

	// 解析路径前缀（逗号分隔）
	prefixes := []string{}
	for _, p := range strings.Split(prefixesStr, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			prefixes = append(prefixes, p)
		}
	}
	if len(prefixes) == 0 {
		return fmt.Errorf("至少需要一个路径前缀")
	}

	exact := false
	if exactStr != "" {
		// 支持多种格式：true/false, yes/no, 1/0, y/n
		exactStrLower := strings.ToLower(exactStr)
		if exactStrLower == "true" || exactStrLower == "yes" || exactStrLower == "1" || exactStrLower == "y" {
			exact = true
		} else if exactStrLower == "false" || exactStrLower == "no" || exactStrLower == "0" || exactStrLower == "n" {
			exact = false
		} else {
			return fmt.Errorf("无效的精确匹配值: %s (请输入 true/false, yes/no, 1/0, 或按空格键切换)", exactStr)
		}
	}

	enabled := true
	if enabledStr != "" {
		// 支持多种格式：true/false, yes/no, 1/0, y/n
		enabledStrLower := strings.ToLower(enabledStr)
		if enabledStrLower == "true" || enabledStrLower == "yes" || enabledStrLower == "1" || enabledStrLower == "y" {
			enabled = true
		} else if enabledStrLower == "false" || enabledStrLower == "no" || enabledStrLower == "0" || enabledStrLower == "n" {
			enabled = false
		} else {
			return fmt.Errorf("无效的启用值: %s (请输入 true/false, yes/no, 1/0, 或按空格键切换)", enabledStr)
		}
	}

	rule := config.PathPrefixRule{
		Name:        name,
		Description: description,
		Prefixes:    prefixes,
		Exact:       exact,
		Enabled:     enabled,
		// 设置默认后端配置
		Backends: []config.ProxyBackend{
			{
				ID:      uuid.New().String(),
				Host:    pm.rule.Target,
				Port:    pm.rule.Port,
				Weight:  1,
				Priority: 0,
				Enabled: true,
			},
		},
		LoadBalancerAlgorithm: pm.rule.LoadBalancerAlgorithm,
		SessionAffinityEnabled: pm.rule.SessionAffinityEnabled,
		SessionAffinityMethod:  pm.rule.SessionAffinityMethod,
		SessionAffinityCookie:  pm.rule.SessionAffinityCookie,
		SessionAffinityTTL:     pm.rule.SessionAffinityTTL,
		HealthCheckEnabled:     pm.rule.HealthCheckEnabled,
		HealthCheckPath:        pm.rule.HealthCheckPath,
		HealthCheckInterval:    pm.rule.HealthCheckInterval,
		HealthCheckTimeout:     pm.rule.HealthCheckTimeout,
		HealthCheckMethod:      pm.rule.HealthCheckMethod,
		ExpectedStatusCode:     pm.rule.ExpectedStatusCode,
		FailoverEnabled:        pm.rule.FailoverEnabled,
		MaxRetries:             pm.rule.MaxRetries,
		RetryInterval:          pm.rule.RetryInterval,
		FailureThreshold:       pm.rule.FailureThreshold,
		RecoveryThreshold:      pm.rule.RecoveryThreshold,
	}

	if pm.editingIndex >= 0 && pm.editingIndex < len(pm.rule.PathPrefixRules) {
		pm.rule.PathPrefixRules[pm.editingIndex] = rule
	} else {
		pm.rule.PathPrefixRules = append(pm.rule.PathPrefixRules, rule)
	}

	return nil
}

func (pm *pathPrefixRuleManager) handleAdd() tea.Cmd {
	pm.editing = true
	pm.editingIndex = -1
	pm.initialValues = nil // 清除初始值
	pm.initForm()
	pm.resetForm() // 设置默认值
	return textinput.Blink
}

func (pm *pathPrefixRuleManager) handleEdit() tea.Cmd {
	selected := pm.list.SelectedItem()
	if selected != nil {
		item := selected.(pathPrefixRuleItem)
		pm.editing = true
		pm.editingIndex = item.index
		pm.initForm()
		pm.loadRule(item.rule)
		// 保存编辑前的初始值
		pm.initialValues = make([]string, len(pm.formInputs))
		for i := range pm.formInputs {
			pm.initialValues[i] = pm.formInputs[i].Value()
		}
		return textinput.Blink
	}
	return nil
}

func (pm *pathPrefixRuleManager) handleDelete() error {
	selected := pm.list.SelectedItem()
	if selected != nil {
		item := selected.(pathPrefixRuleItem)
		pm.rule.PathPrefixRules = append(
			pm.rule.PathPrefixRules[:item.index],
			pm.rule.PathPrefixRules[item.index+1:]...,
		)
		pm.refreshList()
		return nil
	}
	return fmt.Errorf("未选择规则")
}

func (pm *pathPrefixRuleManager) handleFormInput(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "enter":
		if err := pm.saveRule(); err != nil {
			pm.message = fmt.Sprintf("❌ 错误: %v", err)
			return nil, false
		}
		pm.editing = false
		pm.initialValues = nil // 清除初始值
		pm.refreshList()
		pm.message = "✅ 规则已保存"
		return nil, true

	case "esc":
		// 恢复到编辑前的值
		pm.resetForm()
		pm.editing = false
		pm.initialValues = nil
		return nil, true

	case "tab":
		pm.formIndex = (pm.formIndex + 1) % len(pm.formInputs)
		for i := range pm.formInputs {
			if i == pm.formIndex {
				pm.formInputs[i].Focus()
			} else {
				pm.formInputs[i].Blur()
			}
		}
		return textinput.Blink, false

	case "shift+tab":
		pm.formIndex = (pm.formIndex - 1 + len(pm.formInputs)) % len(pm.formInputs)
		for i := range pm.formInputs {
			if i == pm.formIndex {
				pm.formInputs[i].Focus()
			} else {
				pm.formInputs[i].Blur()
			}
		}
		return textinput.Blink, false

	case " ": // 空格键 - 用于切换布尔值字段
		// 如果是精确匹配字段（索引3）或启用字段（索引4），切换 true/false
		if pm.formIndex == 3 || pm.formIndex == 4 {
			currentValue := strings.TrimSpace(pm.formInputs[pm.formIndex].Value())
			newValue := "false"
			if currentValue == "" || currentValue == "false" {
				newValue = "true"
			}
			pm.formInputs[pm.formIndex].SetValue(newValue)
			return textinput.Blink, false
		}

	case "ctrl+r":
		// Ctrl+R 重置表单
		pm.resetForm()
		pm.message = "🔄 表单已重置"
		return nil, false
	}

	if pm.formIndex < len(pm.formInputs) {
		var cmd tea.Cmd
		pm.formInputs[pm.formIndex], cmd = pm.formInputs[pm.formIndex].Update(msg)
		return cmd, false
	}

	return nil, false
}

func (pm *pathPrefixRuleManager) Update(msg tea.Msg, width, height int) tea.Cmd {
	pm.list.SetWidth(width - 4)
	pm.list.SetHeight(height - 15)

	if pm.editing {
		// 确保表单已初始化
		if len(pm.formInputs) == 0 {
			pm.initForm()
			// 如果是编辑模式，重新加载旧值
			if pm.editingIndex >= 0 && pm.editingIndex < len(pm.rule.PathPrefixRules) {
				pm.loadRule(&pm.rule.PathPrefixRules[pm.editingIndex])
			}
		}
		
		var cmd tea.Cmd
		var done bool
		switch msg := msg.(type) {
		case tea.KeyMsg:
			cmd, done = pm.handleFormInput(msg)
			if done {
				return cmd
			}
		}
		return cmd
	}

	var cmd tea.Cmd
	pm.list, cmd = pm.list.Update(msg)
	return cmd
}

func (pm *pathPrefixRuleManager) View() string {
	if pm.editing {
		// 确保表单已初始化
		if len(pm.formInputs) == 0 {
			pm.initForm()
			// 如果是编辑模式，重新加载旧值
			if pm.editingIndex >= 0 && pm.editingIndex < len(pm.rule.PathPrefixRules) {
				pm.loadRule(&pm.rule.PathPrefixRules[pm.editingIndex])
			}
		}
		return pm.renderForm()
	}
	return pm.list.View()
}

func (pm *pathPrefixRuleManager) renderForm() string {
	// 确保表单已初始化
	if len(pm.formInputs) == 0 {
		pm.initForm()
		// 如果是编辑模式，重新加载旧值
		if pm.editingIndex >= 0 && pm.editingIndex < len(pm.rule.PathPrefixRules) {
			pm.loadRule(&pm.rule.PathPrefixRules[pm.editingIndex])
		}
	}
	
	action := "添加"
	if pm.editingIndex >= 0 {
		action = "编辑"
	}

	formContent := []string{
		fmt.Sprintf("%s路径前缀规则", action),
		"",
		fmt.Sprintf("名称: %s", pm.formInputs[0].View()),
		fmt.Sprintf("描述: %s", pm.formInputs[1].View()),
		fmt.Sprintf("路径前缀: %s", pm.formInputs[2].View()),
		fmt.Sprintf("精确匹配: %s", pm.formInputs[3].View()),
		fmt.Sprintf("启用: %s", pm.formInputs[4].View()),
		"",
		helpStyle.Render("Tab: 切换字段 | Enter: 保存 | Esc: 取消 | 空格键: 切换布尔值 | Ctrl+R: 重置"),
	}

	if pm.message != "" {
		messageView := ""
		if strings.HasPrefix(pm.message, "❌") {
			messageView = errorStyle.Render(pm.message)
		} else {
			messageView = successStyle.Render(pm.message)
		}
		formContent = append([]string{messageView, ""}, formContent...)
	}

	return strings.Join(formContent, "\n")
}

