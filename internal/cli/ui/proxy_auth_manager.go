package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

// authManager 访问控制（Basic Auth）管理器
type authManager struct {
	rule          *config.ProxyRule
	list          list.Model
	editing       bool
	editingIndex  int // -1 表示添加新用户
	formIndex     int
	formInputs    []textinput.Model
	enabledInput  textinput.Model
	timeoutInput  textinput.Model
	cookieDomainInput textinput.Model
	message       string
}

// authUserItem Basic Auth 用户列表项
type authUserItem struct {
	user  *config.ProxyAuthUser
	index int
}

func (i authUserItem) FilterValue() string {
	return i.user.Username
}

func (i authUserItem) Title() string {
	return fmt.Sprintf("用户: %s", i.user.Username)
}

func (i authUserItem) Description() string {
	return fmt.Sprintf("密码: %s", strings.Repeat("*", len(i.user.Password)))
}

func newAuthManager(rule *config.ProxyRule) *authManager {
	am := &authManager{
		rule:         rule,
		editingIndex: -1,
	}
	am.refreshList()
	
	// 初始化启用状态和超时配置输入框
	am.enabledInput = textinput.New()
	am.enabledInput.Placeholder = "启用 (true/false)"
	am.timeoutInput = textinput.New()
	am.timeoutInput.Placeholder = "会话超时(秒，默认3600)"
	am.cookieDomainInput = textinput.New()
	am.cookieDomainInput.Placeholder = "Cookie域名（默认使用代理域名）"
	
	return am
}

func (am *authManager) refreshList() {
	users := am.rule.AuthUsers
	if users == nil {
		users = []config.ProxyAuthUser{}
	}

	items := make([]list.Item, len(users))
	for i := range users {
		items[i] = authUserItem{user: &users[i], index: i}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Basic Auth 用户"
	l.SetShowStatusBar(false)
	am.list = l
}

func (am *authManager) initForm() {
	// 初始化表单：用户名、密码
	am.formInputs = []textinput.Model{
		textinput.New(),
		textinput.New(),
	}
	am.formInputs[0].Placeholder = "用户名"
	am.formInputs[1].Placeholder = "密码"
	am.formIndex = 0
	if len(am.formInputs) > 0 {
		am.formInputs[0].Focus()
	}
}

func (am *authManager) loadUser(user *config.ProxyAuthUser) {
	am.formInputs[0].SetValue(user.Username)
	am.formInputs[1].SetValue(user.Password)
}

func (am *authManager) saveUser() error {
	username := strings.TrimSpace(am.formInputs[0].Value())
	password := strings.TrimSpace(am.formInputs[1].Value())

	if username == "" {
		return fmt.Errorf("用户名不能为空")
	}
	if password == "" {
		return fmt.Errorf("密码不能为空")
	}

	user := config.ProxyAuthUser{
		Username: username,
		Password: password,
	}

	if am.rule.AuthUsers == nil {
		am.rule.AuthUsers = []config.ProxyAuthUser{}
	}

	if am.editingIndex >= 0 && am.editingIndex < len(am.rule.AuthUsers) {
		am.rule.AuthUsers[am.editingIndex] = user
	} else {
		am.rule.AuthUsers = append(am.rule.AuthUsers, user)
	}

	return nil
}

func (am *authManager) handleAdd() tea.Cmd {
	am.editing = true
	am.editingIndex = -1
	am.initForm()
	return textinput.Blink
}

func (am *authManager) handleEdit() tea.Cmd {
	selected := am.list.SelectedItem()
	if selected != nil {
		item := selected.(authUserItem)
		am.editing = true
		am.editingIndex = item.index
		am.initForm()
		am.loadUser(item.user)
		return textinput.Blink
	}
	return nil
}

func (am *authManager) handleDelete() error {
	selected := am.list.SelectedItem()
	if selected != nil {
		item := selected.(authUserItem)
		if am.rule.AuthUsers != nil && len(am.rule.AuthUsers) > item.index {
			am.rule.AuthUsers = append(
				am.rule.AuthUsers[:item.index],
				am.rule.AuthUsers[item.index+1:]...,
			)
			am.refreshList()
			return nil
		}
	}
	return fmt.Errorf("未选择用户")
}

func (am *authManager) handleFormInput(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "enter":
		if err := am.saveUser(); err != nil {
			am.message = fmt.Sprintf("❌ 错误: %v", err)
			return nil, false
		}
		am.editing = false
		am.refreshList()
		am.message = "✅ 用户已保存"
		return nil, true

	case "esc":
		am.editing = false
		return nil, true

	case "tab":
		am.formIndex = (am.formIndex + 1) % len(am.formInputs)
		for i := range am.formInputs {
			if i == am.formIndex {
				am.formInputs[i].Focus()
			} else {
				am.formInputs[i].Blur()
			}
		}
		return textinput.Blink, false

	case "shift+tab":
		am.formIndex = (am.formIndex - 1 + len(am.formInputs)) % len(am.formInputs)
		for i := range am.formInputs {
			if i == am.formIndex {
				am.formInputs[i].Focus()
			} else {
				am.formInputs[i].Blur()
			}
		}
		return textinput.Blink, false
	}

	if am.formIndex < len(am.formInputs) {
		var cmd tea.Cmd
		am.formInputs[am.formIndex], cmd = am.formInputs[am.formIndex].Update(msg)
		return cmd, false
	}

	return nil, false
}

func (am *authManager) Update(msg tea.Msg, width, height int) tea.Cmd {
	am.list.SetWidth(width - 4)
	am.list.SetHeight(height - 20)

	if am.editing {
		var cmd tea.Cmd
		var done bool
		switch msg := msg.(type) {
		case tea.KeyMsg:
			cmd, done = am.handleFormInput(msg)
			if done {
				return cmd
			}
		}
		return cmd
	}

	var cmd tea.Cmd
	am.list, cmd = am.list.Update(msg)
	return cmd
}

func (am *authManager) View() string {
	if am.editing {
		return am.renderForm()
	}

	content := []string{
		subtitleStyle.Render("访问控制配置"),
		"",
		fmt.Sprintf("Basic Auth 启用: %s", am.enabledInput.View()),
		fmt.Sprintf("会话超时(秒): %s", am.timeoutInput.View()),
		fmt.Sprintf("Cookie 域名: %s", am.cookieDomainInput.View()),
		"",
		"用户列表:",
		am.list.View(),
		"",
		helpStyle.Render("a: 添加用户 | e: 编辑用户 | d: 删除用户"),
	}

	if am.message != "" {
		messageView := ""
		if strings.HasPrefix(am.message, "❌") {
			messageView = errorStyle.Render(am.message)
		} else {
			messageView = successStyle.Render(am.message)
		}
		content = append([]string{messageView, ""}, content...)
	}

	return strings.Join(content, "\n")
}

func (am *authManager) renderForm() string {
	action := "添加"
	if am.editingIndex >= 0 {
		action = "编辑"
	}

	formContent := []string{
		fmt.Sprintf("%sBasic Auth 用户", action),
		"",
		fmt.Sprintf("用户名: %s", am.formInputs[0].View()),
		fmt.Sprintf("密码: %s", am.formInputs[1].View()),
		"",
		helpStyle.Render("Tab: 切换字段 | Enter: 保存 | Esc: 取消"),
	}

	if am.message != "" {
		messageView := ""
		if strings.HasPrefix(am.message, "❌") {
			messageView = errorStyle.Render(am.message)
		} else {
			messageView = successStyle.Render(am.message)
		}
		formContent = append([]string{messageView, ""}, formContent...)
	}

	return strings.Join(formContent, "\n")
}

// LoadAuthConfig 加载访问控制配置
func (am *authManager) LoadAuthConfig() {
	am.enabledInput.SetValue(strconv.FormatBool(am.rule.AuthEnabled))
	if am.rule.AuthSessionTimeout > 0 {
		am.timeoutInput.SetValue(strconv.Itoa(am.rule.AuthSessionTimeout))
	} else {
		am.timeoutInput.SetValue("3600")
	}
	if am.rule.AuthCookieDomain != "" {
		am.cookieDomainInput.SetValue(am.rule.AuthCookieDomain)
	} else {
		am.cookieDomainInput.SetValue(am.rule.Domain)
	}
}

// SaveAuthConfig 保存访问控制配置
func (am *authManager) SaveAuthConfig() error {
	enabled, _ := strconv.ParseBool(strings.TrimSpace(am.enabledInput.Value()))
	am.rule.AuthEnabled = enabled

	timeoutStr := strings.TrimSpace(am.timeoutInput.Value())
	if timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			am.rule.AuthSessionTimeout = timeout
		} else {
			am.rule.AuthSessionTimeout = 3600 // 默认值
		}
	} else {
		am.rule.AuthSessionTimeout = 3600 // 默认值
	}

	cookieDomain := strings.TrimSpace(am.cookieDomainInput.Value())
	if cookieDomain != "" {
		am.rule.AuthCookieDomain = cookieDomain
	} else {
		am.rule.AuthCookieDomain = am.rule.Domain // 默认使用代理域名
	}

	return nil
}

