package ui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
	"github.com/xurenlu/sslcat/internal/config"
)

// backendManager 后端服务器管理器
type backendManager struct {
	rule          *config.ProxyRule
	list          list.Model
	editing       bool
	formIndex     int
	formInputs    []textinput.Model
	editingIndex  int // -1 表示添加新后端
	message       string
}

// backendItem 后端服务器列表项
type backendItem struct {
	backend *config.ProxyBackend
	index   int
}

func (i backendItem) FilterValue() string {
	return i.backend.Host + " " + strconv.Itoa(i.backend.Port)
}

func (i backendItem) Title() string {
	status := "✓"
	if !i.backend.Enabled {
		status = "✗"
	}
	return fmt.Sprintf("%s %s:%d (权重: %d)", status, i.backend.Host, i.backend.Port, i.backend.Weight)
}

func (i backendItem) Description() string {
	return fmt.Sprintf("优先级: %d", i.backend.Priority)
}

func newBackendManager(rule *config.ProxyRule) *backendManager {
	bm := &backendManager{
		rule:         rule,
		editingIndex: -1,
	}
	bm.refreshList()
	return bm
}

func (bm *backendManager) refreshList() {
	backends := bm.rule.GetEffectiveBackends()
	if len(backends) == 0 {
		l := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
		l.Title = "后端服务器（空，请添加）"
		l.SetShowStatusBar(false)
		bm.list = l
		return
	}

	items := make([]list.Item, len(backends))
	for i := range backends {
		items[i] = backendItem{backend: &backends[i], index: i}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "后端服务器"
	l.SetShowStatusBar(false)
	bm.list = l
}

func (bm *backendManager) initForm() {
	bm.formInputs = []textinput.Model{
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
		textinput.New(),
	}
	bm.formInputs[0].Placeholder = "主机地址 (例如: 127.0.0.1)"
	bm.formInputs[1].Placeholder = "端口 (例如: 8080)"
	bm.formInputs[2].Placeholder = "权重 (例如: 1)"
	bm.formInputs[3].Placeholder = "优先级 (例如: 0)"
	bm.formInputs[4].Placeholder = "启用 (true/false)"
	bm.formIndex = 0
	if len(bm.formInputs) > 0 {
		bm.formInputs[0].Focus()
	}
}

func (bm *backendManager) loadBackend(backend *config.ProxyBackend) {
	bm.formInputs[0].SetValue(backend.Host)
	bm.formInputs[1].SetValue(strconv.Itoa(backend.Port))
	bm.formInputs[2].SetValue(strconv.Itoa(backend.Weight))
	bm.formInputs[3].SetValue(strconv.Itoa(backend.Priority))
	bm.formInputs[4].SetValue(strconv.FormatBool(backend.Enabled))
}

func (bm *backendManager) saveBackend() error {
	host := strings.TrimSpace(bm.formInputs[0].Value())
	portStr := strings.TrimSpace(bm.formInputs[1].Value())
	weightStr := strings.TrimSpace(bm.formInputs[2].Value())
	priorityStr := strings.TrimSpace(bm.formInputs[3].Value())
	enabledStr := strings.TrimSpace(bm.formInputs[4].Value())

	if host == "" {
		return fmt.Errorf("主机地址不能为空")
	}

	port := 80
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("无效的端口号: %s", portStr)
		}
		port = p
	}

	weight := 1
	if weightStr != "" {
		w, err := strconv.Atoi(weightStr)
		if err != nil {
			return fmt.Errorf("无效的权重值: %s", weightStr)
		}
		weight = w
	}

	priority := 0
	if priorityStr != "" {
		p, err := strconv.Atoi(priorityStr)
		if err != nil {
			return fmt.Errorf("无效的优先级值: %s", priorityStr)
		}
		priority = p
	}

	enabled := true
	if enabledStr != "" {
		e, err := strconv.ParseBool(enabledStr)
		if err != nil {
			return fmt.Errorf("无效的启用值: %s", enabledStr)
		}
		enabled = e
	}

	backend := config.ProxyBackend{
		ID:       uuid.New().String(),
		Host:     host,
		Port:     port,
		Weight:   weight,
		Priority: priority,
		Enabled:  enabled,
	}

	backends := bm.rule.GetEffectiveBackends()
	if bm.editingIndex >= 0 && bm.editingIndex < len(backends) {
		backend.ID = backends[bm.editingIndex].ID // 保留原有ID
		bm.rule.Backends[bm.editingIndex] = backend
	} else {
		bm.rule.Backends = append(bm.rule.Backends, backend)
	}

	return nil
}

func (bm *backendManager) handleAdd() tea.Cmd {
	bm.editing = true
	bm.editingIndex = -1
	bm.initForm()
	return textinput.Blink
}

func (bm *backendManager) handleEdit() tea.Cmd {
	selected := bm.list.SelectedItem()
	if selected != nil {
		item := selected.(backendItem)
		bm.editing = true
		bm.editingIndex = item.index
		bm.initForm()
		bm.loadBackend(item.backend)
		return textinput.Blink
	}
	return nil
}

func (bm *backendManager) handleDelete() error {
	selected := bm.list.SelectedItem()
	if selected != nil {
		item := selected.(backendItem)
		backends := bm.rule.GetEffectiveBackends()
		if len(backends) <= 1 {
			return fmt.Errorf("至少需要保留一个后端服务器")
		}
		bm.rule.Backends = append(backends[:item.index], backends[item.index+1:]...)
		bm.refreshList()
		return nil
	}
	return fmt.Errorf("未选择后端服务器")
}

func (bm *backendManager) handleFormInput(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "enter":
		if err := bm.saveBackend(); err != nil {
			bm.message = fmt.Sprintf("❌ 错误: %v", err)
			return nil, false
		}
		bm.editing = false
		bm.refreshList()
		bm.message = "✅ 后端已保存"
		return nil, true

	case "esc":
		bm.editing = false
		return nil, true

	case "tab":
		bm.formIndex = (bm.formIndex + 1) % len(bm.formInputs)
		for i := range bm.formInputs {
			if i == bm.formIndex {
				bm.formInputs[i].Focus()
			} else {
				bm.formInputs[i].Blur()
			}
		}
		return textinput.Blink, false

	case "shift+tab":
		bm.formIndex = (bm.formIndex - 1 + len(bm.formInputs)) % len(bm.formInputs)
		for i := range bm.formInputs {
			if i == bm.formIndex {
				bm.formInputs[i].Focus()
			} else {
				bm.formInputs[i].Blur()
			}
		}
		return textinput.Blink, false
	}

	if bm.formIndex < len(bm.formInputs) {
		var cmd tea.Cmd
		bm.formInputs[bm.formIndex], cmd = bm.formInputs[bm.formIndex].Update(msg)
		return cmd, false
	}

	return nil, false
}

func (bm *backendManager) Update(msg tea.Msg, width, height int) tea.Cmd {
	bm.list.SetWidth(width - 4)
	bm.list.SetHeight(height - 15)

	if bm.editing {
		var cmd tea.Cmd
		var done bool
		switch msg := msg.(type) {
		case tea.KeyMsg:
			cmd, done = bm.handleFormInput(msg)
			if done {
				return cmd
			}
		}
		return cmd
	}

	var cmd tea.Cmd
	bm.list, cmd = bm.list.Update(msg)
	return cmd
}

func (bm *backendManager) View() string {
	if bm.editing {
		return bm.renderForm()
	}
	return bm.list.View()
}

func (bm *backendManager) renderForm() string {
	action := "添加"
	if bm.editingIndex >= 0 {
		action = "编辑"
	}

	formContent := []string{
		fmt.Sprintf("%s后端服务器", action),
		"",
		fmt.Sprintf("主机地址: %s", bm.formInputs[0].View()),
		fmt.Sprintf("端口: %s", bm.formInputs[1].View()),
		fmt.Sprintf("权重: %s", bm.formInputs[2].View()),
		fmt.Sprintf("优先级: %s", bm.formInputs[3].View()),
		fmt.Sprintf("启用: %s", bm.formInputs[4].View()),
		"",
		helpStyle.Render("Tab: 切换字段 | Enter: 保存 | Esc: 取消"),
	}

	if bm.message != "" {
		messageView := ""
		if strings.HasPrefix(bm.message, "❌") {
			messageView = errorStyle.Render(bm.message)
		} else {
			messageView = successStyle.Render(bm.message)
		}
		formContent = append([]string{messageView, ""}, formContent...)
	}

	return strings.Join(formContent, "\n")
}

