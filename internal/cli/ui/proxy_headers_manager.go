package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
)

// headersManager 自定义头部管理器
type headersManager struct {
	requestHeaders  map[string]string
	responseHeaders map[string]string
	requestList     list.Model
	responseList    list.Model
	editing         bool
	editingType     string // "request" or "response"
	editingKey      string
	keyInput        textinput.Model
	valueInput      textinput.Model
	message         string
}

// headerItem 头部列表项
type headerItem struct {
	key   string
	value string
	index int
}

func (i headerItem) FilterValue() string {
	return i.key + " " + i.value
}

func (i headerItem) Title() string {
	return fmt.Sprintf("%s: %s", i.key, i.value)
}

func (i headerItem) Description() string {
	return ""
}

func newHeadersManager(requestHeaders, responseHeaders map[string]string) *headersManager {
	hm := &headersManager{
		requestHeaders:  make(map[string]string),
		responseHeaders: make(map[string]string),
		editingType:     "request",
	}

	// 复制头部映射
	if requestHeaders != nil {
		for k, v := range requestHeaders {
			hm.requestHeaders[k] = v
		}
	}
	if responseHeaders != nil {
		for k, v := range responseHeaders {
			hm.responseHeaders[k] = v
		}
	}

	hm.keyInput = textinput.New()
	hm.keyInput.Placeholder = "头部名称 (例如: X-Custom-Header)"
	hm.valueInput = textinput.New()
	hm.valueInput.Placeholder = "头部值"

	hm.refreshLists()

	return hm
}

func (hm *headersManager) refreshLists() {
	// 刷新请求头列表
	requestItems := make([]list.Item, 0, len(hm.requestHeaders))
	idx := 0
	for k, v := range hm.requestHeaders {
		requestItems = append(requestItems, headerItem{key: k, value: v, index: idx})
		idx++
	}
	requestList := list.New(requestItems, list.NewDefaultDelegate(), 0, 0)
	requestList.Title = "请求头"
	requestList.SetShowStatusBar(false)
	hm.requestList = requestList

	// 刷新响应头列表
	responseItems := make([]list.Item, 0, len(hm.responseHeaders))
	idx = 0
	for k, v := range hm.responseHeaders {
		responseItems = append(responseItems, headerItem{key: k, value: v, index: idx})
		idx++
	}
	responseList := list.New(responseItems, list.NewDefaultDelegate(), 0, 0)
	responseList.Title = "响应头"
	responseList.SetShowStatusBar(false)
	hm.responseList = responseList
}

func (hm *headersManager) handleAdd() tea.Cmd {
	hm.editing = true
	hm.editingKey = ""
	hm.keyInput.SetValue("")
	hm.valueInput.SetValue("")
	hm.keyInput.Focus()
	return textinput.Blink
}

func (hm *headersManager) handleEdit() tea.Cmd {
	selected := hm.getSelectedItem()
	if selected != nil {
		item := selected.(headerItem)
		hm.editing = true
		hm.editingKey = item.key
		hm.keyInput.SetValue(item.key)
		hm.valueInput.SetValue(item.value)
		hm.keyInput.Focus()
		return textinput.Blink
	}
	return nil
}

func (hm *headersManager) handleDelete() error {
	selected := hm.getSelectedItem()
	if selected != nil {
		item := selected.(headerItem)
		if hm.editingType == "request" {
			delete(hm.requestHeaders, item.key)
		} else {
			delete(hm.responseHeaders, item.key)
		}
		hm.refreshLists()
		return nil
	}
	return fmt.Errorf("未选择头部")
}

func (hm *headersManager) getSelectedItem() list.Item {
	if hm.editingType == "request" {
		return hm.requestList.SelectedItem()
	}
	return hm.responseList.SelectedItem()
}

func (hm *headersManager) handleFormInput(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "enter":
		// 保存头部
		key := strings.TrimSpace(hm.keyInput.Value())
		value := strings.TrimSpace(hm.valueInput.Value())

		if key == "" {
			hm.message = "❌ 头部名称不能为空"
			return nil, false
		}

		headers := hm.requestHeaders
		if hm.editingType == "response" {
			headers = hm.responseHeaders
		}

		// 如果是编辑模式，删除旧的键
		if hm.editingKey != "" && hm.editingKey != key {
			delete(headers, hm.editingKey)
		}

		headers[key] = value
		hm.editing = false
		hm.refreshLists()
		hm.message = "✅ 头部已保存"
		return nil, true

	case "esc":
		hm.editing = false
		return nil, true

	case "tab":
		if hm.keyInput.Focused() {
			hm.keyInput.Blur()
			hm.valueInput.Focus()
		} else {
			hm.valueInput.Blur()
			hm.keyInput.Focus()
		}
		return textinput.Blink, false

	case "shift+tab":
		if hm.valueInput.Focused() {
			hm.valueInput.Blur()
			hm.keyInput.Focus()
		} else {
			hm.keyInput.Blur()
			hm.valueInput.Focus()
		}
		return textinput.Blink, false
	}

	var cmd tea.Cmd
	if hm.keyInput.Focused() {
		hm.keyInput, cmd = hm.keyInput.Update(msg)
	} else if hm.valueInput.Focused() {
		hm.valueInput, cmd = hm.valueInput.Update(msg)
	} else {
		hm.keyInput.Focus()
		hm.keyInput, cmd = hm.keyInput.Update(msg)
	}

	return cmd, false
}

func (hm *headersManager) Update(msg tea.Msg, width, height int) tea.Cmd {
	hm.requestList.SetWidth(width/2 - 4)
	hm.requestList.SetHeight(height - 15)
	hm.responseList.SetWidth(width/2 - 4)
	hm.responseList.SetHeight(height - 15)

	if hm.editing {
		var cmd tea.Cmd
		var done bool
		switch msg := msg.(type) {
		case tea.KeyMsg:
			cmd, done = hm.handleFormInput(msg)
			if done {
				return cmd
			}
		}
		return cmd
	}

	// 处理类型切换
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "t" || msg.String() == "T" {
			// 切换请求/响应头
			if hm.editingType == "request" {
				hm.editingType = "response"
			} else {
				hm.editingType = "request"
			}
			return nil
		}
	}

	var cmd tea.Cmd
	if hm.editingType == "request" {
		hm.requestList, cmd = hm.requestList.Update(msg)
	} else {
		hm.responseList, cmd = hm.responseList.Update(msg)
	}
	return cmd
}

func (hm *headersManager) View() string {
	if hm.editing {
		return hm.renderForm()
	}

	// 并排显示请求头和响应头
	requestView := hm.requestList.View()
	responseView := hm.responseList.View()

	requestBox := lipgloss.NewStyle().
		Width((hm.requestList.Width() + 4)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("39")).
		Render(requestView)

	responseBox := lipgloss.NewStyle().
		Width((hm.responseList.Width() + 4)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("75")).
		Render(responseView)

	content := lipgloss.JoinHorizontal(lipgloss.Top, requestBox, "  ", responseBox)

	helpText := helpStyle.Render(fmt.Sprintf("当前: %s | t: 切换类型 | a: 添加 | e: 编辑 | d: 删除", hm.editingType))
	return lipgloss.JoinVertical(lipgloss.Left, content, "", helpText)
}

func (hm *headersManager) renderForm() string {
	action := "添加"
	if hm.editingKey != "" {
		action = "编辑"
	}

	typeLabel := "请求头"
	if hm.editingType == "response" {
		typeLabel = "响应头"
	}

	formContent := []string{
		fmt.Sprintf("%s%s", action, typeLabel),
		"",
		fmt.Sprintf("头部名称: %s", hm.keyInput.View()),
		fmt.Sprintf("头部值: %s", hm.valueInput.View()),
		"",
		helpStyle.Render("Tab: 切换字段 | Enter: 保存 | Esc: 取消"),
	}

	if hm.message != "" {
		messageView := ""
		if strings.HasPrefix(hm.message, "❌") {
			messageView = errorStyle.Render(hm.message)
		} else {
			messageView = successStyle.Render(hm.message)
		}
		formContent = append([]string{messageView, ""}, formContent...)
	}

	return strings.Join(formContent, "\n")
}

// GetRequestHeaders 获取请求头映射
func (hm *headersManager) GetRequestHeaders() map[string]string {
	return hm.requestHeaders
}

// GetResponseHeaders 获取响应头映射
func (hm *headersManager) GetResponseHeaders() map[string]string {
	return hm.responseHeaders
}

