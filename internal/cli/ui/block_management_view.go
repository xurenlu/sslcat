package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/security"
)

type blockManagementModel struct {
	config          *config.Config
	securityManager *security.Manager
	configFile      string
	list            list.Model
	editing         bool
	editInput       textinput.Model
	editKey         string
	message         string
	width           int
	height          int
	blockType       string // "ip" or "user-agent"
	showAddForm     bool
	addInput        textinput.Model
	addDuration     textinput.Model
	addReason       textinput.Model
	activeInput     int // 0: value, 1: duration, 2: reason
}

type blockItem struct {
	value      string
	reason     string
	blockTime  time.Time
	expireTime time.Time
	itemType   string // "ip" or "user-agent"
}

func (i blockItem) FilterValue() string {
	return i.value + " " + i.reason
}

func (i blockItem) Title() string {
	return i.value
}

func (i blockItem) Description() string {
	remaining := time.Until(i.expireTime)
	remainingStr := formatDuration(remaining)
	return fmt.Sprintf("Reason: %s | Expires: %s (%s)", i.reason, i.expireTime.Format("2006-01-02 15:04:05"), remainingStr)
}

func NewBlockManagementModel(cfg *config.Config, configFile string) blockManagementModel {
	// 创建Security Manager实例
	secMgr := security.NewManager(cfg)
	secMgr.Start()

	items := buildBlockItems(secMgr, "ip")
	listItems := make([]list.Item, len(items))
	for i, item := range items {
		listItems[i] = item
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "封禁管理 - IP"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	// 初始化输入框
	valueInput := textinput.New()
	valueInput.Placeholder = "IP地址或User-Agent..."
	valueInput.Focus()

	durationInput := textinput.New()
	durationInput.Placeholder = "封禁时长 (如: 1h, 24h, 7d, 0=永久)"
	durationInput.SetValue("24h")

	reasonInput := textinput.New()
	reasonInput.Placeholder = "封禁原因 (可选)"

	return blockManagementModel{
		config:          cfg,
		securityManager: secMgr,
		configFile:      configFile,
		list:            l,
		blockType:       "ip",
		addInput:        valueInput,
		addDuration:     durationInput,
		addReason:       reasonInput,
		activeInput:     0,
	}
}

func (m blockManagementModel) Init() tea.Cmd {
	return nil
}

func (m blockManagementModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width - 4)
		m.list.SetHeight(msg.Height - 15)
		return m, nil

	case tea.KeyMsg:
		if m.showAddForm {
			return m.handleAddFormInput(msg)
		}

		switch msg.String() {
		case "ctrl+c", "q":
			if m.securityManager != nil {
				m.securityManager.Stop()
			}
			return m, tea.Quit

		case "esc":
			if m.message != "" {
				m.message = ""
				return m, nil
			}
			if m.securityManager != nil {
				m.securityManager.Stop()
			}
			return m, tea.Quit

		case "tab":
			// 切换封禁类型
			if m.blockType == "ip" {
				m.blockType = "user-agent"
				m.list.Title = "封禁管理 - User-Agent"
			} else {
				m.blockType = "ip"
				m.list.Title = "封禁管理 - IP"
			}
			items := buildBlockItems(m.securityManager, m.blockType)
			listItems := make([]list.Item, len(items))
			for i, item := range items {
				listItems[i] = item
			}
			m.list.SetItems(listItems)
			return m, nil

		case "a", "A":
			// 添加封禁
			m.showAddForm = true
			m.activeInput = 0
			m.addInput.Focus()
			m.addInput.SetValue("")
			m.addDuration.SetValue("24h")
			m.addReason.SetValue("")
			return m, textinput.Blink

		case "d", "delete":
			// 删除选中的封禁
			selected := m.list.SelectedItem()
			if selected != nil {
				item := selected.(blockItem)
				if err := m.unblockItem(item.itemType, item.value); err != nil {
					m.message = fmt.Sprintf("❌ 解封失败: %v", err)
				} else {
					m.message = fmt.Sprintf("✅ %s 已解封", item.value)
					// 刷新列表
					items := buildBlockItems(m.securityManager, m.blockType)
					listItems := make([]list.Item, len(items))
					for i, item := range items {
						listItems[i] = item
					}
					m.list.SetItems(listItems)
				}
			}
			return m, nil

		case "r":
			// 刷新列表
			items := buildBlockItems(m.securityManager, m.blockType)
			listItems := make([]list.Item, len(items))
			for i, item := range items {
				listItems[i] = item
			}
			m.list.SetItems(listItems)
			m.message = "✅ 列表已刷新"
			return m, nil
		}

		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m blockManagementModel) handleAddFormInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		if m.activeInput < 2 {
			// 切换到下一个输入框
			m.activeInput++
			if m.activeInput == 1 {
				m.addInput.Blur()
				m.addDuration.Focus()
				return m, textinput.Blink
			} else if m.activeInput == 2 {
				m.addDuration.Blur()
				m.addReason.Focus()
				return m, textinput.Blink
			}
		} else {
			// 提交表单
			value := strings.TrimSpace(m.addInput.Value())
			durationStr := strings.TrimSpace(m.addDuration.Value())
			reason := strings.TrimSpace(m.addReason.Value())

			if value == "" {
				m.message = "❌ 值不能为空"
				m.showAddForm = false
				return m, nil
			}

			duration, err := parseDurationForBlock(durationStr)
			if err != nil {
				m.message = fmt.Sprintf("❌ 无效的时长格式: %v", err)
				m.showAddForm = false
				return m, nil
			}

			if reason == "" {
				reason = "Manual block via TUI"
			}

			if err := m.blockItem(m.blockType, value, duration, reason); err != nil {
				m.message = fmt.Sprintf("❌ 封禁失败: %v", err)
			} else {
				m.message = fmt.Sprintf("✅ %s 已封禁", value)
				// 刷新列表
				items := buildBlockItems(m.securityManager, m.blockType)
				listItems := make([]list.Item, len(items))
				for i, item := range items {
					listItems[i] = item
				}
				m.list.SetItems(listItems)
			}

			m.showAddForm = false
			m.activeInput = 0
			m.addInput.Blur()
			m.addDuration.Blur()
			m.addReason.Blur()
			return m, nil
		}

	case "esc":
		m.showAddForm = false
		m.activeInput = 0
		m.addInput.Blur()
		m.addDuration.Blur()
		m.addReason.Blur()
		return m, nil

	case "tab":
		m.activeInput = (m.activeInput + 1) % 3
		m.addInput.Blur()
		m.addDuration.Blur()
		m.addReason.Blur()
		switch m.activeInput {
		case 0:
			m.addInput.Focus()
		case 1:
			m.addDuration.Focus()
		case 2:
			m.addReason.Focus()
		}
		return m, textinput.Blink
	}

	var cmd tea.Cmd
	switch m.activeInput {
	case 0:
		m.addInput, cmd = m.addInput.Update(msg)
	case 1:
		m.addDuration, cmd = m.addDuration.Update(msg)
	case 2:
		m.addReason, cmd = m.addReason.Update(msg)
	}
	return m, cmd
}

func (m blockManagementModel) blockItem(itemType, value string, duration time.Duration, reason string) error {
	switch itemType {
	case "ip":
		m.securityManager.BlockIP(value, duration, reason)
	case "user-agent":
		m.securityManager.BlockUserAgent(value, duration, reason)
	default:
		return fmt.Errorf("unknown item type: %s", itemType)
	}
	return nil
}

func (m blockManagementModel) unblockItem(itemType, value string) error {
	switch itemType {
	case "ip":
		m.securityManager.UnblockIP(value) // UnblockIP 内部已经保存
	case "user-agent":
		m.securityManager.UnblockUserAgent(value)
	default:
		return fmt.Errorf("unknown item type: %s", itemType)
	}
	return nil
}

func (m blockManagementModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("封禁管理")

	var content string
	if m.showAddForm {
		content = m.renderAddForm()
	} else {
		listView := m.list.View()
		messageView := ""
		if m.message != "" {
			if strings.HasPrefix(m.message, "❌") {
				messageView = errorStyle.Render(m.message)
			} else {
				messageView = successStyle.Render(m.message)
			}
		}

		typeHint := ""
		if m.blockType == "ip" {
			typeHint = "当前类型: IP (按Tab切换到User-Agent)"
		} else {
			typeHint = "当前类型: User-Agent (按Tab切换到IP)"
		}

		help := renderHelp(map[string]string{
			"↑↓/jk":  "移动",
			"Tab":    "切换类型(IP/User-Agent)",
			"a":      "添加封禁",
			"d":      "解封选中项",
			"r":      "刷新列表",
			"q/Esc":  "返回",
		})

		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			infoStyle.Render(typeHint),
			"",
			listView,
			"",
			messageView,
			"",
			help,
		)
	}

	box := lipgloss.NewStyle().
		Width(m.width - 4).
		MaxWidth(m.width - 4).
		Render(content)

	return box
}

func (m blockManagementModel) renderAddForm() string {
	title := titleStyle.Render("添加封禁")

	valueLabel := "值"
	if m.blockType == "ip" {
		valueLabel = "IP地址"
	} else {
		valueLabel = "User-Agent"
	}

	valueInput := m.addInput.View()
	durationInput := m.addDuration.View()
	reasonInput := m.addReason.View()

	form := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		"",
		fmt.Sprintf("%s:", valueLabel),
		valueInput,
		"",
		"封禁时长 (1h, 24h, 7d, 0=永久):",
		durationInput,
		"",
		"封禁原因 (可选):",
		reasonInput,
		"",
		helpStyle.Render("Enter: 下一个/提交 | Tab: 切换字段 | Esc: 取消"),
	)

	return form
}

func buildBlockItems(secMgr *security.Manager, itemType string) []blockItem {
	var items []blockItem

	if itemType == "ip" {
		blockedIPs := secMgr.GetBlockedIPs()
		for _, blocked := range blockedIPs {
			items = append(items, blockItem{
				value:      blocked.IP,
				reason:     blocked.Reason,
				blockTime:  blocked.BlockTime,
				expireTime: blocked.ExpireTime,
				itemType:   "ip",
			})
		}
	} else {
		blockedUAs := secMgr.GetBlockedUserAgents()
		for _, blocked := range blockedUAs {
			items = append(items, blockItem{
				value:      blocked.UserAgent,
				reason:     blocked.Reason,
				blockTime:  blocked.BlockTime,
				expireTime: blocked.ExpireTime,
				itemType:   "user-agent",
			})
		}
	}

	return items
}

func parseDurationForBlock(s string) (time.Duration, error) {
	if s == "0" {
		return 0, nil // 永久封禁
	}
	return time.ParseDuration(s)
}

