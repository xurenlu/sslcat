package ui

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
	"github.com/xurenlu/sslcat/internal/config"
)

type sslModel struct {
	config     *config.Config
	configFile string
	list       list.Model
	certDetail string
	width      int
	height     int
	message    string
}

type certItem struct {
	name     string
	certPath string
	cert     *x509.Certificate
}

func NewSSLModel(cfg *config.Config, configFile string) sslModel {
	// 扫描证书目录
	certDir := cfg.SSL.CertDir
	if certDir == "" {
		certDir = "./data/certs"
	}

	items := scanCertificates(certDir)

	listItems := make([]list.Item, len(items))
	for i := range items {
		listItems[i] = &items[i]
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "SSL 证书"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)

	return sslModel{
		config:     cfg,
		configFile: configFile,
		list:       l,
	}
}

func (m sslModel) Init() tea.Cmd {
	return nil
}

func (m sslModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetWidth(msg.Width - 4)
		m.list.SetHeight(msg.Height - 10)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "esc":
			if m.certDetail != "" {
				m.certDetail = ""
				return m, nil
			}
			if m.message != "" {
				m.message = ""
				return m, nil
			}
			return m, tea.Quit

		case "enter":
			// 查看证书详情
			selected := m.list.SelectedItem()
			if selected != nil {
				item := selected.(*certItem)
				m.certDetail = m.getCertDetail(item)
			}
			return m, nil

		case "r":
			// 刷新证书列表
			certDir := m.config.SSL.CertDir
			if certDir == "" {
				certDir = "./data/certs"
			}
			items := scanCertificates(certDir)
			listItems := make([]list.Item, len(items))
			for i := range items {
				listItems[i] = &items[i]
			}
			m.list.SetItems(listItems)
			m.message = "✅ 证书列表已刷新"
			return m, nil
		}

		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m sslModel) View() string {
	if m.width == 0 {
		m.width = 80
	}

	title := titleStyle.Render("SSL 证书管理")

	var content string
	if m.certDetail != "" {
		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			m.certDetail,
			"",
			helpStyle.Render("Esc: 返回"),
		)
	} else {
		listView := m.list.View()
		messageView := ""
		if m.message != "" {
			messageView = successStyle.Render(m.message)
		}

		// 显示配置信息
		configInfo := []string{
			fmt.Sprintf("证书目录: %s", m.config.SSL.CertDir),
			fmt.Sprintf("密钥目录: %s", m.config.SSL.KeyDir),
			fmt.Sprintf("邮箱: %s", m.config.SSL.Email),
			fmt.Sprintf("测试环境: %v", m.config.SSL.Staging),
			fmt.Sprintf("自动续期: %v", m.config.SSL.AutoRenew),
		}

		configBox := renderBox("SSL 配置", strings.Join(configInfo, "\n"), m.width)

		help := renderHelp(map[string]string{
			"↑↓/jk":  "移动",
			"Enter":  "查看详情",
			"r":      "刷新列表",
			"q/Esc":  "返回",
		})

		content = lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			configBox,
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

func scanCertificates(certDir string) []certItem {
	var items []certItem

	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		return items
	}

	entries, err := os.ReadDir(certDir)
	if err != nil {
		return items
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
			continue
		}

		certPath := filepath.Join(certDir, name)
		cert, err := loadCertificate(certPath)
		if err != nil {
			// 即使解析失败也添加到列表
			items = append(items, certItem{
				name:     name,
				certPath: certPath,
				cert:     nil,
			})
			continue
		}

		items = append(items, certItem{
			name:     name,
			certPath: certPath,
			cert:     cert,
		})
	}

	return items
}

func loadCertificate(certPath string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("无法解析 PEM 数据")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (m sslModel) getCertDetail(item *certItem) string {
	if item.cert == nil {
		return fmt.Sprintf("证书文件: %s\n❌ 无法解析证书", item.certPath)
	}

	cert := item.cert
	now := time.Now()

	valid := "✅ 有效"
	if now.After(cert.NotAfter) {
		valid = "❌ 已过期"
	} else if now.Before(cert.NotBefore) {
		valid = "⏳ 尚未生效"
	}

	expiresIn := cert.NotAfter.Sub(now)
	expiresInStr := formatDuration(expiresIn)

	detail := []string{
		fmt.Sprintf("证书文件: %s", item.name),
		fmt.Sprintf("状态: %s", valid),
		"",
		fmt.Sprintf("域名: %s", strings.Join(cert.DNSNames, ", ")),
		fmt.Sprintf("颁发者: %s", cert.Issuer.String()),
		fmt.Sprintf("使用者: %s", cert.Subject.String()),
		fmt.Sprintf("序列号: %s", cert.SerialNumber.String()),
		"",
		fmt.Sprintf("生效时间: %s", cert.NotBefore.Format("2006-01-02 15:04:05")),
		fmt.Sprintf("过期时间: %s", cert.NotAfter.Format("2006-01-02 15:04:05")),
		fmt.Sprintf("剩余有效期: %s", expiresInStr),
	}

	return strings.Join(detail, "\n")
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	} else if hours > 0 {
		return fmt.Sprintf("%d 小时 %d 分钟", hours, minutes)
	} else {
		return fmt.Sprintf("%d 分钟", minutes)
	}
}

// 实现 list.Item 接口
func (i *certItem) FilterValue() string {
	return i.name
}

func (i *certItem) Title() string {
	if i.cert == nil {
		return fmt.Sprintf("❌ %s", i.name)
	}

	now := time.Now()
	status := "✓"
	if now.After(i.cert.NotAfter) {
		status = "✗"
	} else if now.Before(i.cert.NotBefore) {
		status = "⏳"
	}

	domains := ""
	if len(i.cert.DNSNames) > 0 {
		domains = " - " + strings.Join(i.cert.DNSNames[:min(3, len(i.cert.DNSNames))], ", ")
		if len(i.cert.DNSNames) > 3 {
			domains += "..."
		}
	}

	return fmt.Sprintf("%s %s%s", status, i.name, domains)
}

func (i *certItem) Description() string {
	if i.cert == nil {
		return "无法解析"
	}

	now := time.Now()
	if now.After(i.cert.NotAfter) {
		return fmt.Sprintf("已过期 (%s)", i.cert.NotAfter.Format("2006-01-02"))
	} else if now.Before(i.cert.NotBefore) {
		return fmt.Sprintf("尚未生效 (%s)", i.cert.NotBefore.Format("2006-01-02"))
	} else {
		expiresIn := i.cert.NotAfter.Sub(now)
		return fmt.Sprintf("剩余 %s", formatDuration(expiresIn))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

