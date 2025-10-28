package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// Command 表示一个 CLI 命令
type Command struct {
	Name        string
	Description string
	Handler     func(args []string) error
}

// CLI 管理器
type Manager struct {
	commands map[string]*Command
	config   *config.Config
}

// NewManager 创建新的 CLI 管理器
func NewManager() *Manager {
	return &Manager{
		commands: make(map[string]*Command),
	}
}

// RegisterCommand 注册命令
func (m *Manager) RegisterCommand(cmd *Command) {
	m.commands[cmd.Name] = cmd
}

// Execute 执行命令
func (m *Manager) Execute(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	commandName := args[0]
	cmd, exists := m.commands[commandName]
	if !exists {
		return fmt.Errorf("unknown command: %s", commandName)
	}

	return cmd.Handler(args[1:])
}

// ShowHelp 显示帮助信息
func (m *Manager) ShowHelp() {
	fmt.Println("SSLcat CLI Commands:")
	fmt.Println()

	for name, cmd := range m.commands {
		fmt.Printf("  %-15s %s\n", name, cmd.Description)
	}
	fmt.Println()
	fmt.Println("Use 'sslcat <command> --help' for detailed help")
}

// 配置管理命令
func (m *Manager) RegisterConfigCommands() {
	// config show
	m.RegisterCommand(&Command{
		Name:        "config",
		Description: "Configuration management",
		Handler: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("config subcommand required (show|set|get)")
			}

			subcmd := args[0]
			switch subcmd {
			case "show":
				return m.showConfig(args[1:])
			case "set":
				return m.setConfig(args[1:])
			case "get":
				return m.getConfig(args[1:])
			default:
				return fmt.Errorf("unknown config subcommand: %s", subcmd)
			}
		},
	})
}

// showConfig 显示配置
func (m *Manager) showConfig(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// 格式化输出配置
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// setConfig 设置配置项
func (m *Manager) setConfig(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: sslcat config set <key> <value>")
	}

	key := args[0]
	value := args[1]

	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// 解析配置路径 (例如: server.port, ssl.email)
	keys := strings.Split(key, ".")
	if len(keys) < 2 {
		return fmt.Errorf("invalid config key format, use dot notation (e.g., server.port)")
	}

	// 这里需要实现配置项的设置逻辑
	// 由于配置结构复杂，建议使用反射或专门的设置函数
	fmt.Printf("Setting %s = %s\n", key, value)
	fmt.Println("Note: Configuration modification not yet implemented")

	return nil
}

// getConfig 获取配置项
func (m *Manager) getConfig(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sslcat config get <key>")
	}

	key := args[0]

	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// 这里需要实现配置项的获取逻辑
	fmt.Printf("Getting %s\n", key)
	fmt.Println("Note: Configuration reading not yet implemented")

	return nil
}

// 代理管理命令
func (m *Manager) RegisterProxyCommands() {
	m.RegisterCommand(&Command{
		Name:        "proxy",
		Description: "Proxy management",
		Handler: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("proxy subcommand required (list|add|update|delete)")
			}

			subcmd := args[0]
			switch subcmd {
			case "list":
				return m.listProxyRules(args[1:])
			case "add":
				return m.addProxyRule(args[1:])
			case "update":
				return m.updateProxyRule(args[1:])
			case "delete":
				return m.deleteProxyRule(args[1:])
			default:
				return fmt.Errorf("unknown proxy subcommand: %s", subcmd)
			}
		},
	})
}

// listProxyRules 列出代理规则
func (m *Manager) listProxyRules(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	fmt.Println("Proxy Rules:")
	fmt.Println("============")

	for i, rule := range m.config.Proxy.Rules {
		fmt.Printf("%d. Domain: %s\n", i+1, rule.Domain)
		fmt.Printf("   Target: %s:%d\n", rule.Target, rule.Port)
		fmt.Printf("   Enabled: %t\n", rule.Enabled)
		fmt.Printf("   SSL Only: %t\n", rule.SSLOnly)
		fmt.Println()
	}

	return nil
}

// addProxyRule 添加代理规则
func (m *Manager) addProxyRule(args []string) error {
	fmt.Println("Adding proxy rule...")
	fmt.Println("Note: Proxy rule addition not yet implemented")
	return nil
}

// updateProxyRule 更新代理规则
func (m *Manager) updateProxyRule(args []string) error {
	fmt.Println("Updating proxy rule...")
	fmt.Println("Note: Proxy rule update not yet implemented")
	return nil
}

// deleteProxyRule 删除代理规则
func (m *Manager) deleteProxyRule(args []string) error {
	fmt.Println("Deleting proxy rule...")
	fmt.Println("Note: Proxy rule deletion not yet implemented")
	return nil
}

// RegisterHelpCommand 注册帮助命令
func (m *Manager) RegisterHelpCommand() {
	m.RegisterCommand(&Command{
		Name:        "help",
		Description: "Show help information",
		Handler: func(args []string) error {
			m.ShowHelp()
			return nil
		},
	})
}

// SetConfig 设置配置
func (m *Manager) SetConfig(cfg *config.Config) {
	m.config = cfg
}
