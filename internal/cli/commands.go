package cli

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
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
	commands   map[string]*Command
	config     *config.Config
	configFile string
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

	// 使用反射设置配置值
	if err := m.setConfigValue(m.config, keys, value); err != nil {
		return fmt.Errorf("failed to set config: %w", err)
	}

	// 保存配置到文件
	if err := m.saveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("✅ 配置已更新: %s = %s\n", key, value)
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

	// 解析配置路径
	keys := strings.Split(key, ".")
	if len(keys) < 2 {
		return fmt.Errorf("invalid config key format, use dot notation (e.g., server.port)")
	}

	// 使用反射获取配置值
	value, err := m.getConfigValue(m.config, keys)
	if err != nil {
		return fmt.Errorf("failed to get config: %w", err)
	}

	fmt.Printf("%s = %v\n", key, value)
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
	if len(args) < 2 {
		return fmt.Errorf("usage: sslcat proxy add -domain <domain> -target <target> [-port <port>] [-ssl] [-enabled]")
	}

	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// 解析参数
	var domain, target string
	var port int = 80
	var sslOnly, enabled bool = false, true

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-domain":
			if i+1 >= len(args) {
				return fmt.Errorf("domain value required")
			}
			domain = args[i+1]
			i++
		case "-target":
			if i+1 >= len(args) {
				return fmt.Errorf("target value required")
			}
			target = args[i+1]
			i++
		case "-port":
			if i+1 >= len(args) {
				return fmt.Errorf("port value required")
			}
			var err error
			port, err = strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid port: %s", args[i+1])
			}
			i++
		case "-ssl":
			sslOnly = true
		case "-enabled":
			enabled = true
		case "-disabled":
			enabled = false
		}
	}

	if domain == "" || target == "" {
		return fmt.Errorf("domain and target are required")
	}

	// 检查域名是否已存在
	for _, rule := range m.config.Proxy.Rules {
		if rule.Domain == domain {
			return fmt.Errorf("proxy rule for domain %s already exists", domain)
		}
	}

	// 创建新的代理规则
	newRule := config.ProxyRule{
		Domain:  domain,
		Target:  target,
		Port:    port,
		Enabled: enabled,
		SSLOnly: sslOnly,
	}

	// 添加规则
	m.config.Proxy.Rules = append(m.config.Proxy.Rules, newRule)

	// 保存配置
	if err := m.saveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("✅ 代理规则已添加: %s -> %s:%d (SSL: %t, Enabled: %t)\n",
		domain, target, port, sslOnly, enabled)
	return nil
}

// updateProxyRule 更新代理规则
func (m *Manager) updateProxyRule(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sslcat proxy update -domain <domain> [-target <target>] [-port <port>] [-ssl] [-enabled]")
	}

	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// 解析参数
	var domain, target string
	var port int = -1
	var sslOnly, enabled *bool = nil, nil

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-domain":
			if i+1 >= len(args) {
				return fmt.Errorf("domain value required")
			}
			domain = args[i+1]
			i++
		case "-target":
			if i+1 >= len(args) {
				return fmt.Errorf("target value required")
			}
			target = args[i+1]
			i++
		case "-port":
			if i+1 >= len(args) {
				return fmt.Errorf("port value required")
			}
			var err error
			port, err = strconv.Atoi(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid port: %s", args[i+1])
			}
			i++
		case "-ssl":
			sslOnly = &[]bool{true}[0]
		case "-no-ssl":
			sslOnly = &[]bool{false}[0]
		case "-enabled":
			enabled = &[]bool{true}[0]
		case "-disabled":
			enabled = &[]bool{false}[0]
		}
	}

	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	// 查找并更新规则
	found := false
	for i, rule := range m.config.Proxy.Rules {
		if rule.Domain == domain {
			if target != "" {
				rule.Target = target
			}
			if port != -1 {
				rule.Port = port
			}
			if sslOnly != nil {
				rule.SSLOnly = *sslOnly
			}
			if enabled != nil {
				rule.Enabled = *enabled
			}

			m.config.Proxy.Rules[i] = rule
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("proxy rule for domain %s not found", domain)
	}

	// 保存配置
	if err := m.saveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("✅ 代理规则已更新: %s\n", domain)
	return nil
}

// deleteProxyRule 删除代理规则
func (m *Manager) deleteProxyRule(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sslcat proxy delete -domain <domain>")
	}

	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// 解析参数
	var domain string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-domain":
			if i+1 >= len(args) {
				return fmt.Errorf("domain value required")
			}
			domain = args[i+1]
			i++
		}
	}

	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	// 查找并删除规则
	found := false
	for i, rule := range m.config.Proxy.Rules {
		if rule.Domain == domain {
			m.config.Proxy.Rules = append(m.config.Proxy.Rules[:i], m.config.Proxy.Rules[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("proxy rule for domain %s not found", domain)
	}

	// 保存配置
	if err := m.saveConfig(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("✅ 代理规则已删除: %s\n", domain)
	return nil
}

// RegisterSSLCommands 注册 SSL 证书管理命令
func (m *Manager) RegisterSSLCommands() {
	m.RegisterCommand(&Command{
		Name:        "ssl",
		Description: "SSL certificate management",
		Handler: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("ssl subcommand required (list|show|request|renew|delete)")
			}

			subcmd := args[0]
			switch subcmd {
			case "list":
				return m.listCertificates(args[1:])
			case "show":
				return m.showCertificate(args[1:])
			case "request":
				return m.requestCertificate(args[1:])
			case "renew":
				return m.renewCertificate(args[1:])
			case "delete":
				return m.deleteCertificate(args[1:])
			default:
				return fmt.Errorf("unknown ssl subcommand: %s", subcmd)
			}
		},
	})
}

// listCertificates 列出所有证书
func (m *Manager) listCertificates(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	fmt.Println("SSL Certificates:")
	fmt.Println("=================")

	// 这里需要实现证书列表功能
	// 由于需要访问 SSL 管理器，暂时显示占位信息
	fmt.Println("Note: SSL certificate listing requires SSL manager integration")
	fmt.Println("Available domains from config:")

	for _, rule := range m.config.Proxy.Rules {
		if rule.Enabled {
			fmt.Printf("  - %s\n", rule.Domain)
		}
	}

	return nil
}

// showCertificate 显示证书详情
func (m *Manager) showCertificate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sslcat ssl show -domain <domain>")
	}

	var domain string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-domain":
			if i+1 >= len(args) {
				return fmt.Errorf("domain value required")
			}
			domain = args[i+1]
			i++
		}
	}

	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	fmt.Printf("Certificate details for %s:\n", domain)
	fmt.Println("Note: SSL certificate details require SSL manager integration")

	return nil
}

// requestCertificate 申请证书
func (m *Manager) requestCertificate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sslcat ssl request -domain <domain> [-email <email>]")
	}

	var domain, email string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-domain":
			if i+1 >= len(args) {
				return fmt.Errorf("domain value required")
			}
			domain = args[i+1]
			i++
		case "-email":
			if i+1 >= len(args) {
				return fmt.Errorf("email value required")
			}
			email = args[i+1]
			i++
		}
	}

	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	if email == "" {
		email = m.config.SSL.Email
		if email == "" {
			return fmt.Errorf("email is required (use -email flag or set ssl.email in config)")
		}
	}

	fmt.Printf("Requesting SSL certificate for %s (email: %s)\n", domain, email)
	fmt.Println("Note: SSL certificate request requires SSL manager integration")

	return nil
}

// renewCertificate 续期证书
func (m *Manager) renewCertificate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sslcat ssl renew -domain <domain>")
	}

	var domain string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-domain":
			if i+1 >= len(args) {
				return fmt.Errorf("domain value required")
			}
			domain = args[i+1]
			i++
		}
	}

	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	fmt.Printf("Renewing SSL certificate for %s\n", domain)
	fmt.Println("Note: SSL certificate renewal requires SSL manager integration")

	return nil
}

// deleteCertificate 删除证书
func (m *Manager) deleteCertificate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sslcat ssl delete -domain <domain>")
	}

	var domain string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-domain":
			if i+1 >= len(args) {
				return fmt.Errorf("domain value required")
			}
			domain = args[i+1]
			i++
		}
	}

	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	fmt.Printf("Deleting SSL certificate for %s\n", domain)
	fmt.Println("Note: SSL certificate deletion requires SSL manager integration")

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

// RegisterConsoleCommand 注册控制台命令
func (m *Manager) RegisterConsoleCommand() {
	m.RegisterCommand(&Command{
		Name:        "console",
		Description: "Interactive terminal UI console",
		Handler: func(args []string) error {
			if m.config == nil {
				return fmt.Errorf("no configuration loaded")
			}
			return RunConsole(m.config, m.configFile)
		},
	})

	// 同时注册 interactive 作为别名
	m.RegisterCommand(&Command{
		Name:        "interactive",
		Description: "Interactive terminal UI console (alias for console)",
		Handler: func(args []string) error {
			if m.config == nil {
				return fmt.Errorf("no configuration loaded")
			}
			return RunConsole(m.config, m.configFile)
		},
	})
}

// setConfigValue 使用反射设置配置值
func (m *Manager) setConfigValue(obj interface{}, keys []string, value string) error {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// 遍历路径，找到目标字段
	for _, key := range keys[:len(keys)-1] {
		field := v.FieldByName(strings.Title(key))
		if !field.IsValid() {
			return fmt.Errorf("field %s not found", key)
		}

		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				field.Set(reflect.New(field.Type().Elem()))
			}
			field = field.Elem()
		}

		v = field
	}

	// 设置最后一个字段的值
	lastKey := keys[len(keys)-1]
	field := v.FieldByName(strings.Title(lastKey))
	if !field.IsValid() {
		return fmt.Errorf("field %s not found", lastKey)
	}

	if !field.CanSet() {
		return fmt.Errorf("field %s cannot be set", lastKey)
	}

	// 根据字段类型转换值
	if err := m.setFieldValue(field, value); err != nil {
		return fmt.Errorf("failed to set field %s: %w", lastKey, err)
	}

	return nil
}

// getConfigValue 使用反射获取配置值
func (m *Manager) getConfigValue(obj interface{}, keys []string) (interface{}, error) {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	// 遍历路径，找到目标字段
	for _, key := range keys {
		field := v.FieldByName(strings.Title(key))
		if !field.IsValid() {
			return nil, fmt.Errorf("field %s not found", key)
		}

		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				return nil, fmt.Errorf("field %s is nil", key)
			}
			field = field.Elem()
		}

		v = field
	}

	return v.Interface(), nil
}

// setFieldValue 根据字段类型设置值
func (m *Manager) setFieldValue(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		intVal, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer value: %s", value)
		}
		field.SetInt(intVal)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		uintVal, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid unsigned integer value: %s", value)
		}
		field.SetUint(uintVal)
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean value: %s", value)
		}
		field.SetBool(boolVal)
	case reflect.Float32, reflect.Float64:
		floatVal, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return fmt.Errorf("invalid float value: %s", value)
		}
		field.SetFloat(floatVal)
	default:
		return fmt.Errorf("unsupported field type: %s", field.Kind())
	}

	return nil
}

// saveConfig 保存配置到文件
func (m *Manager) saveConfig() error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	configFile := m.configFile
	if configFile == "" {
		configFile = "sslcat.conf"
	}

	// 使用 Config.Save 方法，它会自动只保存与默认值不同的配置
	if err := m.config.Save(configFile); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

// SetConfig 设置配置
func (m *Manager) SetConfig(cfg *config.Config) {
	m.config = cfg
}

// SetConfigFile 设置配置文件路径
func (m *Manager) SetConfigFile(configFile string) {
	m.configFile = configFile
}
