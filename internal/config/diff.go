package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// KeyChange 描述一个字段的变更
type KeyChange struct {
	Key string `json:"key"`
	Old string `json:"old"`
	New string `json:"new"`
}

// ProxyRuleChange 描述某个域名规则的变更
type ProxyRuleChange struct {
	Domain       string      `json:"domain"`
	FieldChanges []KeyChange `json:"field_changes"`
	Old          ProxyRule   `json:"old"`
	New          ProxyRule   `json:"new"`
}

// ConfigDiff 总体差异
type ConfigDiff struct {
	ServerChanges       []KeyChange       `json:"server_changes"`
	SSLChanges          []KeyChange       `json:"ssl_changes"`
	AdminChanges        []KeyChange       `json:"admin_changes"`
	SecurityChanges     []KeyChange       `json:"security_changes"`
	CompressionChanges  []KeyChange       `json:"compression_changes"`
	CDNCacheChanges     []KeyChange       `json:"cdn_cache_changes"`
	NotificationChanges []KeyChange       `json:"notification_changes"`
	AdminPrefix         *KeyChange        `json:"admin_prefix,omitempty"`
	ProxyAdded          []ProxyRule       `json:"proxy_added"`
	ProxyRemoved        []ProxyRule       `json:"proxy_removed"`
	ProxyModified       []ProxyRuleChange `json:"proxy_modified"`
	HasChanges          bool              `json:"has_changes"`
}

func stringOf[T any](v T) string { return fmt.Sprintf("%v", v) }

func compareStruct(a, b any, fields []string, prefix string) (changes []KeyChange) {
	va := reflect.ValueOf(a)
	vb := reflect.ValueOf(b)
	if va.Kind() == reflect.Pointer {
		va = va.Elem()
	}
	if vb.Kind() == reflect.Pointer {
		vb = vb.Elem()
	}
	for _, f := range fields {
		fa := va.FieldByName(f)
		fb := vb.FieldByName(f)
		if !fa.IsValid() || !fb.IsValid() {
			continue
		}
		if reflect.DeepEqual(fa.Interface(), fb.Interface()) {
			continue
		}
		changes = append(changes, KeyChange{Key: prefix + f, Old: stringOf(fa.Interface()), New: stringOf(fb.Interface())})
	}
	return
}

func CompareConfigs(cur, prop *Config) ConfigDiff {
	diff := ConfigDiff{}

	diff.ServerChanges = compareStruct(&cur.Server, &prop.Server, []string{"Host", "Port", "Debug"}, "server.")
	diff.SSLChanges = compareStruct(&cur.SSL, &prop.SSL, []string{"Email", "Staging", "CertDir", "KeyDir", "AutoRenew", "DisableSelfSigned"}, "ssl.")

	// SSL Domains 需要特殊处理
	if !reflect.DeepEqual(cur.SSL.Domains, prop.SSL.Domains) {
		diff.SSLChanges = append(diff.SSLChanges, KeyChange{
			Key: "ssl.domains",
			Old: fmt.Sprintf("[%s]", strings.Join(cur.SSL.Domains, ", ")),
			New: fmt.Sprintf("[%s]", strings.Join(prop.SSL.Domains, ", ")),
		})
	}

	// Admin: 不直接展示密码明文
	if cur.Admin.Username != prop.Admin.Username {
		diff.AdminChanges = append(diff.AdminChanges, KeyChange{Key: "admin.username", Old: cur.Admin.Username, New: prop.Admin.Username})
	}
	if cur.Admin.Password != prop.Admin.Password {
		diff.AdminChanges = append(diff.AdminChanges, KeyChange{Key: "admin.password", Old: "(已设置)", New: "(已修改)"})
	}
	if cur.Admin.FirstRun != prop.Admin.FirstRun {
		diff.AdminChanges = append(diff.AdminChanges, KeyChange{Key: "admin.first_run", Old: stringOf(cur.Admin.FirstRun), New: stringOf(prop.Admin.FirstRun)})
	}
	if cur.Admin.PasswordFile != prop.Admin.PasswordFile {
		diff.AdminChanges = append(diff.AdminChanges, KeyChange{Key: "admin.password_file", Old: cur.Admin.PasswordFile, New: prop.Admin.PasswordFile})
	}

	// Security
	diff.SecurityChanges = append(diff.SecurityChanges, simpleDiff("security.max_attempts", cur.Security.MaxAttempts, prop.Security.MaxAttempts)...)
	diff.SecurityChanges = append(diff.SecurityChanges, simpleDiff("security.block_duration", cur.Security.BlockDurationStr, prop.Security.BlockDurationStr)...)
	diff.SecurityChanges = append(diff.SecurityChanges, simpleDiff("security.max_attempts_5min", cur.Security.MaxAttempts5Min, prop.Security.MaxAttempts5Min)...)
	if !reflect.DeepEqual(cur.Security.AllowedUserAgents, prop.Security.AllowedUserAgents) {
		diff.SecurityChanges = append(diff.SecurityChanges, KeyChange{
			Key: "security.allowed_user_agents",
			Old: stringOf(cur.Security.AllowedUserAgents),
			New: stringOf(prop.Security.AllowedUserAgents),
		})
	}
	if cur.Security.BlockFile != prop.Security.BlockFile {
		diff.SecurityChanges = append(diff.SecurityChanges, KeyChange{Key: "security.block_file", Old: cur.Security.BlockFile, New: prop.Security.BlockFile})
	}
	// TLS 指纹相关配置
	diff.SecurityChanges = append(diff.SecurityChanges, simpleDiff("security.tls_fp_window_sec", cur.Security.TLSFingerprintWindowSec, prop.Security.TLSFingerprintWindowSec)...)
	diff.SecurityChanges = append(diff.SecurityChanges, simpleDiff("security.tls_fp_max_per_min", cur.Security.TLSFingerprintMaxPerMin, prop.Security.TLSFingerprintMaxPerMin)...)
	diff.SecurityChanges = append(diff.SecurityChanges, simpleDiff("security.tls_fp_top_n", cur.Security.TLSFingerprintTopN, prop.Security.TLSFingerprintTopN)...)

	// Compression 配置比较
	diff.CompressionChanges = compareCompressionConfigs(cur.Compression, prop.Compression)

	// CDN Cache 配置比较
	diff.CDNCacheChanges = compareCDNCacheConfigs(cur.CDNCache, prop.CDNCache)

	// Notification 配置比较
	diff.NotificationChanges = compareNotificationConfigs(cur.Notification, prop.Notification)

	if cur.AdminPrefix != prop.AdminPrefix {
		kc := KeyChange{Key: "admin_prefix", Old: cur.AdminPrefix, New: prop.AdminPrefix}
		diff.AdminPrefix = &kc
	}

	// Proxy rules
	curMap := make(map[string]ProxyRule)
	for _, r := range cur.Proxy.Rules {
		curMap[r.Domain] = r
	}
	propMap := make(map[string]ProxyRule)
	for _, r := range prop.Proxy.Rules {
		propMap[r.Domain] = r
	}

	// Added & Modified
	for dom, nr := range propMap {
		if or, ok := curMap[dom]; !ok {
			diff.ProxyAdded = append(diff.ProxyAdded, nr)
		} else {
			if !reflect.DeepEqual(or, nr) {
				var fcs []KeyChange
				if or.Target != nr.Target {
					fcs = append(fcs, KeyChange{Key: "target", Old: or.Target, New: nr.Target})
				}
				if or.Port != nr.Port {
					fcs = append(fcs, KeyChange{Key: "port", Old: stringOf(or.Port), New: stringOf(nr.Port)})
				}
				if or.Enabled != nr.Enabled {
					fcs = append(fcs, KeyChange{Key: "enabled", Old: stringOf(or.Enabled), New: stringOf(nr.Enabled)})
				}
				if or.SSLOnly != nr.SSLOnly {
					fcs = append(fcs, KeyChange{Key: "ssl_only", Old: stringOf(or.SSLOnly), New: stringOf(nr.SSLOnly)})
				}

				// 负载均衡配置比较
				if or.LoadBalancerEnabled != nr.LoadBalancerEnabled {
					fcs = append(fcs, KeyChange{Key: "load_balancer_enabled", Old: stringOf(or.LoadBalancerEnabled), New: stringOf(nr.LoadBalancerEnabled)})
				}
				if or.LoadBalancerAlgorithm != nr.LoadBalancerAlgorithm {
					fcs = append(fcs, KeyChange{Key: "load_balancer_algorithm", Old: or.LoadBalancerAlgorithm, New: nr.LoadBalancerAlgorithm})
				}
				if !reflect.DeepEqual(or.LoadBalancerBackends, nr.LoadBalancerBackends) {
					fcs = append(fcs, KeyChange{Key: "load_balancer_backends", Old: fmt.Sprintf("%d backends", len(or.LoadBalancerBackends)), New: fmt.Sprintf("%d backends", len(nr.LoadBalancerBackends))})
				}

				// 会话保持配置比较
				if or.SessionAffinityEnabled != nr.SessionAffinityEnabled {
					fcs = append(fcs, KeyChange{Key: "session_affinity_enabled", Old: stringOf(or.SessionAffinityEnabled), New: stringOf(nr.SessionAffinityEnabled)})
				}
				if or.SessionAffinityMethod != nr.SessionAffinityMethod {
					fcs = append(fcs, KeyChange{Key: "session_affinity_method", Old: or.SessionAffinityMethod, New: nr.SessionAffinityMethod})
				}

				// 健康检查配置比较
				if or.HealthCheckEnabled != nr.HealthCheckEnabled {
					fcs = append(fcs, KeyChange{Key: "health_check_enabled", Old: stringOf(or.HealthCheckEnabled), New: stringOf(nr.HealthCheckEnabled)})
				}
				if or.HealthCheckPath != nr.HealthCheckPath {
					fcs = append(fcs, KeyChange{Key: "health_check_path", Old: or.HealthCheckPath, New: nr.HealthCheckPath})
				}
				if or.HealthCheckInterval != nr.HealthCheckInterval {
					fcs = append(fcs, KeyChange{Key: "health_check_interval", Old: stringOf(or.HealthCheckInterval), New: stringOf(nr.HealthCheckInterval)})
				}

				// CDN配置比较
				if or.CDNEnabled != nr.CDNEnabled {
					fcs = append(fcs, KeyChange{Key: "cdn_enabled", Old: stringOf(or.CDNEnabled), New: stringOf(nr.CDNEnabled)})
				}
				if or.CDNPreset != nr.CDNPreset {
					fcs = append(fcs, KeyChange{Key: "cdn_preset", Old: or.CDNPreset, New: nr.CDNPreset})
				}

				if len(fcs) > 0 {
					diff.ProxyModified = append(diff.ProxyModified, ProxyRuleChange{Domain: dom, FieldChanges: fcs, Old: or, New: nr})
				}
			}
		}
	}

	// Removed
	for dom, or := range curMap {
		if _, ok := propMap[dom]; !ok {
			diff.ProxyRemoved = append(diff.ProxyRemoved, or)
		}
	}

	// 标记是否有变更
	total := len(diff.ServerChanges) + len(diff.SSLChanges) + len(diff.AdminChanges) + len(diff.SecurityChanges) +
		len(diff.CompressionChanges) + len(diff.CDNCacheChanges) + len(diff.NotificationChanges) +
		len(diff.ProxyAdded) + len(diff.ProxyRemoved) + len(diff.ProxyModified)
	if diff.AdminPrefix != nil {
		total++
	}
	diff.HasChanges = total > 0

	// 稳定输出顺序
	sort.Slice(diff.ProxyAdded, func(i, j int) bool { return diff.ProxyAdded[i].Domain < diff.ProxyAdded[j].Domain })
	sort.Slice(diff.ProxyRemoved, func(i, j int) bool { return diff.ProxyRemoved[i].Domain < diff.ProxyRemoved[j].Domain })
	sort.Slice(diff.ProxyModified, func(i, j int) bool { return diff.ProxyModified[i].Domain < diff.ProxyModified[j].Domain })
	return diff
}

func simpleDiff[T comparable](key string, a, b T) []KeyChange {
	if a == b {
		return nil
	}
	return []KeyChange{{Key: key, Old: stringOf(a), New: stringOf(b)}}
}

// compareNotificationConfigs 比较通知配置
func compareNotificationConfigs(cur, prop NotificationConfig) []KeyChange {
	var changes []KeyChange

	// 基本配置
	changes = append(changes, simpleDiff("notification.enabled", cur.Enabled, prop.Enabled)...)

	// 邮件配置
	emailChanges := compareEmailChannelConfigs(cur.Channels.Email, prop.Channels.Email)
	changes = append(changes, emailChanges...)

	// Webhook配置
	webhookChanges := compareWebhookChannelConfigs(cur.Channels.Webhook, prop.Channels.Webhook)
	changes = append(changes, webhookChanges...)

	// 系统日志配置
	syslogChanges := compareSyslogChannelConfigs(cur.Channels.Syslog, prop.Channels.Syslog)
	changes = append(changes, syslogChanges...)

	// 控制台配置
	consoleChanges := compareConsoleChannelConfigs(cur.Channels.Console, prop.Channels.Console)
	changes = append(changes, consoleChanges...)

	return changes
}

// compareEmailChannelConfigs 比较邮件渠道配置
func compareEmailChannelConfigs(cur, prop EmailChannelConfig) []KeyChange {
	var changes []KeyChange
	prefix := "notification.channels.email."

	changes = append(changes, simpleDiff(prefix+"enabled", cur.Enabled, prop.Enabled)...)
	changes = append(changes, simpleDiff(prefix+"smtp_host", cur.SMTPHost, prop.SMTPHost)...)
	changes = append(changes, simpleDiff(prefix+"smtp_port", cur.SMTPPort, prop.SMTPPort)...)
	changes = append(changes, simpleDiff(prefix+"username", cur.Username, prop.Username)...)

	// 密码需要特殊处理，不显示明文
	if cur.Password != prop.Password {
		changes = append(changes, KeyChange{
			Key: prefix + "password",
			Old: "(已设置)",
			New: "(已修改)",
		})
	}

	changes = append(changes, simpleDiff(prefix+"from", cur.From, prop.From)...)

	// To字段需要特殊处理数组
	if !reflect.DeepEqual(cur.To, prop.To) {
		changes = append(changes, KeyChange{
			Key: prefix + "to",
			Old: fmt.Sprintf("[%s]", strings.Join(cur.To, ", ")),
			New: fmt.Sprintf("[%s]", strings.Join(prop.To, ", ")),
		})
	}

	changes = append(changes, simpleDiff(prefix+"use_tls", cur.UseTLS, prop.UseTLS)...)

	return changes
}

// compareWebhookChannelConfigs 比较Webhook渠道配置
func compareWebhookChannelConfigs(cur, prop WebhookChannelConfig) []KeyChange {
	var changes []KeyChange
	prefix := "notification.channels.webhook."

	changes = append(changes, simpleDiff(prefix+"enabled", cur.Enabled, prop.Enabled)...)
	changes = append(changes, simpleDiff(prefix+"url", cur.URL, prop.URL)...)
	changes = append(changes, simpleDiff(prefix+"timeout", cur.Timeout, prop.Timeout)...)

	// Headers需要特殊处理
	if !reflect.DeepEqual(cur.Headers, prop.Headers) {
		changes = append(changes, KeyChange{
			Key: prefix + "headers",
			Old: stringOf(cur.Headers),
			New: stringOf(prop.Headers),
		})
	}

	return changes
}

// compareSyslogChannelConfigs 比较系统日志渠道配置
func compareSyslogChannelConfigs(cur, prop SyslogChannelConfig) []KeyChange {
	var changes []KeyChange
	prefix := "notification.channels.syslog."

	changes = append(changes, simpleDiff(prefix+"enabled", cur.Enabled, prop.Enabled)...)
	changes = append(changes, simpleDiff(prefix+"address", cur.Address, prop.Address)...)
	changes = append(changes, simpleDiff(prefix+"network", cur.Network, prop.Network)...)

	return changes
}

// compareConsoleChannelConfigs 比较控制台渠道配置
func compareConsoleChannelConfigs(cur, prop ConsoleChannelConfig) []KeyChange {
	var changes []KeyChange
	prefix := "notification.channels.console."

	changes = append(changes, simpleDiff(prefix+"enabled", cur.Enabled, prop.Enabled)...)

	return changes
}

// compareCompressionConfigs 比较压缩配置
func compareCompressionConfigs(cur, prop CompressionConfig) []KeyChange {
	var changes []KeyChange
	prefix := "compression."

	changes = append(changes, simpleDiff(prefix+"enabled", cur.Enabled, prop.Enabled)...)
	changes = append(changes, simpleDiff(prefix+"min_size", cur.MinSize, prop.MinSize)...)
	changes = append(changes, simpleDiff(prefix+"level.gzip", cur.Level.Gzip, prop.Level.Gzip)...)
	changes = append(changes, simpleDiff(prefix+"level.brotli", cur.Level.Brotli, prop.Level.Brotli)...)

	// 算法数组比较
	if !reflect.DeepEqual(cur.Algorithms, prop.Algorithms) {
		changes = append(changes, KeyChange{
			Key: prefix + "algorithms",
			Old: fmt.Sprintf("[%s]", strings.Join(cur.Algorithms, ", ")),
			New: fmt.Sprintf("[%s]", strings.Join(prop.Algorithms, ", ")),
		})
	}

	// 文件类型数组比较
	if !reflect.DeepEqual(cur.Types, prop.Types) {
		changes = append(changes, KeyChange{
			Key: prefix + "types",
			Old: fmt.Sprintf("%d types", len(cur.Types)),
			New: fmt.Sprintf("%d types", len(prop.Types)),
		})
	}

	// 排除类型数组比较
	if !reflect.DeepEqual(cur.ExcludedTypes, prop.ExcludedTypes) {
		changes = append(changes, KeyChange{
			Key: prefix + "excluded_types",
			Old: fmt.Sprintf("%d types", len(cur.ExcludedTypes)),
			New: fmt.Sprintf("%d types", len(prop.ExcludedTypes)),
		})
	}

	return changes
}

// compareCDNCacheConfigs 比较CDN缓存配置
func compareCDNCacheConfigs(cur, prop CDNCacheConfig) []KeyChange {
	var changes []KeyChange
	prefix := "cdn_cache."

	changes = append(changes, simpleDiff(prefix+"enabled", cur.Enabled, prop.Enabled)...)
	changes = append(changes, simpleDiff(prefix+"cache_dir", cur.CacheDir, prop.CacheDir)...)
	changes = append(changes, simpleDiff(prefix+"max_size_bytes", cur.MaxSizeBytes, prop.MaxSizeBytes)...)
	changes = append(changes, simpleDiff(prefix+"default_ttl_seconds", cur.DefaultTTLSeconds, prop.DefaultTTLSeconds)...)
	changes = append(changes, simpleDiff(prefix+"clean_interval_seconds", cur.CleanIntervalSec, prop.CleanIntervalSec)...)
	changes = append(changes, simpleDiff(prefix+"max_object_bytes", cur.MaxObjectBytes, prop.MaxObjectBytes)...)

	// 缓存规则比较
	if !reflect.DeepEqual(cur.Rules, prop.Rules) {
		changes = append(changes, KeyChange{
			Key: prefix + "rules",
			Old: fmt.Sprintf("%d rules", len(cur.Rules)),
			New: fmt.Sprintf("%d rules", len(prop.Rules)),
		})
	}

	return changes
}
