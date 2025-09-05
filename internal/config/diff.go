package config

import (
	"fmt"
	"reflect"
	"sort"
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
	ServerChanges   []KeyChange       `json:"server_changes"`
	SSLChanges      []KeyChange       `json:"ssl_changes"`
	AdminChanges    []KeyChange       `json:"admin_changes"`
	SecurityChanges []KeyChange       `json:"security_changes"`
	AdminPrefix     *KeyChange        `json:"admin_prefix,omitempty"`
	ProxyAdded      []ProxyRule       `json:"proxy_added"`
	ProxyRemoved    []ProxyRule       `json:"proxy_removed"`
	ProxyModified   []ProxyRuleChange `json:"proxy_modified"`
	HasChanges      bool              `json:"has_changes"`
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
	diff.SSLChanges = compareStruct(&cur.SSL, &prop.SSL, []string{"Email", "Staging", "CertDir", "KeyDir", "AutoRenew"}, "ssl.")

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
				diff.ProxyModified = append(diff.ProxyModified, ProxyRuleChange{Domain: dom, FieldChanges: fcs, Old: or, New: nr})
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
	total := len(diff.ServerChanges) + len(diff.SSLChanges) + len(diff.AdminChanges) + len(diff.SecurityChanges) + len(diff.ProxyAdded) + len(diff.ProxyRemoved) + len(diff.ProxyModified)
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
