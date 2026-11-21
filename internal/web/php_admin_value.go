package web

import (
	"fmt"
	"sort"
	"strings"
)

// phpAdminValueAllowed 是允许通过 PHP_ADMIN_VALUE 下发的 PHP 指令白名单。
// PHP_ADMIN_VALUE 等价于 php-fpm pool 的 php_admin_value，可覆盖 PHP_INI_SYSTEM，
// 但只允许白名单内的指令进入 FastCGI 请求，避免任意 ini 覆盖。
var phpAdminValueAllowed = map[string]struct{}{
	"memory_limit":                    {},
	"post_max_size":                   {},
	"upload_max_filesize":             {},
	"max_execution_time":              {},
	"max_input_time":                  {},
	"max_input_vars":                  {},
	"max_file_uploads":                {},
	"session.upload_progress.enabled": {},
	"session.use_strict_mode":         {},
	"session.cookie_httponly":         {},
	"session.cookie_secure":           {},
	"session.cookie_samesite":         {},
	"fatal_error_backtraces":          {},
	"display_errors":                  {},
	"log_errors":                      {},
	"error_log":                       {},
	"expose_php":                      {},
	"allow_url_include":               {},
	"disable_functions":               {},
	"opcache.enable":                  {},
	"opcache.validate_timestamps":     {},
	"date.timezone":                   {},
	"default_charset":                 {},
	"short_open_tag":                  {},
}

// PHPIniError 描述站点指令被拒绝的原因，便于 API 返回可读错误。
type PHPIniError struct {
	Directive string
	Reason    string
}

func (e *PHPIniError) Error() string {
	return fmt.Sprintf("php ini %q: %s", e.Directive, e.Reason)
}

// buildPHPAdminValue 将站点 vars 转换为 FastCGI 的 PHP_ADMIN_VALUE 值。
// 键名统一小写并按字典序输出，保证同一配置生成的参数稳定可测。
func buildPHPAdminValue(vars map[string]string) (string, error) {
	if len(vars) == 0 {
		return "", nil
	}

	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, rawKey := range keys {
		key := strings.ToLower(strings.TrimSpace(rawKey))
		if key == "" {
			return "", &PHPIniError{Directive: rawKey, Reason: "指令名为空"}
		}
		if _, ok := phpAdminValueAllowed[key]; !ok {
			return "", &PHPIniError{Directive: key, Reason: "不在允许下发的指令白名单内"}
		}

		if seen[key] {
			return "", &PHPIniError{Directive: key, Reason: "规范化后指令名重复"}
		}
		seen[key] = true

		if strings.ContainsAny(vars[rawKey], "\n\r\x00") {
			return "", &PHPIniError{Directive: key, Reason: "值包含换行或 NUL 字符"}
		}
		value := strings.TrimSpace(vars[rawKey])
		if value == "" {
			continue
		}
		pairs = append(pairs, key+"="+value)
	}

	return strings.Join(pairs, "\n"), nil
}

// sanitizePHPAdminIni 规范化站点 PHP 指令：剔除空值并统一键名为小写。
// 调用前应先用 buildPHPAdminValue 校验，这里只做持久化前的清理。
func sanitizePHPAdminIni(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		key := strings.ToLower(strings.TrimSpace(k))
		value := strings.TrimSpace(v)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
