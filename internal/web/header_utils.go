package web

import "strings"

// sanitizeHeaderMap 规范化头部键值，移除空键并裁剪空白
func sanitizeHeaderMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string)
	for key, value := range in {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		out[trimmedKey] = trimmedValue
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
