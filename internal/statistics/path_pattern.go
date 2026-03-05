package statistics

import (
	"regexp"
	"strings"
)

// pathPatternRe 匹配数字、UUID、十六进制 ID 等
var (
	digitsRe   = regexp.MustCompile(`^\d+$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexIdRe    = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`) // 长 hex 如 objectid
	slugRe     = regexp.MustCompile(`^[a-z0-9-]{20,}$`)  // 长 slug
)

// BuildAPIPatternKey 构建带域名的学习 key，用于二次学习
// host 为空时仅用 path；否则 host:pathPattern，使不同域名的同 path 分开学习
// 例：log.17push.com + /api/v1/ingest -> log.17push.com:/api/v1/*
func BuildAPIPatternKey(host, path string) string {
	pattern := ToPathPattern(path)
	if host == "" {
		return pattern
	}
	// 去掉端口
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return host + ":" + pattern
}

// ToPathPattern 将具体 path 归一化为 pattern，用于二次学习
// /api/users/123 -> /api/users/*
// /api/orders/550e8400-e29b-41d4-a716-446655440000 -> /api/orders/*
// /api/v1/users -> /api/v1/users（无变化）
func ToPathPattern(path string) string {
	if path == "" || path == "/" {
		return path
	}
	path = strings.TrimSuffix(path, "/")
	segments := strings.Split(path, "/")

	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if digitsRe.MatchString(seg) {
			segments[i] = "*"
			continue
		}
		if uuidRe.MatchString(seg) {
			segments[i] = "*"
			continue
		}
		if len(seg) >= 16 && hexIdRe.MatchString(seg) {
			segments[i] = "*"
			continue
		}
		if len(seg) >= 20 && slugRe.MatchString(seg) {
			segments[i] = "*"
			continue
		}
	}
	return strings.Join(segments, "/")
}
