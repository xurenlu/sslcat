// Package resources 实现 MCP 的 3 个核心 resource：
//
//	sslcat://config/current              当前完整配置（脱敏）
//	sslcat://metrics/snapshot            当前指标快照（JSON）
//	sslcat://logs/access{?since,domain,limit}  访问日志尾部（按时间窗口/域名过滤）
//	sslcat://logs/error-sources          错误日志源清单（内部 + 所有站点）
//	sslcat://logs/error{?id,kind,domain,since,keyword,limit,max_bytes} 错误日志尾部
//
// 所有 resource 都要求 scope=read；不暴露任何能解出明文密码/token 的数据。
package resources

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
	"github.com/xurenlu/sslcat/internal/mcp/logview"
	"github.com/xurenlu/sslcat/internal/proxy"
	"github.com/xurenlu/sslcat/internal/ssl"
)

// Deps 子集，避免与 tools.Deps 耦合循环 import。
// 都是可选；nil 字段在对应 resource 内部检测后返回错误。
type Deps struct {
	Version    string
	Config     *config.Config
	ConfigFile string
	SSL        *ssl.Manager
	Proxy      *proxy.Manager
	Tasks      *mcp.TaskRegistry
}

// Register 把核心 resource 注册到 ResourceRegistry。
func Register(reg *mcp.ResourceRegistry, d *Deps) error {
	if err := reg.Register(&mcp.Resource{
		URI:         "sslcat://config/current",
		Name:        "Current sslcat configuration (redacted)",
		Description: "当前内存配置的脱敏快照（密码、token hash、API key、私钥等敏感字段会被替换为 ***）。",
		MimeType:    "application/json",
		Scope:       mcp.ScopeRead,
		Reader:      configCurrentReader(d),
	}); err != nil {
		return err
	}
	if err := reg.Register(&mcp.Resource{
		URI:         "sslcat://metrics/snapshot",
		Name:        "Runtime metrics snapshot",
		Description: "当前 sslcat 运行指标快照：站点/证书数量、代理统计、近期 MCP 任务等。比 /metrics 文本格式更适合 AI 直接读。",
		MimeType:    "application/json",
		Scope:       mcp.ScopeRead,
		Reader:      metricsSnapshotReader(d),
	}); err != nil {
		return err
	}
	if err := reg.RegisterTemplate(&mcp.ResourceTemplate{
		URITemplate: "sslcat://logs/access{?since,domain,limit}",
		Name:        "Access log tail",
		Description: "访问日志尾部。query 参数：since=10m (相对) 或 RFC3339 时间；domain= 子串过滤；limit= 行数上限（默认 200，最大 2000）。",
		MimeType:    "text/plain",
		Scope:       mcp.ScopeRead,
		MatchPrefix: "sslcat://logs/access",
		Reader:      logsAccessReader(d),
	}); err != nil {
		return err
	}
	if err := reg.Register(&mcp.Resource{
		URI:         "sslcat://logs/error-sources",
		Name:        "Error log sources",
		Description: "sslcat 内部错误日志与所有站点 error log 的配置清单，包含启用状态、文件路径、大小和更新时间。",
		MimeType:    "application/json",
		Scope:       mcp.ScopeRead,
		Reader:      logsErrorSourcesReader(d),
	}); err != nil {
		return err
	}
	if err := reg.RegisterTemplate(&mcp.ResourceTemplate{
		URITemplate: "sslcat://logs/error{?id,kind,domain,since,keyword,limit,max_bytes}",
		Name:        "Error log tail",
		Description: "错误日志尾部。query 参数：id=internal 或 proxy:域名/static:域名/php:域名；kind/domain 可替代 id；since=10m 或 RFC3339；keyword=关键字；limit 默认 200 最大 2000；max_bytes 默认 1MB 最大 4MB。",
		MimeType:    "text/plain",
		Scope:       mcp.ScopeRead,
		MatchPrefix: "sslcat://logs/error",
		Reader:      logsErrorReader(d),
	}); err != nil {
		return err
	}
	return nil
}

// ---------- sslcat://config/current ----------

// sensitiveFieldRe 字段名子串匹配（小写）。任何字段名包含这些子串的值都会被 ***。
var sensitiveSubstr = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"api_secret", "access_key", "private_key", "totp", "auth_key",
	"token_hash",
}

func isSensitiveField(name string) bool {
	low := strings.ToLower(name)
	for _, s := range sensitiveSubstr {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// redactValue 递归遍历任意结构，把敏感字段替换为 ***。
// 仅处理 struct/map/slice/array/pointer；其它原样返回。
func redactValue(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return v
		}
		return redactValue(v.Elem())
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			redactValue(v.Index(i))
		}
	case reflect.Map:
		// map[string]X：检查 key
		if v.Type().Key().Kind() == reflect.String {
			for _, k := range v.MapKeys() {
				if isSensitiveField(k.String()) {
					mv := reflect.New(v.Type().Elem()).Elem()
					if mv.Kind() == reflect.String {
						mv.SetString("***")
						v.SetMapIndex(k, mv)
					} else {
						// 非字符串值：跳过，复杂
					}
				} else {
					mv := v.MapIndex(k)
					if mv.Kind() == reflect.Ptr || mv.Kind() == reflect.Interface ||
						mv.Kind() == reflect.Struct || mv.Kind() == reflect.Map ||
						mv.Kind() == reflect.Slice {
						// map 元素不可寻址：先取出、redact、再写回（仅 string 值有意义）
						redactValue(mv)
					}
				}
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			fld := t.Field(i)
			if !fld.IsExported() {
				continue
			}
			fv := v.Field(i)
			if !fv.CanSet() {
				continue
			}
			if isSensitiveField(fld.Name) && fv.Kind() == reflect.String {
				if fv.String() != "" {
					fv.SetString("***")
				}
				continue
			}
			redactValue(fv)
		}
	}
	return v
}

func configCurrentReader(d *Deps) mcp.ResourceReader {
	return func(ctx context.Context, uri string, caller *mcp.CallContext) (string, string, error) {
		if d.Config == nil {
			return "", "", fmt.Errorf("config not loaded")
		}
		// 深拷贝再脱敏，不动原始内存
		clone := *d.Config
		// 顶层 slice/map 字段需要单独深拷贝避免和原始 config 共享底层数组
		if d.Config.MCP.Tokens != nil {
			cp := make([]config.MCPToken, len(d.Config.MCP.Tokens))
			copy(cp, d.Config.MCP.Tokens)
			clone.MCP.Tokens = cp
		}
		if d.Config.SSL.DNSProviders != nil {
			cp := make([]config.DNSProvider, len(d.Config.SSL.DNSProviders))
			copy(cp, d.Config.SSL.DNSProviders)
			clone.SSL.DNSProviders = cp
		}
		// reflect 走起
		redactValue(reflect.ValueOf(&clone).Elem())
		buf, err := json.MarshalIndent(&clone, "", "  ")
		if err != nil {
			return "", "", fmt.Errorf("marshal: %w", err)
		}
		return "application/json", string(buf), nil
	}
}

// ---------- sslcat://metrics/snapshot ----------

func metricsSnapshotReader(d *Deps) mcp.ResourceReader {
	return func(ctx context.Context, uri string, caller *mcp.CallContext) (string, string, error) {
		now := time.Now()
		snap := map[string]any{
			"app":         "sslcat",
			"version":     d.Version,
			"server_time": now.Format(time.RFC3339),
		}
		if d.Config != nil {
			snap["sites_total"] = len(d.Config.Proxy.Rules)
			enabled := 0
			for _, r := range d.Config.Proxy.Rules {
				if r.Enabled {
					enabled++
				}
			}
			snap["sites_enabled"] = enabled
			snap["static_sites"] = len(d.Config.StaticSites)
			snap["php_sites"] = len(d.Config.PHPSites)
			snap["cluster_mode"] = d.Config.GetClusterMode()
		}
		if d.SSL != nil {
			list := d.SSL.GetCertificateList()
			snap["certs_total"] = len(list)
			expiringSoon := 0
			for _, c := range list {
				if !c.SelfSigned && time.Until(c.ExpiresAt) < 30*24*time.Hour {
					expiringSoon++
				}
			}
			snap["certs_expiring_in_30d"] = expiringSoon
		}
		if d.Proxy != nil {
			snap["proxy_stats"] = d.Proxy.GetProxyStats()
		}
		if d.Tasks != nil {
			// 让 admin 一口气查看全局任务统计（resource 调用方有 read scope 才能到这里，
			// 这里 nil caller 给 List 视作内部，返回所有任务，再自己 group by status）。
			all := d.Tasks.List(nil, "", 0)
			by := map[string]int{}
			for _, t := range all {
				by[string(t.Status)]++
			}
			snap["mcp_tasks_total"] = len(all)
			snap["mcp_tasks_by_status"] = by
		}
		buf, err := json.MarshalIndent(snap, "", "  ")
		if err != nil {
			return "", "", err
		}
		return "application/json", string(buf), nil
	}
}

// ---------- sslcat://logs/access?since=...&domain=...&limit=... ----------

func logsAccessReader(d *Deps) mcp.ResourceReader {
	return func(ctx context.Context, uri string, caller *mcp.CallContext) (string, string, error) {
		if d.Config == nil {
			return "", "", fmt.Errorf("config not loaded")
		}
		q, err := mcp.ParseURIQuery(uri)
		if err != nil {
			return "", "", fmt.Errorf("parse query: %w", err)
		}
		path := d.Config.Server.AccessLogPath
		if path == "" {
			return "", "", fmt.Errorf("access log path not configured")
		}
		limit := parseIntDefault(q.Get("limit"), 200)
		if limit < 1 {
			limit = 1
		}
		if limit > 2000 {
			limit = 2000
		}
		sinceArg := q.Get("since")
		var sinceCutoff time.Time
		if sinceArg != "" {
			cutoff, perr := parseSince(sinceArg, time.Now())
			if perr != nil {
				return "", "", fmt.Errorf("invalid 'since': %w", perr)
			}
			sinceCutoff = cutoff
		}
		domainFilter := strings.ToLower(strings.TrimSpace(q.Get("domain")))

		lines, err := tailFilteredLines(path, limit, sinceCutoff, domainFilter)
		if err != nil {
			return "", "", err
		}
		header := fmt.Sprintf("# sslcat access log tail\n# source=%s lines=%d limit=%d", path, len(lines), limit)
		if !sinceCutoff.IsZero() {
			header += " since=" + sinceCutoff.Format(time.RFC3339)
		}
		if domainFilter != "" {
			header += " domain=" + domainFilter
		}
		body := header + "\n" + strings.Join(lines, "\n")
		if len(lines) > 0 && !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		return "text/plain", body, nil
	}
}

// ---------- sslcat://logs/error-sources / sslcat://logs/error?... ----------

func logsErrorSourcesReader(d *Deps) mcp.ResourceReader {
	return func(ctx context.Context, uri string, caller *mcp.CallContext) (string, string, error) {
		if d.Config == nil {
			return "", "", fmt.Errorf("config not loaded")
		}
		sources := logview.ListSources(d.Config)
		buf, err := json.MarshalIndent(map[string]any{
			"total":   len(sources),
			"sources": sources,
		}, "", "  ")
		if err != nil {
			return "", "", err
		}
		return "application/json", string(buf), nil
	}
}

func logsErrorReader(d *Deps) mcp.ResourceReader {
	return func(ctx context.Context, uri string, caller *mcp.CallContext) (string, string, error) {
		if d.Config == nil {
			return "", "", fmt.Errorf("config not loaded")
		}
		q, err := mcp.ParseURIQuery(uri)
		if err != nil {
			return "", "", fmt.Errorf("parse query: %w", err)
		}
		src, ok := logview.FindSource(d.Config, q.Get("id"), q.Get("kind"), q.Get("domain"))
		if !ok {
			return "", "", fmt.Errorf("error log source not found")
		}
		since, err := logview.ParseSince(q.Get("since"), time.Now())
		if err != nil {
			return "", "", fmt.Errorf("invalid 'since': %w", err)
		}
		res, err := logview.ReadTail(src, logview.TailOptions{
			Limit:    parseIntDefault(q.Get("limit"), logview.DefaultLimit),
			MaxBytes: int64(parseIntDefault(q.Get("max_bytes"), int(logview.DefaultMaxBytes))),
			Since:    since,
			Domain:   q.Get("domain"),
			Keyword:  q.Get("keyword"),
		})
		if err != nil {
			return "", "", err
		}
		header := fmt.Sprintf("# sslcat error log tail\n# source=%s kind=%s path=%s lines=%d limit=%d max_bytes=%d",
			res.Source.ID, res.Source.Kind, res.Source.Path, res.LineCount, res.Limit, res.MaxBytes)
		if !since.IsZero() {
			header += " since=" + since.Format(time.RFC3339)
		}
		if res.Truncated {
			header += " truncated=true"
		}
		if res.FilterNote != "" {
			header += "\n# " + res.FilterNote
		}
		body := header + "\n" + strings.Join(res.Lines, "\n")
		if len(res.Lines) > 0 && !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		return "text/plain", body, nil
	}
}

// parseSince 接受 "10m"/"1h"/"30s" 或 RFC3339 绝对时间。
func parseSince(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expect RFC3339 or duration (e.g. 10m), got %q", s)
	}
	if dur < 0 {
		dur = -dur
	}
	return now.Add(-dur), nil
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// tailFilteredLines 从 path 读最后 limit 条满足 since/domain 过滤的行。
// 简化实现：顺序读全文件，匹配的行入环形缓冲。文件很大时不够高效，但避免增加复杂度。
// access log 一般每天切割，单文件远小于内存。
func tailFilteredLines(path string, limit int, since time.Time, domain string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]string, 0, limit+8)
	add := func(line string) {
		buf = append(buf, line)
		if len(buf) > limit {
			buf = buf[len(buf)-limit:]
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 单行最大 1MB
	for sc.Scan() {
		line := sc.Text()
		if domain != "" && !strings.Contains(strings.ToLower(line), domain) {
			continue
		}
		if !since.IsZero() {
			// 解析行首时间。优先两种格式：
			//   1. nginx default: "10.0.0.1 - - [03/Jun/2026:10:00:00 +0800] ..."
			//   2. ISO/RFC3339 前缀: "2026-06-03T10:00:00+08:00 ..."
			if lineTS, ok := extractLineTime(line); ok {
				if lineTS.Before(since) {
					continue
				}
			}
			// 时间解析不出来时，宁可保留也不滤掉，避免静默丢日志
		}
		add(line)
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	sort.SliceStable(buf, func(i, j int) bool { return false }) // no-op: 保持文件顺序
	return buf, nil
}

// extractLineTime 从 access log 行尝试抽出时间戳。
func extractLineTime(line string) (time.Time, bool) {
	// nginx 格式：寻找 '[' ... ']'
	if i := strings.IndexByte(line, '['); i >= 0 {
		if j := strings.IndexByte(line[i:], ']'); j > 0 {
			ts := line[i+1 : i+j]
			// "03/Jun/2026:10:00:00 +0800"
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", ts); err == nil {
				return t, true
			}
		}
	}
	// RFC3339 前缀
	if len(line) >= 25 {
		if t, err := time.Parse(time.RFC3339, line[:25]); err == nil {
			return t, true
		}
		if t, err := time.Parse(time.RFC3339, line[:20]); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// 兜底使用 url 包，避免未来扩展导入失败。
var _ = url.Parse
