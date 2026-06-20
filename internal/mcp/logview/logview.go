package logview

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

const (
	DefaultLimit    = 200
	MaxLimit        = 2000
	DefaultMaxBytes = int64(1024 * 1024)
	MaxBytes        = int64(4 * 1024 * 1024)
)

type Source struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Domain      string `json:"domain,omitempty"`
	Path        string `json:"path"`
	Enabled     bool   `json:"enabled"`
	Shared      bool   `json:"shared"`
	Exists      bool   `json:"exists"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	ModifiedAt  string `json:"modified_at,omitempty"`
	Description string `json:"description,omitempty"`
}

type TailOptions struct {
	Limit    int
	MaxBytes int64
	Since    time.Time
	Domain   string
	Keyword  string
}

type TailResult struct {
	Source     Source   `json:"source"`
	Limit      int      `json:"limit"`
	MaxBytes   int64    `json:"max_bytes"`
	Truncated  bool     `json:"truncated"`
	LineCount  int      `json:"line_count"`
	Lines      []string `json:"lines"`
	FilterNote string   `json:"filter_note,omitempty"`
}

func ListSources(cfg *config.Config) []Source {
	if cfg == nil {
		return nil
	}
	sources := make([]Source, 0, 1+len(cfg.Proxy.Rules)+len(cfg.StaticSites)+len(cfg.PHPSites))
	globalPath := expandCurrentLogPath(cfg.Server.ErrorLogPath)
	add := func(src Source) {
		src.Path = expandCurrentLogPath(src.Path)
		if src.Path != "" {
			src.Exists, src.SizeBytes, src.ModifiedAt = statPath(src.Path)
		}
		sources = append(sources, src)
	}
	add(Source{
		ID:          "internal",
		Kind:        "internal",
		Path:        globalPath,
		Enabled:     cfg.Server.ErrorLogEnabled,
		Description: "sslcat internal/application error log",
	})
	for _, rule := range cfg.Proxy.Rules {
		enabled := cfg.Server.ErrorLogEnabled
		if rule.ErrorLogEnabled != nil {
			enabled = *rule.ErrorLogEnabled
		}
		path := globalPath
		if rule.ErrorLogPath != "" {
			path = rule.ErrorLogPath
		}
		add(Source{
			ID:          "proxy:" + rule.Domain,
			Kind:        "proxy",
			Domain:      rule.Domain,
			Path:        path,
			Enabled:     enabled,
			Shared:      path == globalPath,
			Description: "proxy site error log",
		})
	}
	for _, site := range cfg.StaticSites {
		enabled := cfg.Server.ErrorLogEnabled
		if site.ErrorLogEnabled != nil {
			enabled = *site.ErrorLogEnabled
		}
		path := globalPath
		if site.ErrorLogPath != "" {
			path = site.ErrorLogPath
		}
		add(Source{
			ID:          "static:" + site.Domain,
			Kind:        "static",
			Domain:      site.Domain,
			Path:        path,
			Enabled:     enabled,
			Shared:      path == globalPath,
			Description: "static site error log",
		})
	}
	for _, site := range cfg.PHPSites {
		enabled := cfg.Server.ErrorLogEnabled
		if site.ErrorLogEnabled != nil {
			enabled = *site.ErrorLogEnabled
		}
		path := globalPath
		if site.ErrorLogPath != "" {
			path = site.ErrorLogPath
		}
		if site.MonitoringConfig != nil && site.MonitoringConfig.LogFile != "" {
			path = site.MonitoringConfig.LogFile
		}
		if path == "" && site.Root != "" {
			path = filepath.Join(site.Root, "logs", "php_errors.log")
		}
		add(Source{
			ID:          "php:" + site.Domain,
			Kind:        "php",
			Domain:      site.Domain,
			Path:        path,
			Enabled:     enabled,
			Shared:      path == globalPath,
			Description: "PHP site error log",
		})
	}
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].Kind == sources[j].Kind {
			return sources[i].Domain < sources[j].Domain
		}
		return sources[i].Kind < sources[j].Kind
	})
	return sources
}

func FindSource(cfg *config.Config, id, kind, domain string) (Source, bool) {
	id = strings.TrimSpace(id)
	kind = strings.ToLower(strings.TrimSpace(kind))
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, src := range ListSources(cfg) {
		if id != "" && src.ID == id {
			return src, true
		}
		if kind != "" && src.Kind != kind {
			continue
		}
		if domain != "" && strings.EqualFold(src.Domain, domain) {
			return src, true
		}
		if id == "" && kind != "" && domain == "" && src.Kind == kind {
			return src, true
		}
	}
	return Source{}, false
}

func ReadTail(src Source, opts TailOptions) (TailResult, error) {
	limit := normalizeLimit(opts.Limit)
	maxBytes := normalizeMaxBytes(opts.MaxBytes)
	result := TailResult{Source: src, Limit: limit, MaxBytes: maxBytes}
	if src.Path == "" {
		return result, fmt.Errorf("log path not configured for %s", src.ID)
	}
	lines, truncated, err := tailFile(src.Path, maxBytes)
	if err != nil {
		return result, err
	}
	filtered := make([]string, 0, limit)
	domain := strings.ToLower(strings.TrimSpace(opts.Domain))
	keyword := strings.ToLower(strings.TrimSpace(opts.Keyword))
	for _, line := range lines {
		low := strings.ToLower(line)
		if domain != "" && !strings.Contains(low, domain) {
			continue
		}
		if keyword != "" && !strings.Contains(low, keyword) {
			continue
		}
		if !opts.Since.IsZero() {
			if ts, ok := ExtractLineTime(line); ok && ts.Before(opts.Since) {
				continue
			}
		}
		filtered = append(filtered, line)
		if len(filtered) > limit {
			filtered = filtered[len(filtered)-limit:]
		}
	}
	result.Truncated = truncated
	result.LineCount = len(filtered)
	result.Lines = filtered
	if truncated {
		result.FilterNote = "read from file tail only; older lines may be omitted before filtering"
	}
	return result, nil
}

func ParseSince(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
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

func ExtractLineTime(line string) (time.Time, bool) {
	if i := strings.IndexByte(line, '['); i >= 0 {
		if j := strings.IndexByte(line[i:], ']'); j > 0 {
			ts := line[i+1 : i+j]
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", ts); err == nil {
				return t, true
			}
		}
	}
	for _, n := range []int{25, 20} {
		if len(line) >= n {
			if t, err := time.Parse(time.RFC3339, line[:n]); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return DefaultLimit
	}
	if limit > MaxLimit {
		return MaxLimit
	}
	return limit
}

func normalizeMaxBytes(maxBytes int64) int64 {
	if maxBytes <= 0 {
		return DefaultMaxBytes
	}
	if maxBytes > MaxBytes {
		return MaxBytes
	}
	return maxBytes
}

func tailFile(path string, maxBytes int64) ([]string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	start := int64(0)
	truncated := false
	if stat.Size() > maxBytes {
		start = stat.Size() - maxBytes
		truncated = true
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, false, err
	}
	reader := bufio.NewReader(f)
	if truncated {
		_, _ = reader.ReadString('\n')
	}
	lines := make([]string, 0, 256)
	sc := bufio.NewScanner(reader)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return nil, false, err
	}
	return lines, truncated, nil
}

func statPath(path string) (bool, int64, string) {
	st, err := os.Stat(path)
	if err != nil {
		return false, 0, ""
	}
	return true, st.Size(), st.ModTime().Format(time.RFC3339)
}

func expandCurrentLogPath(path string) string {
	if path == "" {
		return ""
	}
	now := time.Now()
	repl := []struct {
		old string
		new string
	}{
		{"2006-01-02_15-04-05", now.Format("2006-01-02_15-04-05")},
		{"2006-01-02", now.Format("2006-01-02")},
		{"15:04:05", now.Format("15:04:05")},
		{"%Y", now.Format("2006")},
		{"%y", now.Format("06")},
		{"%m", now.Format("01")},
		{"%d", now.Format("02")},
		{"%H", now.Format("15")},
		{"%M", now.Format("04")},
		{"%S", now.Format("05")},
		{"%s", fmt.Sprintf("%d", now.Unix())},
	}
	out := path
	for _, r := range repl {
		out = strings.ReplaceAll(out, r.old, r.new)
	}
	return out
}
