package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AuditEntry MCP 工具调用审计记录。
type AuditEntry struct {
	Time      time.Time       `json:"time"`
	TokenName string          `json:"token_name"`
	IP        string          `json:"ip"`
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args,omitempty"`
	Status    string          `json:"status"`
	LatencyMS int64           `json:"latency_ms"`
}

// Auditor 把审计记录写到本地文件，每天一切片（不实现 rotation 复杂逻辑，
// 文件名按日期生成，最简也最稳妥）。
type Auditor struct {
	mu       sync.Mutex
	baseFile string
	current  *os.File
	day      string // YYYYMMDD
	log      *logrus.Entry
}

// NewAuditor 创建审计器。baseFile 为基础文件路径（如 ./data/mcp_audit.log），
// 实际文件名会带日期后缀：./data/mcp_audit.20260603.log。
func NewAuditor(baseFile string) (*Auditor, error) {
	if baseFile == "" {
		return nil, fmt.Errorf("audit file path required")
	}
	if err := os.MkdirAll(filepath.Dir(baseFile), 0755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	a := &Auditor{
		baseFile: baseFile,
		log:      logrus.WithField("component", "mcp-audit"),
	}
	if err := a.rotateIfNeeded(time.Now()); err != nil {
		return nil, err
	}
	return a, nil
}

// Log 写入一条审计记录。失败仅记录到 logger，不影响主流程。
func (a *Auditor) Log(e AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.rotateIfNeeded(e.Time); err != nil {
		a.log.WithError(err).Warn("rotate audit log failed")
		return
	}
	// 脱敏：参数中如出现明显敏感字段，替换为 ***。
	e.Args = sanitizeArgs(e.Args)
	line, err := json.Marshal(e)
	if err != nil {
		a.log.WithError(err).Warn("marshal audit entry failed")
		return
	}
	if _, err := a.current.Write(append(line, '\n')); err != nil {
		a.log.WithError(err).Warn("write audit log failed")
	}
}

// Close 关闭审计文件。
func (a *Auditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current != nil {
		err := a.current.Close()
		a.current = nil
		return err
	}
	return nil
}

func (a *Auditor) rotateIfNeeded(t time.Time) error {
	day := t.Format("20060102")
	if day == a.day && a.current != nil {
		return nil
	}
	if a.current != nil {
		_ = a.current.Close()
		a.current = nil
	}
	dir := filepath.Dir(a.baseFile)
	base := filepath.Base(a.baseFile)
	ext := filepath.Ext(base)
	name := base[:len(base)-len(ext)]
	if ext == "" {
		ext = ".log"
	}
	path := filepath.Join(dir, fmt.Sprintf("%s.%s%s", name, day, ext))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open audit file %s: %w", path, err)
	}
	a.current = f
	a.day = day
	return nil
}

// sensitiveKeys 审计日志中需脱敏的字段。匹配规则：完全相等或包含子串。
var sensitiveKeys = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"api_secret", "access_key", "private_key", "totp_secret",
}

// sanitizeArgs 把 JSON 对象里的敏感字段值替换为 ***。仅处理顶层和一层嵌套，避免递归性能问题。
func sanitizeArgs(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	maskMap(m)
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func maskMap(m map[string]any) {
	for k, v := range m {
		if isSensitive(k) {
			m[k] = "***"
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			maskMap(sub)
		}
	}
}

func isSensitive(k string) bool {
	low := toLower(k)
	for _, s := range sensitiveKeys {
		if low == s {
			return true
		}
		if containsSubstr(low, s) {
			return true
		}
	}
	return false
}

// 避免引入 strings 仅为两个小函数。
func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func containsSubstr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// 兼容 io.Writer 接口，供调试用。
var _ io.Closer = (*Auditor)(nil)
