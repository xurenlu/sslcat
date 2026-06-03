package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// ConfirmGate 管理 destructive tool 的二次确认。
//
// 流程：
//   1. AI 第一次调用 destructive tool，不带 confirm 字段；
//   2. 服务端校验 tool/args 合法（由 tool 自身的 PreviewHandler 完成），生成一个 confirm_token，
//      返回 dry-run 预览 + token 给 AI；AI 把这个 token 复述给用户确认；
//   3. AI 再次调用同一 tool，带上 confirm=<token>；服务端命中 pending 并消费它，真正执行。
//
// token 与 (caller.TokenName, tool, canonicalArgs) 强绑定，且 60s TTL，防重放。
type ConfirmGate struct {
	ttl time.Duration

	mu      sync.Mutex
	pending map[string]time.Time // confirmToken -> 过期时间
}

// NewConfirmGate 创建一个 ConfirmGate。
func NewConfirmGate(ttl time.Duration) *ConfirmGate {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	g := &ConfirmGate{ttl: ttl, pending: make(map[string]time.Time)}
	return g
}

// Issue 为一次 (tool, args, caller) 组合签发 confirm_token。
func (g *ConfirmGate) Issue(tool string, args json.RawMessage, caller *CallContext) string {
	tok := confirmTokenFor(tool, args, caller)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gcLocked()
	g.pending[tok] = time.Now().Add(g.ttl)
	return tok
}

// Consume 验证客户端带来的 token 是否对得上这次调用，命中则消费掉返回 true。
func (g *ConfirmGate) Consume(token, tool string, args json.RawMessage, caller *CallContext) bool {
	if token == "" {
		return false
	}
	want := confirmTokenFor(tool, args, caller)
	if token != want {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.pending[token]
	if !ok {
		return false
	}
	delete(g.pending, token)
	return time.Now().Before(exp)
}

// PendingCount 当前等待确认的数量（供 metrics 用）。
func (g *ConfirmGate) PendingCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gcLocked()
	return len(g.pending)
}

func (g *ConfirmGate) gcLocked() {
	now := time.Now()
	for k, exp := range g.pending {
		if now.After(exp) {
			delete(g.pending, k)
		}
	}
}

// confirmTokenFor 计算 token：sha256(tokenName | tool | canonical(args))
// 取前 16 字节 hex（32 字符）即可，碰撞概率可忽略。
func confirmTokenFor(tool string, args json.RawMessage, caller *CallContext) string {
	tokenName := ""
	if caller != nil {
		tokenName = caller.TokenName
	}
	h := sha256.New()
	h.Write([]byte(tokenName))
	h.Write([]byte{0})
	h.Write([]byte(tool))
	h.Write([]byte{0})
	h.Write(canonicalize(args))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// canonicalize 把 JSON 重新序列化为 key 排序的紧凑形式，确保等价 args 得到相同 hash。
// 同时把可选的 confirm 字段剔除——AI 第二次调用必然多了这个字段，但语义参数相同。
func canonicalize(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// 解析不了就用原始字节，反正后面 Consume 时拿到的也是同样不合法的字节，仍然能比对
		return raw
	}
	if m, ok := v.(map[string]any); ok {
		delete(m, "confirm")
		v = sortMap(m)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

// kv 表示一个有序键值对，用于稳定的 JSON 序列化。
type kv struct {
	K string
	V any
}

// orderedObject 是按 key 排序的有序对象，实现 MarshalJSON 输出稳定字节。
type orderedObject []kv

// MarshalJSON 输出按 key 字典序的对象，保证哈希稳定。
func (o orderedObject) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, p := range o {
		if i > 0 {
			buf = append(buf, ',')
		}
		key, _ := json.Marshal(p.K)
		buf = append(buf, key...)
		buf = append(buf, ':')
		val, err := json.Marshal(p.V)
		if err != nil {
			return nil, err
		}
		buf = append(buf, val...)
	}
	buf = append(buf, '}')
	return buf, nil
}

// sortMap 把 map 递归转为按 key 排序的有序结构，保证 Marshal 输出稳定。
func sortMap(m map[string]any) any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make(orderedObject, 0, len(keys))
	for _, k := range keys {
		v := m[k]
		if sub, ok := v.(map[string]any); ok {
			v = sortMap(sub)
		}
		pairs = append(pairs, kv{K: k, V: v})
	}
	return pairs
}
