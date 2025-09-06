package security

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// TokenRole 定义令牌权限
type TokenRole string

const (
	TokenRoleRead  TokenRole = "read"
	TokenRoleWrite TokenRole = "write"
)

// APIToken 表示一个API令牌
type APIToken struct {
	Token     string    `json:"token"`
	Role      TokenRole `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	Note      string    `json:"note,omitempty"`
}

// TokenStore 负责持久化管理令牌
type TokenStore struct {
	filePath string
	tokens   map[string]APIToken
	mu       sync.RWMutex
}

func NewTokenStore(filePath string) *TokenStore {
	ts := &TokenStore{filePath: filePath, tokens: make(map[string]APIToken)}
	_ = ts.load()
	return ts
}

func (ts *TokenStore) load() error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.filePath == "" {
		ts.filePath = "./data/tokens.json"
	}
	if _, err := os.Stat(ts.filePath); os.IsNotExist(err) {
		// ensure dir
		_ = os.MkdirAll(filepath.Dir(ts.filePath), 0755)
		return nil
	}
	b, err := os.ReadFile(ts.filePath)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	var arr []APIToken
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	m := make(map[string]APIToken, len(arr))
	for _, t := range arr {
		m[t.Token] = t
	}
	ts.tokens = m
	return nil
}

func (ts *TokenStore) save() error {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	// stable order
	arr := make([]APIToken, 0, len(ts.tokens))
	for _, t := range ts.tokens {
		arr = append(arr, t)
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].CreatedAt.Before(arr[j].CreatedAt) })
	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ts.filePath), 0755); err != nil {
		return err
	}
	return os.WriteFile(ts.filePath, b, 0600)
}

func (ts *TokenStore) Generate(role TokenRole, note string) (APIToken, error) {
	if role != TokenRoleRead && role != TokenRoleWrite {
		return APIToken{}, fmt.Errorf("invalid role: %s", role)
	}
	// 32字节随机令牌
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return APIToken{}, err
	}
	token := hex.EncodeToString(buf)
	at := APIToken{Token: token, Role: role, CreatedAt: time.Now(), Note: strings.TrimSpace(note)}
	ts.mu.Lock()
	ts.tokens[token] = at
	ts.mu.Unlock()
	if err := ts.save(); err != nil {
		return APIToken{}, err
	}
	return at, nil
}

func (ts *TokenStore) List() []APIToken {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]APIToken, 0, len(ts.tokens))
	for _, t := range ts.tokens {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (ts *TokenStore) Delete(token string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, ok := ts.tokens[token]; ok {
		delete(ts.tokens, token)
		_ = ts.save()
		return true
	}
	return false
}

func (ts *TokenStore) Validate(token string) (TokenRole, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	if t, ok := ts.tokens[token]; ok {
		return t.Role, true
	}
	return "", false
}
