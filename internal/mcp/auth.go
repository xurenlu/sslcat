package mcp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/xurenlu/sslcat/internal/config"
)

// argon2id 参数。中等强度，token 校验路径不会高频。
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashToken 用 argon2id 对明文 token 做哈希，返回 PHC 格式字符串：
//   $argon2id$v=19$m=65536,t=1,p=2$<saltB64>$<hashB64>
func HashToken(plain string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("gen salt: %w", err)
	}
	key := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyToken 校验明文是否匹配某个 argon2id 哈希。
func VerifyToken(plain, hash string) bool {
	parts := strings.Split(hash, "$")
	// 形如 ["", "argon2id", "v=19", "m=65536,t=1,p=2", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(plain), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GenerateToken 生成一个随机明文 token，前缀 sslcat_mcp_。
func GenerateToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sslcat_mcp_" + hex.EncodeToString(b), nil
}

// AuthResult 鉴权成功后返回的 caller 信息。
type AuthResult struct {
	TokenName string
	Scopes    []Scope
}

// ErrUnauthorized / ErrForbidden / ErrRateLimited 鉴权层错误。
var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrRateLimited  = errors.New("rate limited")
	ErrExpired      = errors.New("token expired")
)

// Authenticator 基于 MCPConfig 的 token 校验器。线程安全。
//
// 注：调用方在校验通过后应缓存结果（如 SessionId → AuthResult），避免每次请求都走 argon2。
type Authenticator struct {
	cfg *config.MCPConfig

	mu      sync.Mutex
	buckets map[string]*rateBucket // tokenName -> bucket
}

// NewAuthenticator 创建鉴权器。
func NewAuthenticator(cfg *config.MCPConfig) *Authenticator {
	return &Authenticator{
		cfg:     cfg,
		buckets: make(map[string]*rateBucket),
	}
}

// Authenticate 用明文 token + 客户端 IP 校验。
func (a *Authenticator) Authenticate(plain, clientIP string) (*AuthResult, error) {
	if a == nil || a.cfg == nil || plain == "" {
		return nil, ErrUnauthorized
	}
	for i := range a.cfg.Tokens {
		t := &a.cfg.Tokens[i]
		if t.TokenHash == "" {
			continue
		}
		if !VerifyToken(plain, t.TokenHash) {
			continue
		}
		// 过期
		if t.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339, t.ExpiresAt); err == nil {
				if time.Now().After(exp) {
					return nil, ErrExpired
				}
			}
		}
		// IP 白名单
		if len(t.IPAllowlist) > 0 && !ipInList(clientIP, t.IPAllowlist) {
			return nil, ErrForbidden
		}
		// 限速
		if t.RateLimit != "" {
			if !a.allow(t.Name, t.RateLimit) {
				return nil, ErrRateLimited
			}
		}
		return &AuthResult{
			TokenName: t.Name,
			Scopes:    parseScopes(t.Scopes),
		}, nil
	}
	return nil, ErrUnauthorized
}

func parseScopes(in []string) []Scope {
	out := make([]Scope, 0, len(in))
	for _, s := range in {
		out = append(out, Scope(strings.TrimSpace(s)))
	}
	return out
}

func ipInList(clientIP string, list []string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, cidr := range list {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			if ip.String() == cidr {
				return true
			}
			continue
		}
		_, n, err := net.ParseCIDR(cidr)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// rateBucket 简单令牌桶：N/min 或 N/sec 或 N/hour。
type rateBucket struct {
	max     int
	per     time.Duration
	tokens  int
	updated time.Time
}

func (a *Authenticator) allow(name, spec string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.buckets[name]
	if !ok {
		max, per, err := parseRate(spec)
		if err != nil {
			return true // 配置错误时不限速，避免误伤
		}
		b = &rateBucket{max: max, per: per, tokens: max, updated: time.Now()}
		a.buckets[name] = b
	}
	now := time.Now()
	elapsed := now.Sub(b.updated)
	// 按比例补充
	if elapsed > 0 {
		add := int(float64(b.max) * (float64(elapsed) / float64(b.per)))
		if add > 0 {
			b.tokens += add
			if b.tokens > b.max {
				b.tokens = b.max
			}
			b.updated = now
		}
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func parseRate(spec string) (int, time.Duration, error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid rate spec: %s", spec)
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || n <= 0 {
		return 0, 0, fmt.Errorf("invalid rate count: %s", parts[0])
	}
	unit := strings.ToLower(strings.TrimSpace(parts[1]))
	var per time.Duration
	switch unit {
	case "sec", "second", "s":
		per = time.Second
	case "min", "minute", "m":
		per = time.Minute
	case "hour", "h":
		per = time.Hour
	default:
		return 0, 0, fmt.Errorf("invalid rate unit: %s", unit)
	}
	return n, per, nil
}

// ExtractBearer 从 Authorization 头解析 Bearer token。返回空字符串表示没有。
func ExtractBearer(authHeader string) string {
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) {
		return ""
	}
	if !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(authHeader[len(prefix):])
}
