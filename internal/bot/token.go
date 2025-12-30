package bot

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TokenManager Token 管理器
type TokenManager struct {
	secret []byte
}

// NewTokenManager 创建 Token 管理器
func NewTokenManager(secret string) *TokenManager {
	if secret == "" {
		secret = "default-bot-verification-secret-change-me"
	}
	return &TokenManager{
		secret: []byte(secret),
	}
}

// GenerateToken 生成验证 Token
// Token 格式: base64(clientIP|userAgentHash|expiresAt|signature)
func (tm *TokenManager) GenerateToken(clientIP, userAgent string, duration time.Duration) (string, error) {
	expiresAt := time.Now().Add(duration).Unix()
	
	// 计算 User-Agent 哈希
	uaHash := tm.hashString(userAgent)
	
	// 构建 payload
	payload := fmt.Sprintf("%s|%s|%d", clientIP, uaHash, expiresAt)
	
	// 生成签名
	signature := tm.sign(payload)
	
	// 组合 Token
	token := fmt.Sprintf("%s|%s", payload, signature)
	
	// Base64 编码
	return base64.URLEncoding.EncodeToString([]byte(token)), nil
}

// VerifyToken 验证 Token
func (tm *TokenManager) VerifyToken(token, clientIP, userAgent string) bool {
	// Base64 解码
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	
	// 分割 Token
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 4 {
		return false
	}
	
	tokenIP := parts[0]
	tokenUAHash := parts[1]
	tokenExpiresStr := parts[2]
	tokenSignature := parts[3]
	
	// 验证 IP
	if tokenIP != clientIP {
		return false
	}
	
	// 验证 User-Agent 哈希
	uaHash := tm.hashString(userAgent)
	if tokenUAHash != uaHash {
		return false
	}
	
	// 验证过期时间
	expiresAt, err := strconv.ParseInt(tokenExpiresStr, 10, 64)
	if err != nil {
		return false
	}
	
	if time.Now().Unix() > expiresAt {
		return false
	}
	
	// 验证签名
	payload := fmt.Sprintf("%s|%s|%d", tokenIP, tokenUAHash, expiresAt)
	expectedSignature := tm.sign(payload)
	
	return hmac.Equal([]byte(tokenSignature), []byte(expectedSignature))
}

// ParseToken 解析 Token（不验证）
func (tm *TokenManager) ParseToken(token string) (clientIP string, expiresAt time.Time, err error) {
	// Base64 解码
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid token format")
	}
	
	// 分割 Token
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 4 {
		return "", time.Time{}, fmt.Errorf("invalid token structure")
	}
	
	clientIP = parts[0]
	expiresAtUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("invalid expiration time")
	}
	
	expiresAt = time.Unix(expiresAtUnix, 0)
	
	return clientIP, expiresAt, nil
}

// sign 签名
func (tm *TokenManager) sign(data string) string {
	h := hmac.New(sha256.New, tm.secret)
	h.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// hashString 计算字符串哈希
func (tm *TokenManager) hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(h[:])
}

