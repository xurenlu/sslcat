package web

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// CaptchaManager 验证码管理器
type CaptchaManager struct {
	sessions map[string]CaptchaSession
	mutex    sync.RWMutex
}

// CaptchaSession 验证码会话数据
type CaptchaSession struct {
	Answer    int       `json:"answer"`
	AnswerStr string    `json:"answer_str"`
	CreatedAt time.Time `json:"created_at"`
	Salt      string    `json:"salt"`
}

// CaptchaData 验证码数据（返回给前端）
type CaptchaData struct {
	SessionID       string `json:"session_id"`
	EncodedQuestion string `json:"encoded_question"`
	Salt            string `json:"salt"`
	Offset          int    `json:"offset"`
}

// NewCaptchaManager 创建验证码管理器
func NewCaptchaManager() *CaptchaManager {
	cm := &CaptchaManager{
		sessions: make(map[string]CaptchaSession),
	}

	// 启动清理goroutine，每5分钟清理过期session
	go cm.cleanup()

	return cm
}

// GenerateCaptcha 生成验证码
func (c *CaptchaManager) GenerateCaptcha() (*CaptchaData, error) {
	// 生成两个1-20的随机数
	a, err := rand.Int(rand.Reader, big.NewInt(20))
	if err != nil {
		return nil, err
	}
	b, err := rand.Int(rand.Reader, big.NewInt(20))
	if err != nil {
		return nil, err
	}

	num1 := int(a.Int64()) + 1
	num2 := int(b.Int64()) + 1
	answer := num1 + num2

	// 生成会话ID和盐值
	sessionID := c.generateSessionID()
	salt := c.generateSalt()
	// 计算偏移量（与前端共享）
	offset := c.getSaltOffset(salt)

	// 生成问题文本
	question := fmt.Sprintf("%d + %d = ?", num1, num2)

	// 编码问题
	encodedQuestion := c.encodeQuestion(question, salt)

	// 存储会话
	c.mutex.Lock()
	c.sessions[sessionID] = CaptchaSession{
		Answer:    answer,
		CreatedAt: time.Now(),
		Salt:      salt,
	}
	c.mutex.Unlock()

	return &CaptchaData{
		SessionID:       sessionID,
		EncodedQuestion: encodedQuestion,
		Salt:            salt,
		Offset:          offset,
	}, nil
}

// VerifyCaptcha 验证验证码
func (c *CaptchaManager) VerifyCaptcha(sessionID string, userAnswer int) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	session, exists := c.sessions[sessionID]
	if !exists {
		return false
	}

	// 删除使用过的session（一次性使用）
	delete(c.sessions, sessionID)

	// 检查session是否过期（10分钟）
	if time.Since(session.CreatedAt) > 10*time.Minute {
		return false
	}

	return session.Answer == userAnswer
}

// VerifyCaptchaString 校验字符串验证码
func (c *CaptchaManager) VerifyCaptchaString(sessionID string, userAnswer string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	session, exists := c.sessions[sessionID]
	if !exists {
		return false
	}
	// 一次性使用
	delete(c.sessions, sessionID)
	if time.Since(session.CreatedAt) > 10*time.Minute {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(session.AnswerStr), strings.TrimSpace(userAnswer))
}

// GenerateImageCaptcha 生成图形验证码（仅创建会话与答案字符串）
func (c *CaptchaManager) GenerateImageCaptcha() (string, string, error) {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 5)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", "", err
		}
		b[i] = chars[n.Int64()]
	}
	code := string(b)
	sessionID := c.generateSessionID()
	c.mutex.Lock()
	c.sessions[sessionID] = CaptchaSession{AnswerStr: code, CreatedAt: time.Now()}
	c.mutex.Unlock()
	return sessionID, code, nil
}

// encodeQuestion 编码问题文本
// 使用简单的字符偏移 + Base64 编码
func (c *CaptchaManager) encodeQuestion(question, salt string) string {
	// 使用盐值生成偏移量
	offset := c.getSaltOffset(salt)

	// 字符偏移
	encoded := make([]byte, len(question))
	for i, char := range []byte(question) {
		// 只对可打印字符进行偏移
		if char >= 32 && char <= 126 {
			shifted := ((int(char) - 32 + offset) % 95) + 32
			encoded[i] = byte(shifted)
		} else {
			encoded[i] = char
		}
	}

	// Base64编码
	return base64.StdEncoding.EncodeToString(encoded)
}

// getSaltOffset 从盐值生成偏移量
func (c *CaptchaManager) getSaltOffset(salt string) int {
	hash := md5.Sum([]byte(salt))
	// 使用哈希的前两个字节生成1-50的偏移量
	offset := int(hash[0])%50 + 1
	return offset
}

// generateSessionID 生成会话ID
func (c *CaptchaManager) generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateSalt 生成盐值
func (c *CaptchaManager) generateSalt() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// cleanup 清理过期的session
func (c *CaptchaManager) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mutex.Lock()
		now := time.Now()
		for id, session := range c.sessions {
			if now.Sub(session.CreatedAt) > 10*time.Minute {
				delete(c.sessions, id)
			}
		}
		c.mutex.Unlock()
	}
}

// GetJSDecodeFunction 获取JS解码函数
// 这个函数返回用于前端解码的JavaScript代码
func (c *CaptchaManager) GetJSDecodeFunction() string {
	return `
function decodeCaptchaQuestion(encodedQuestion, salt, offset) {
    try {
        // Base64解码
        const decoded = atob(encodedQuestion);
        
        // 使用服务端提供的偏移量；若缺失则回退本地计算
        const usedOffset = (typeof offset === 'number' && !Number.isNaN(offset)) ? offset : getSaltOffset(salt);
        
        // 字符偏移解码
        let question = '';
        for (let i = 0; i < decoded.length; i++) {
            const charCode = decoded.charCodeAt(i);
            if (charCode >= 32 && charCode <= 126) {
                // 反向偏移
                let shifted = charCode - 32 - usedOffset;
                if (shifted < 0) {
                    shifted += 95;
                }
                question += String.fromCharCode(shifted + 32);
            } else {
                question += decoded.charAt(i);
            }
        }
        
        return question;
    } catch (e) {
        console.error('解码验证码问题失败:', e);
        return '验证码加载失败，请刷新页面';
    }
}

function getSaltOffset(salt) {
    // 简单的哈希函数，与Go端md5逻辑近似
    let hash = 0;
    for (let i = 0; i < salt.length; i++) {
        const char = salt.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // 转换为32位整数
    }
    return Math.abs(hash) % 50 + 1;
}

function loadCaptchaQuestion(captchaData) {
    if (!captchaData || !captchaData.encoded_question || !captchaData.salt) {
        document.getElementById('captcha-question').textContent = '验证码加载失败';
        return;
    }
    
    const question = decodeCaptchaQuestion(captchaData.encoded_question, captchaData.salt, captchaData.offset);
    document.getElementById('captcha-question').textContent = question;
    document.getElementById('captcha-session-id').value = captchaData.session_id;
}
`
}
