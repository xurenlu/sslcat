package bot

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ChallengeManager 挑战管理器
type ChallengeManager struct {
	challenges map[string]*Challenge // key: challengeID
	tokens     *TokenManager
	logger     *logrus.Entry
	mutex      sync.RWMutex
}

// Challenge 验证挑战
type Challenge struct {
	ID           string    `json:"id"`
	ClientIP     string    `json:"client_ip"`
	Domain       string    `json:"domain"`
	Type         string    `json:"type"` // "slider"
	Question     string    `json:"question"`
	Answer       int       `json:"-"` // 不返回给客户端
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Attempts     int       `json:"attempts"`
	MaxAttempts  int       `json:"max_attempts"`
	Used         bool      `json:"-"`
	
	// 滑块验证特有字段
	SliderTarget int `json:"slider_target"` // 目标位置 (0-100)
	SliderRange  int `json:"slider_range"`  // 允许的误差范围
}

// ChallengeVerification 挑战验证请求
type ChallengeVerification struct {
	ChallengeID string                 `json:"challenge_id"`
	Answer      int                    `json:"answer"`
	Track       []TrackPoint           `json:"track"` // 滑动轨迹
	Metadata    map[string]interface{} `json:"metadata"`
}

// TrackPoint 轨迹点
type TrackPoint struct {
	X         int   `json:"x"`
	Y         int   `json:"y"`
	Timestamp int64 `json:"timestamp"`
}

// NewChallengeManager 创建挑战管理器
func NewChallengeManager(logger *logrus.Logger, tokenSecret string) *ChallengeManager {
	cm := &ChallengeManager{
		challenges: make(map[string]*Challenge),
		tokens:     NewTokenManager(tokenSecret),
		logger:     logger.WithField("component", "challenge_manager"),
	}

	// 启动清理协程
	go cm.cleanupRoutine()

	return cm
}

// GenerateChallenge 生成挑战
func (cm *ChallengeManager) GenerateChallenge(clientIP, domain string) *Challenge {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// 生成唯一 ID
	challengeID := cm.generateID()

	// 生成滑块验证挑战
	target := 50 + (rand.Intn(40) - 20) // 30-70 之间的随机位置
	challenge := &Challenge{
		ID:           challengeID,
		ClientIP:     clientIP,
		Domain:       domain,
		Type:         "slider",
		Question:     "请拖动滑块完成验证",
		Answer:       target,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute),
		Attempts:     0,
		MaxAttempts:  3,
		Used:         false,
		SliderTarget: target,
		SliderRange:  5, // 允许 ±5 的误差
	}

	cm.challenges[challengeID] = challenge

	cm.logger.WithFields(logrus.Fields{
		"challenge_id": challengeID,
		"client_ip":    clientIP,
		"domain":       domain,
	}).Info("Generated new challenge")

	return challenge
}

// VerifyChallenge 验证挑战
func (cm *ChallengeManager) VerifyChallenge(verification *ChallengeVerification) (bool, string, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	challenge, exists := cm.challenges[verification.ChallengeID]
	if !exists {
		return false, "", fmt.Errorf("challenge not found")
	}

	// 检查是否已使用
	if challenge.Used {
		return false, "", fmt.Errorf("challenge already used")
	}

	// 检查是否过期
	if time.Now().After(challenge.ExpiresAt) {
		delete(cm.challenges, verification.ChallengeID)
		return false, "", fmt.Errorf("challenge expired")
	}

	// 增加尝试次数
	challenge.Attempts++

	// 检查尝试次数
	if challenge.Attempts > challenge.MaxAttempts {
		delete(cm.challenges, verification.ChallengeID)
		return false, "", fmt.Errorf("too many attempts")
	}

	// 验证答案
	diff := math.Abs(float64(verification.Answer - challenge.Answer))
	if diff > float64(challenge.SliderRange) {
		cm.logger.WithFields(logrus.Fields{
			"challenge_id": verification.ChallengeID,
			"answer":       verification.Answer,
			"target":       challenge.Answer,
			"diff":         diff,
		}).Warn("Challenge verification failed: answer out of range")
		return false, "", fmt.Errorf("incorrect answer")
	}

	// 验证轨迹真实性
	if !cm.verifyTrack(verification.Track, verification.Answer) {
		cm.logger.WithFields(logrus.Fields{
			"challenge_id": verification.ChallengeID,
		}).Warn("Challenge verification failed: suspicious track")
		return false, "", fmt.Errorf("suspicious behavior detected")
	}

	// 标记为已使用
	challenge.Used = true

	// 生成验证 Token
	token, err := cm.tokens.GenerateToken(challenge.ClientIP, "", 24*time.Hour)
	if err != nil {
		return false, "", fmt.Errorf("failed to generate token: %w", err)
	}

	cm.logger.WithFields(logrus.Fields{
		"challenge_id": verification.ChallengeID,
		"client_ip":    challenge.ClientIP,
	}).Info("Challenge verified successfully")

	// 删除挑战
	delete(cm.challenges, verification.ChallengeID)

	return true, token, nil
}

// verifyTrack 验证滑动轨迹的真实性
func (cm *ChallengeManager) verifyTrack(track []TrackPoint, finalPosition int) bool {
	// 基本检查
	if len(track) < 5 {
		// 轨迹点太少，可能是脚本
		return false
	}

	if len(track) > 1000 {
		// 轨迹点太多，异常
		return false
	}

	// 检查时间跨度
	if len(track) >= 2 {
		duration := track[len(track)-1].Timestamp - track[0].Timestamp
		if duration < 100 {
			// 完成太快（小于 100ms），可能是脚本
			return false
		}
		if duration > 30000 {
			// 完成太慢（超过 30 秒），异常
			return false
		}
	}

	// 检查轨迹是否单调递增（滑块只能向右移动）
	for i := 1; i < len(track); i++ {
		if track[i].X < track[i-1].X-10 {
			// 允许小幅回退，但不能大幅回退
			return false
		}
	}

	// 检查速度变化（人类滑动会有加速和减速）
	if len(track) >= 3 {
		hasVariation := false
		for i := 2; i < len(track); i++ {
			dt1 := track[i-1].Timestamp - track[i-2].Timestamp
			dt2 := track[i].Timestamp - track[i-1].Timestamp
			
			if dt1 > 0 && dt2 > 0 {
				dx1 := track[i-1].X - track[i-2].X
				dx2 := track[i].X - track[i-1].X
				
				v1 := float64(dx1) / float64(dt1)
				v2 := float64(dx2) / float64(dt2)
				
				// 检查速度变化
				if math.Abs(v1-v2) > 0.01 {
					hasVariation = true
					break
				}
			}
		}
		
		if !hasVariation {
			// 速度完全恒定，可能是脚本
			return false
		}
	}

	return true
}

// VerifyToken 验证 Token
func (cm *ChallengeManager) VerifyToken(token, clientIP, userAgent string) bool {
	return cm.tokens.VerifyToken(token, clientIP, userAgent)
}

// RefreshChallenge 刷新挑战
func (cm *ChallengeManager) RefreshChallenge(challengeID, clientIP, domain string) *Challenge {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// 删除旧挑战
	if old, exists := cm.challenges[challengeID]; exists {
		if old.ClientIP == clientIP {
			delete(cm.challenges, challengeID)
		}
	}

	// 生成新挑战
	cm.mutex.Unlock()
	newChallenge := cm.GenerateChallenge(clientIP, domain)
	cm.mutex.Lock()

	return newChallenge
}

// GetChallenge 获取挑战
func (cm *ChallengeManager) GetChallenge(challengeID string) (*Challenge, bool) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	challenge, exists := cm.challenges[challengeID]
	return challenge, exists
}

// ActiveCount 获取活跃挑战数量
func (cm *ChallengeManager) ActiveCount() int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	return len(cm.challenges)
}

// cleanupRoutine 定期清理过期挑战
func (cm *ChallengeManager) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cm.cleanup()
	}
}

// cleanup 清理过期挑战
func (cm *ChallengeManager) cleanup() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	now := time.Now()
	count := 0

	for id, challenge := range cm.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(cm.challenges, id)
			count++
		}
	}

	if count > 0 {
		cm.logger.Debugf("Cleaned up %d expired challenges", count)
	}
}

// generateID 生成唯一 ID
func (cm *ChallengeManager) generateID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

