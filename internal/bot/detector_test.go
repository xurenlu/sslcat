package bot

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestIsKnownBot(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		expected  bool
	}{
		{"Empty UA", "", true},
		{"Normal Browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", false},
		{"Scrapy", "Scrapy/2.5.0", true},
		{"Selenium", "Mozilla/5.0 (compatible; Selenium/3.0)", true},
		{"curl", "curl/7.68.0", true},
		{"wget", "Wget/1.20.3", true},
		{"Python Requests", "python-requests/2.25.1", true},
		{"Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1)", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKnownBot(tt.userAgent)
			if result != tt.expected {
				t.Errorf("IsKnownBot(%q) = %v, expected %v", tt.userAgent, result, tt.expected)
			}
		})
	}
}

func TestBehaviorAnalyzer_AnalyzeUserAgent(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	analyzer := NewBehaviorAnalyzer(logger)

	tests := []struct {
		name      string
		userAgent string
		minScore  int
		maxScore  int
	}{
		{"Empty UA", "", 30, 30},
		{"Normal Browser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", 0, 5},
		{"Short UA", "Bot", 15, 30},
		{"Known Bot", "Scrapy/2.5.0", 30, 30},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.analyzeUserAgent(tt.userAgent)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("analyzeUserAgent(%q) = %d, expected between %d and %d", tt.userAgent, score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestDetector_CheckRequest(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// 创建临时数据库
	whitelist, err := NewWhitelistManager(logger, ":memory:")
	if err != nil {
		t.Fatalf("Failed to create whitelist manager: %v", err)
	}
	defer whitelist.Close()

	challenge := NewChallengeManager(logger, "test-secret")
	detector := NewDetector(logger, whitelist, challenge)

	config := DefaultConfig()
	config.Mode = "challenge"

	tests := []struct {
		name           string
		userAgent      string
		path           string
		expectChallenge bool
	}{
		{
			name:            "Normal Browser",
			userAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			path:            "/",
			expectChallenge: false,
		},
		{
			name:            "Known Bot",
			userAgent:       "Scrapy/2.5.0",
			path:            "/",
			expectChallenge: true,
		},
		{
			name:            "Skipped Path",
			userAgent:       "Scrapy/2.5.0",
			path:            "/api/health",
			expectChallenge: false,
		},
	}

	// 添加跳过路径
	config.SkipPaths = []string{"/api/health"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.Header.Set("User-Agent", tt.userAgent)
			req.RemoteAddr = "1.2.3.4:12345"

			result, needsChallenge := detector.CheckRequest(req, config)

			if needsChallenge != tt.expectChallenge {
				t.Errorf("CheckRequest() needsChallenge = %v, expected %v (score: %d, action: %s)",
					needsChallenge, tt.expectChallenge, result.RiskScore, result.Action)
			}
		})
	}
}

func TestTokenManager_GenerateAndVerify(t *testing.T) {
	tm := NewTokenManager("test-secret")

	clientIP := "1.2.3.4"
	userAgent := "Mozilla/5.0 Test"

	// 生成 Token
	token, err := tm.GenerateToken(clientIP, userAgent, 3600)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateToken() returned empty token")
	}

	// 验证 Token
	valid := tm.VerifyToken(token, clientIP, userAgent)
	if !valid {
		t.Error("VerifyToken() = false, expected true")
	}

	// 验证错误的 IP
	valid = tm.VerifyToken(token, "5.6.7.8", userAgent)
	if valid {
		t.Error("VerifyToken() with wrong IP = true, expected false")
	}

	// 验证错误的 User-Agent
	valid = tm.VerifyToken(token, clientIP, "Different UA")
	if valid {
		t.Error("VerifyToken() with wrong UA = true, expected false")
	}
}

func TestChallengeManager_GenerateAndVerify(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cm := NewChallengeManager(logger, "test-secret")

	clientIP := "1.2.3.4"
	domain := "example.com"

	// 生成挑战
	challenge := cm.GenerateChallenge(clientIP, domain)

	if challenge == nil {
		t.Fatal("GenerateChallenge() returned nil")
	}

	if challenge.ID == "" {
		t.Error("Challenge ID is empty")
	}

	if challenge.SliderTarget < 30 || challenge.SliderTarget > 70 {
		t.Errorf("SliderTarget = %d, expected between 30 and 70", challenge.SliderTarget)
	}

	// 验证挑战（正确答案）
	verification := &ChallengeVerification{
		ChallengeID: challenge.ID,
		Answer:      challenge.SliderTarget,
		Track: []TrackPoint{
			{X: 0, Y: 0, Timestamp: 1000},
			{X: 10, Y: 0, Timestamp: 1100},
			{X: 20, Y: 0, Timestamp: 1200},
			{X: 30, Y: 0, Timestamp: 1300},
			{X: challenge.SliderTarget, Y: 0, Timestamp: 1400},
		},
	}

	success, token, err := cm.VerifyChallenge(verification)
	if err != nil {
		t.Errorf("VerifyChallenge() error = %v", err)
	}

	if !success {
		t.Error("VerifyChallenge() = false, expected true")
	}

	if token == "" {
		t.Error("VerifyChallenge() returned empty token")
	}

	// 验证挑战（错误答案）
	challenge2 := cm.GenerateChallenge(clientIP, domain)
	verification2 := &ChallengeVerification{
		ChallengeID: challenge2.ID,
		Answer:      challenge2.SliderTarget + 20, // 错误答案
		Track: []TrackPoint{
			{X: 0, Y: 0, Timestamp: 1000},
			{X: challenge2.SliderTarget + 20, Y: 0, Timestamp: 1100},
		},
	}

	success, _, err = cm.VerifyChallenge(verification2)
	if success {
		t.Error("VerifyChallenge() with wrong answer = true, expected false")
	}
}

func TestWhitelistManager(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	wm, err := NewWhitelistManager(logger, ":memory:")
	if err != nil {
		t.Fatalf("NewWhitelistManager() error = %v", err)
	}
	defer wm.Close()

	ip := "1.2.3.4"
	domain := "example.com"
	token := "test-token"

	// 添加到白名单
	err = wm.Add(ip, domain, token, 3600)
	if err != nil {
		t.Errorf("Add() error = %v", err)
	}

	// 检查是否在白名单中
	if !wm.IsWhitelisted(ip, domain) {
		t.Error("IsWhitelisted() = false, expected true")
	}

	// 获取条目
	entry, exists := wm.Get(ip, domain)
	if !exists {
		t.Error("Get() exists = false, expected true")
	}

	if entry.IP != ip || entry.Domain != domain {
		t.Errorf("Get() returned wrong entry: IP=%s, Domain=%s", entry.IP, entry.Domain)
	}

	// 删除条目
	err = wm.Remove(ip, domain)
	if err != nil {
		t.Errorf("Remove() error = %v", err)
	}

	// 确认已删除
	if wm.IsWhitelisted(ip, domain) {
		t.Error("IsWhitelisted() after Remove() = true, expected false")
	}
}

