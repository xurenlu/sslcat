package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/xurenlu/sslcat/internal/bot"
)

// serveBotChallenge 服务机器人验证挑战页面
func (s *Server) serveBotChallenge(w http.ResponseWriter, r *http.Request, challenge *bot.Challenge) {
	// 设置响应头
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// 渲染验证页面
	html := s.renderBotChallengePage(challenge, r.URL.String())
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// renderBotChallengePage 渲染机器人验证页面
func (s *Server) renderBotChallengePage(challenge *bot.Challenge, originalURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全验证 - Security Verification</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%%;
            padding: 40px;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .shield-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            border-radius: 50%%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
        }
        
        h1 {
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #666;
            font-size: 14px;
            line-height: 1.6;
        }
        
        .challenge-container {
            margin: 30px 0;
        }
        
        .slider-track {
            position: relative;
            width: 100%%;
            height: 50px;
            background: #f0f0f0;
            border-radius: 25px;
            overflow: hidden;
            cursor: pointer;
            user-select: none;
        }
        
        .slider-fill {
            position: absolute;
            left: 0;
            top: 0;
            height: 100%%;
            background: linear-gradient(90deg, #667eea 0%%, #764ba2 100%%);
            width: 0;
            transition: width 0.1s ease;
        }
        
        .slider-thumb {
            position: absolute;
            left: 0;
            top: 50%%;
            transform: translateY(-50%%);
            width: 50px;
            height: 50px;
            background: white;
            border-radius: 50%%;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            cursor: grab;
            transition: box-shadow 0.2s;
        }
        
        .slider-thumb:active {
            cursor: grabbing;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }
        
        .slider-text {
            position: absolute;
            left: 0;
            right: 0;
            top: 50%%;
            transform: translateY(-50%%);
            text-align: center;
            color: #999;
            font-size: 14px;
            pointer-events: none;
            z-index: 1;
        }
        
        .status-message {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            font-size: 14px;
            display: none;
        }
        
        .status-message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .status-message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .status-message.info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        
        .loading {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid #f3f3f3;
            border-top: 2px solid #667eea;
            border-radius: 50%%;
            animation: spin 1s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }
        
        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }
        
        .footer {
            margin-top: 30px;
            text-align: center;
            color: #999;
            font-size: 12px;
        }
        
        @media (max-width: 600px) {
            .container {
                padding: 30px 20px;
            }
            
            h1 {
                font-size: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="shield-icon">🛡️</div>
            <h1>安全验证</h1>
            <p class="subtitle">为了保护网站安全，请完成以下验证</p>
        </div>
        
        <div class="challenge-container">
            <div class="slider-track" id="sliderTrack">
                <div class="slider-fill" id="sliderFill"></div>
                <div class="slider-text" id="sliderText">向右滑动滑块完成验证</div>
                <div class="slider-thumb" id="sliderThumb">➤</div>
            </div>
        </div>
        
        <div class="status-message" id="statusMessage"></div>
        
        <div class="footer">
            <p>Powered by sslcat</p>
        </div>
    </div>
    
    <script>
        const challengeId = '%s';
        const originalURL = '%s';
        const targetPosition = %d;
        
        const sliderTrack = document.getElementById('sliderTrack');
        const sliderFill = document.getElementById('sliderFill');
        const sliderThumb = document.getElementById('sliderThumb');
        const sliderText = document.getElementById('sliderText');
        const statusMessage = document.getElementById('statusMessage');
        
        let isDragging = false;
        let startX = 0;
        let currentX = 0;
        let track = [];
        let startTime = 0;
        
        // 设置 JavaScript 能力 Cookie
        document.cookie = 'js_enabled=1; path=/; max-age=86400';
        
        function showMessage(message, type) {
            statusMessage.textContent = message;
            statusMessage.className = 'status-message ' + type;
            statusMessage.style.display = 'block';
        }
        
        function hideMessage() {
            statusMessage.style.display = 'none';
        }
        
        function startDrag(e) {
            isDragging = true;
            startX = e.type === 'mousedown' ? e.clientX : e.touches[0].clientX;
            startTime = Date.now();
            track = [];
            sliderThumb.style.transition = 'none';
            sliderFill.style.transition = 'none';
            hideMessage();
        }
        
        function drag(e) {
            if (!isDragging) return;
            
            e.preventDefault();
            const clientX = e.type === 'mousemove' ? e.clientX : e.touches[0].clientX;
            const trackRect = sliderTrack.getBoundingClientRect();
            const maxX = trackRect.width - sliderThumb.offsetWidth;
            
            currentX = Math.max(0, Math.min(clientX - trackRect.left - sliderThumb.offsetWidth / 2, maxX));
            
            sliderThumb.style.left = currentX + 'px';
            sliderFill.style.width = (currentX + sliderThumb.offsetWidth / 2) + 'px';
            
            // 记录轨迹
            track.push({
                x: Math.round((currentX / maxX) * 100),
                y: 0,
                timestamp: Date.now()
            });
            
            // 更新文本透明度
            const progress = currentX / maxX;
            sliderText.style.opacity = 1 - progress;
        }
        
        function endDrag() {
            if (!isDragging) return;
            
            isDragging = false;
            const trackRect = sliderTrack.getBoundingClientRect();
            const maxX = trackRect.width - sliderThumb.offsetWidth;
            const position = Math.round((currentX / maxX) * 100);
            
            // 验证位置
            verifyChallenge(position);
        }
        
        async function verifyChallenge(position) {
            showMessage('验证中...', 'info');
            
            try {
                const response = await fetch('/bot-challenge/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        challenge_id: challengeId,
                        answer: position,
                        track: track,
                        metadata: {
                            user_agent: navigator.userAgent,
                            screen_width: screen.width,
                            screen_height: screen.height,
                            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                        }
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showMessage('✓ 验证成功！正在跳转...', 'success');
                    sliderThumb.textContent = '✓';
                    
                    // 设置验证 Token Cookie
                    if (result.token) {
                        document.cookie = 'bot_verification=' + result.token + '; path=/; max-age=86400';
                    }
                    
                    // 延迟跳转
                    setTimeout(() => {
                        window.location.href = originalURL;
                    }, 1000);
                } else {
                    showMessage('✗ 验证失败：' + (result.message || '请重试'), 'error');
                    resetSlider();
                }
            } catch (error) {
                showMessage('✗ 验证失败：网络错误', 'error');
                resetSlider();
            }
        }
        
        function resetSlider() {
            setTimeout(() => {
                sliderThumb.style.transition = 'left 0.3s ease';
                sliderFill.style.transition = 'width 0.3s ease';
                sliderThumb.style.left = '0';
                sliderFill.style.width = '0';
                sliderText.style.opacity = '1';
                sliderThumb.textContent = '➤';
                currentX = 0;
                track = [];
            }, 1500);
        }
        
        // 鼠标事件
        sliderThumb.addEventListener('mousedown', startDrag);
        document.addEventListener('mousemove', drag);
        document.addEventListener('mouseup', endDrag);
        
        // 触摸事件
        sliderThumb.addEventListener('touchstart', startDrag);
        document.addEventListener('touchmove', drag, { passive: false });
        document.addEventListener('touchend', endDrag);
    </script>
</body>
</html>`, challenge.ID, originalURL, challenge.SliderTarget)
}

// HandleBotChallengeVerify 处理机器人验证请求
func (s *Server) HandleBotChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求
	var verification bot.ChallengeVerification
	if err := json.NewDecoder(r.Body).Decode(&verification); err != nil {
		writeErrorJSON(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// 验证挑战
	if s.botChallengeMgr == nil {
		writeErrorJSON(w, "Bot detection not initialized", http.StatusInternalServerError)
		return
	}

	success, token, err := s.botChallengeMgr.VerifyChallenge(&verification)
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	if !success {
		writeJSON(w, map[string]interface{}{
			"success": false,
			"message": "Verification failed",
		})
		return
	}

	// 验证成功，设置 Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "bot_verification",
		Value:    token,
		Path:     "/",
		MaxAge:   86400, // 24 小时
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, map[string]interface{}{
		"success": true,
		"token":   token,
		"message": "Verification successful",
	})
}

// HandleBotChallengeRefresh 处理刷新挑战请求
func (s *Server) HandleBotChallengeRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ChallengeID string `json:"challenge_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorJSON(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if s.botChallengeMgr == nil {
		writeErrorJSON(w, "Bot detection not initialized", http.StatusInternalServerError)
		return
	}

	clientIP := s.getClientIP(r)
	domain := r.Host

	newChallenge := s.botChallengeMgr.RefreshChallenge(req.ChallengeID, clientIP, domain)

	writeJSON(w, map[string]interface{}{
		"success":   true,
		"challenge": newChallenge,
	})
}

