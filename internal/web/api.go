package web

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"math"
	mathrand "math/rand"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// API处理器

func (s *Server) authorizeAPI(w http.ResponseWriter, r *http.Request, readOnly bool) bool {
	// 1) 如果是面板登录用户（cookie session），允许访问；写接口也允许
	session, exists := s.sessionManager.GetSessionFromRequest(r)
	if exists {
		// 记录用户访问日志
		s.userManager.LogUserAction(
			session.Username,
			"api_access",
			r.URL.Path,
			fmt.Sprintf("API访问: %s %s", r.Method, r.URL.Path),
			s.getClientIP(r),
			r.Header.Get("User-Agent"),
		)
		return true
	}
	// 2) 检查 Authorization: Bearer <token>
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		tok := strings.TrimSpace(authz[len("Bearer "):])
		if role, ok := s.tokenStore.Validate(tok); ok {
			if readOnly {
				return true
			}
			// 写操作需要 write 角色
			if role == "write" {
				return true
			}
		}
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"error":"unauthorized"}`))
	return false
}

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	stats := s.getSystemStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleAPIProxyRules(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.config.Proxy.Rules)
}

func (s *Server) handleAPISSLCerts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	// #region agent log
	logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if logFile != nil {
		logData, _ := json.Marshal(map[string]interface{}{
			"sessionId":    "debug-session",
			"runId":        "run1",
			"hypothesisId": "E",
			"location":     "api.go:86",
			"message":      "API handleAPISSLCerts called",
			"data":         map[string]interface{}{"certDir": s.config.SSL.CertDir},
			"timestamp":    time.Now().UnixMilli(),
		})
		logFile.WriteString(string(logData) + "\n")
		logFile.Close()
	}
	// #endregion

	certs := s.sslManager.GetCertificateList()

	// #region agent log
	if logFile, _ := os.OpenFile("/Users/rocky/Sites/sslcat/.cursor/debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); logFile != nil {
		var domains []string
		for _, c := range certs {
			domains = append(domains, c.Domain)
		}
		logData, _ := json.Marshal(map[string]interface{}{
			"sessionId":    "debug-session",
			"runId":        "run1",
			"hypothesisId": "E",
			"location":     "api.go:99",
			"message":      "API returning certificate list",
			"data":         map[string]interface{}{"certCount": len(certs), "domains": domains},
			"timestamp":    time.Now().UnixMilli(),
		})
		logFile.WriteString(string(logData) + "\n")
		logFile.Close()
	}
	// #endregion

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}

func (s *Server) handleAPISecurityLogs(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	limit := 100
	if ls := r.URL.Query().Get("limit"); ls != "" {
		if v, err := strconv.Atoi(ls); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	onlyFailed := r.URL.Query().Get("only_failed") == "1"

	var all []map[string]any

	// 添加 WAF 事件
	if s.wafEngine != nil && s.wafEngine.Engine != nil {
		wafEvents := s.wafEngine.Engine.GetEvents(limit * 2) // 获取更多事件以便筛选
		for _, event := range wafEvents {
			all = append(all, map[string]any{
				"ip":         event.ClientIP,
				"user_agent": event.UserAgent,
				"path":       event.URL,
				"timestamp":  event.Timestamp,
				"success":    false, // WAF 事件都是失败的访问
				"type":       "waf",
				"rule_name":  event.RuleName,
				"rule_type":  string(event.RuleType),
				"blocked":    event.Blocked,
				"method":     event.Method,
			})
		}
	}

	// 通过只读访问器遍历安全管理器日志
	for ip, logs := range s.securityManager.AccessLogsSnapshot() {
		for _, l := range logs {
			if onlyFailed && l.Success {
				continue
			}
			all = append(all, map[string]any{
				"ip":         ip,
				"user_agent": l.UserAgent,
				"path":       l.Path,
				"timestamp":  l.Timestamp,
				"success":    l.Success,
				"type":       "access",
			})
		}
	}

	// 按时间戳排序（最新的在前）
	sort.Slice(all, func(i, j int) bool {
		ti, ok1 := all[i]["timestamp"].(time.Time)
		tj, ok2 := all[j]["timestamp"].(time.Time)
		if !ok1 || !ok2 {
			return false
		}
		return ti.After(tj)
	})

	if len(all) > limit {
		all = all[:limit]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"logs": all})
}

func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	data, err := os.ReadFile("./data/audit.log")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"logs\":[]}"))
		return
	}
	lines := strings.Split(string(data), "\n")
	type item map[string]any
	var out []item
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var it item
		if err := json.Unmarshal([]byte(ln), &it); err == nil {
			out = append(out, it)
		}
	}
	// 下载模式
	if r.URL.Query().Get("download") == "1" {
		fname := "audit-" + time.Now().Format("20060102-150405") + ".json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+fname)
		json.NewEncoder(w).Encode(map[string]any{"logs": out})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"logs": out})
}

func (s *Server) handleAPITLSFingerprints(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}

	limit := 0
	if q := strings.TrimSpace(r.URL.Query().Get("limit")); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 {
			limit = v
		}
	}

	// 扩展输出（包含 last_seen）
	type ex interface {
		GetTLSFingerprintStatsEx() []struct {
			FP       string
			Count    int
			LastSeen string
		}
	}
	if exm, ok := interface{}(s.securityManager).(ex); ok {
		stats := exm.GetTLSFingerprintStatsEx()
		if limit > 0 && len(stats) > limit {
			stats = stats[:limit]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"fingerprints": stats})
		return
	}
	// 回退到原始统计
	stats := s.securityManager.GetTLSFingerprintStats()
	if limit > 0 && len(stats) > limit {
		stats = stats[:limit]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"fingerprints": stats})
}

// handleAPISecurityAttacks 读取最近N条 DDoS 攻击（JSONL）
func (s *Server) handleAPISecurityAttacks(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	limit := 100
	if q := strings.TrimSpace(r.URL.Query().Get("limit")); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 2000 {
			limit = v
		}
	}
	path := "./data/ddos_attacks.log"
	f, err := os.Open(path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"attacks\":[]}"))
		return
	}
	defer f.Close()
	// 读取全部行（文件通常较小，已做轮转）
	data, _ := io.ReadAll(f)
	lines := strings.Split(string(data), "\n")
	// 取末尾 limit 行
	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}
	type attack map[string]any
	var out []attack
	for i := start; i < len(lines); i++ {
		ln := strings.TrimSpace(lines[i])
		if ln == "" {
			continue
		}
		var rec attack
		if err := json.Unmarshal([]byte(ln), &rec); err == nil {
			out = append(out, rec)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"attacks": out})
}

// handleAPICaptcha 处理验证码API请求
func (s *Server) handleAPICaptcha(w http.ResponseWriter, r *http.Request) {
	// 验证码API不需要登录认证，但只有在需要验证码时才能访问
	if !s.sslManager.HasValidSSLCertificates() {
		// 调试模式允许在无证书时使用 captcha API
		if !(strings.EqualFold(r.URL.Query().Get("debug"), "true") || r.URL.Query().Get("debug") == "1") {
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"error":"captcha not required"}`))
			return
		}
	}

	if r.Method == "GET" {
		// 生成新的验证码
		captchaData, err := s.captchaManager.GenerateCaptcha()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"error":"failed to generate captcha"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(captchaData)
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"error":"method not allowed"}`))
}

// drawCaptchaImage 生成清晰、带适度干扰且带轻微旋转的验证码图片
func drawCaptchaImage(text string) image.Image {
	// 更大画布与更显著字符
	w, h := 220, 72
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// 背景
	bg := color.RGBA{250, 251, 253, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bg}, image.Point{}, draw.Src)

	// safeIntn 使用 crypto/rand 生成安全的随机整数 [0, max)
	// 用于验证码图片的干扰元素生成
	safeIntn := func(max int) int {
		if max <= 0 {
			return 0
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
		if err != nil {
			// 如果 crypto/rand 失败，使用时间戳作为回退
			return int(time.Now().UnixNano()) % max
		}
		return int(n.Int64())
	}

	// 干扰线：使用安全的随机数生成 8~10 条
	lines := 8 + safeIntn(3)
	for i := 0; i < lines; i++ {
		c := color.RGBA{uint8(120 + safeIntn(40)), uint8(130 + safeIntn(40)), uint8(140 + safeIntn(40)), 255}
		x1, y1 := safeIntn(w), safeIntn(h)
		x2, y2 := safeIntn(w), safeIntn(h)
		steps := 220
		for s := 0; s < steps; s++ {
			t := float64(s) / float64(steps)
			x := int(float64(x1) + t*float64(x2-x1))
			y := int(float64(y1) + t*float64(y2-y1))
			if x >= 0 && x < w && y >= 0 && y < h {
				img.SetRGBA(x, y, c)
			}
		}
	}

	// 噪点：随机小块（1~2 px），数量略增
	for i := 0; i < 450; i++ {
		x, y := safeIntn(w), safeIntn(h)
		rw, rh := 1+safeIntn(2), 1+safeIntn(2)
		c := color.RGBA{uint8(190 + safeIntn(40)), uint8(195 + safeIntn(40)), uint8(200 + safeIntn(40)), 255}
		for yy := y; yy < y+rh && yy < h; yy++ {
			for xx := x; xx < x+rw && xx < w; xx++ {
				img.SetRGBA(xx, yy, c)
			}
		}
	}

	// 将每个字符单独绘制到小画布，放大、轻微旋转后粘贴
	col := color.RGBA{16, 16, 16, 255}
	face := basicfont.Face7x13
	per := w / (len(text) + 1)

	// 最近邻 2x 放大
	scale2x := func(src *image.RGBA) *image.RGBA {
		sw := src.Bounds().Dx()
		sh := src.Bounds().Dy()
		dst := image.NewRGBA(image.Rect(0, 0, sw*2, sh*2))
		for y := 0; y < sh*2; y++ {
			sy := y / 2
			for x := 0; x < sw*2; x++ {
				sx := x / 2
				dst.Set(x, y, src.RGBAAt(src.Bounds().Min.X+sx, src.Bounds().Min.Y+sy))
			}
		}
		return dst
	}
	// 最近邻旋转（-18°~+18°），返回含边距的新图
	rotate := func(src *image.RGBA, rad float64) *image.RGBA {
		cw := src.Bounds().Dx()
		ch := src.Bounds().Dy()
		mw, mh := cw+16, ch+16
		dst := image.NewRGBA(image.Rect(0, 0, mw, mh))
		cx := float64(cw) / 2
		cy := float64(ch) / 2
		cosv := math.Cos(rad)
		sinv := math.Sin(rad)
		for y := 0; y < mh; y++ {
			for x := 0; x < mw; x++ {
				sx := float64(x-8) - cx
				sy := float64(y-8) - cy
				ox := +cosv*sx + sinv*sy + cx
				oy := -sinv*sx + cosv*sy + cy
				i := int(math.Round(ox))
				j := int(math.Round(oy))
				if i >= 0 && i < cw && j >= 0 && j < ch {
					c := src.RGBAAt(i, j)
					if c.A != 0 {
						dst.SetRGBA(x, y, c)
					}
				}
			}
		}
		return dst
	}

	for i := 0; i < len(text); i++ {
		ch := string(text[i])
		// 小画布绘制字符（带白色阴影）
		sW, sH := 24, 28
		small := image.NewRGBA(image.Rect(0, 0, sW, sH))
		shadow := &font.Drawer{Dst: small, Src: &image.Uniform{color.RGBA{255, 255, 255, 255}}, Face: face}
		shadow.Dot = fixed.P(4, 17)
		shadow.DrawString(ch)
		dr := &font.Drawer{Dst: small, Src: &image.Uniform{col}, Face: face}
		dr.Dot = fixed.P(3, 16)
		dr.DrawString(ch)

		// 放大 2x
		big := scale2x(small)
		// 数字/特殊字符更大旋转幅度，字母也更大
		// 注意：这里使用 math/rand 仅用于验证码的视觉效果（旋转角度），不影响安全性
		// 验证码的内容本身已在其他地方使用安全随机数生成
		var deg float64
		if strings.ContainsRune("23457?*%$@#", rune(text[i])) {
			deg = (mathrand.Float64()*56 - 28) * math.Pi / 180 // ±28°
		} else {
			deg = (mathrand.Float64()*44 - 22) * math.Pi / 180 // ±22°
		}
		rot := rotate(big, deg)
		// 贴到主画布，居中于分配区块
		px := (i+1)*per - rot.Bounds().Dx()/2
		py := (h - rot.Bounds().Dy()) / 2
		for y := 0; y < rot.Bounds().Dy(); y++ {
			for x := 0; x < rot.Bounds().Dx(); x++ {
				c := rot.RGBAAt(x, y)
				if c.A == 0 {
					continue
				}
				dx := px + x
				dy := py + y
				if dx >= 0 && dx < w && dy >= 0 && dy < h {
					img.SetRGBA(dx, dy, c)
				}
			}
		}
	}

	return img
}

// handleAPIImageCaptcha 返回带干扰线与噪点的图形验证码
func (s *Server) handleAPIImageCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// 生成会话与答案
	sid, code, err := s.captchaManager.GenerateImageCaptcha()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"captcha generation failed"}`))
		return
	}
	// 绘制并返回 PNG
	img := drawCaptchaImage(code)
	w.Header().Set("X-Captcha-Session", sid)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "image/png")
	_ = png.Encode(w, img)
}

