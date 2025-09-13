package web

import (
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"math"
)

// API处理器

func (s *Server) authorizeAPI(w http.ResponseWriter, r *http.Request, readOnly bool) bool {
	// 1) 如果是面板登录用户（cookie session），允许访问；写接口也允许
	if c, err := r.Cookie("sslcat_session"); err == nil && c.Value == "authenticated" {
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

// handleAPICDNCacheStats 返回类CDN缓存的简单统计
func (s *Server) handleAPICDNCacheStats(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	// 通过 proxyManager 间接访问 cdn cache
	type cacher interface{ Stats() map[string]any }
	var stats map[string]any = map[string]any{"enabled": false}
	if pm, ok := interface{}(s.proxyManager).(interface{ GetCDNCache() cacher }); ok {
		if c := pm.GetCDNCache(); c != nil {
			stats = c.Stats()
		}
	}
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

	certs := s.sslManager.GetCertificateList()
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

	type logItem struct {
		IP        string    `json:"ip"`
		UserAgent string    `json:"user_agent"`
		Path      string    `json:"path"`
		Timestamp time.Time `json:"timestamp"`
		Success   bool      `json:"success"`
	}
	var all []logItem

	// 通过只读访问器遍历
	for ip, logs := range s.securityManager.AccessLogsSnapshot() {
		for _, l := range logs {
			if onlyFailed && l.Success {
				continue
			}
			all = append(all, logItem{IP: ip, UserAgent: l.UserAgent, Path: l.Path, Timestamp: l.Timestamp, Success: l.Success})
		}
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
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

	stats := s.securityManager.GetTLSFingerprintStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"fingerprints": stats})
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

// drawCaptchaImage 生成清晰、略带干扰且带轻微旋转的验证码图片
func drawCaptchaImage(text string) image.Image {
	// 画布尺寸更大
	w, h := 220, 72
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	// 背景
	bg := color.RGBA{250, 251, 253, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bg}, image.Point{}, draw.Src)

	// 轻微干扰线（3-4条）
	rand.Seed(time.Now().UnixNano())
	lines := 3 + rand.Intn(2)
	for i := 0; i < lines; i++ {
		c := color.RGBA{180, 190, 200, 255}
		x1, y1 := rand.Intn(w), rand.Intn(h)
		x2, y2 := rand.Intn(w), rand.Intn(h)
		steps := 180
		for s := 0; s < steps; s++ {
			t := float64(s) / float64(steps)
			x := int(float64(x1) + t*float64(x2-x1))
			y := int(float64(y1) + t*float64(y2-y1))
			if x >= 0 && x < w && y >= 0 && y < h {
				img.SetRGBA(x, y, c)
			}
		}
	}
	// 适度噪点（随画布放大而增加）
	for i := 0; i < 350; i++ {
		x, y := rand.Intn(w), rand.Intn(h)
		c := color.RGBA{200, 205, 210, 255}
		img.SetRGBA(x, y, c)
	}

	// 将每个字符单独绘制到小画布，再放大、旋转后贴到主画布
	col := color.RGBA{16, 16, 16, 255}
	face := basicfont.Face7x13
	per := w / (len(text) + 1)

	// 最近邻放大
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
	// 旋转（最近邻），角度单位弧度，返回新图（包含足够边距）
	rotate := func(src *image.RGBA, rad float64) *image.RGBA {
		cw := src.Bounds().Dx()
		ch := src.Bounds().Dy()
		// 目标尺寸留出边距，避免裁剪
		mw, mh := cw+16, ch+16
		dst := image.NewRGBA(image.Rect(0, 0, mw, mh))
		// 预填透明
		// 旋转中心
		cx := float64(cw) / 2
		cy := float64(ch) / 2
		cosv := math.Cos(rad)
		sinv := math.Sin(rad)
		for y := 0; y < mh; y++ {
			for x := 0; x < mw; x++ {
				// 映射到 src
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
		// 小画布绘制字符
		sW, sH := 24, 28
		small := image.NewRGBA(image.Rect(0, 0, sW, sH))
		// 先绘制白色阴影提升可读性
		shadow := &font.Drawer{Dst: small, Src: &image.Uniform{color.RGBA{255, 255, 255, 255}}, Face: face}
		shadow.Dot = fixed.P(3, 16)
		shadow.DrawString(ch)
		dr := &font.Drawer{Dst: small, Src: &image.Uniform{col}, Face: face}
		dr.Dot = fixed.P(2, 15)
		dr.DrawString(ch)

		// 放大 2x
		big := scale2x(small)
		// 随机轻微旋转（-12° ~ +12°）
		deg := (rand.Float64()*24 - 12) * math.Pi / 180
		rot := rotate(big, deg)
		// 贴到主画布，居中于分配区块
		px := (i+1)*per - rot.Bounds().Dx()/2
		py := (h-rot.Bounds().Dy())/2
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
