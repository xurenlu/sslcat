package web

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"

	"github.com/pquerna/otp/totp"
)

// handleTOTPSetup 处理 TOTP 设置页面
func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "GET" {
		// 如果已启用 TOTP，显示禁用选项
		if s.config.Admin.EnableTOTP {
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>TOTP设置</title>
			<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
			<div class="container mt-4">
				<h3>TOTP 二次验证已启用</h3>
				<div class="alert alert-success">您的账户已启用 TOTP 二次验证</div>
				<form method="POST">
					<input type="hidden" name="action" value="disable">
					<button class="btn btn-warning" type="submit">禁用 TOTP</button>
					<a class="btn btn-secondary ms-2" href="%s/settings">返回</a>
				</form>
			</div></body></html>`, s.config.AdminPrefix)
			return
		}

		// 生成新的 TOTP 密钥
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "SSLcat",
			AccountName: s.config.Admin.Username,
		})
		if err != nil {
			http.Error(w, "Failed to generate TOTP key", http.StatusInternalServerError)
			return
		}

		// 生成二维码
		img, err := key.Image(200, 200)
		if err != nil {
			http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
			return
		}

		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			http.Error(w, "Failed to encode QR code", http.StatusInternalServerError)
			return
		}

		qrDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>TOTP设置</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4">
			<h3>设置 TOTP 二次验证</h3>
			<div class="row">
				<div class="col-md-6">
					<h5>1. 扫描二维码</h5>
					<img src="%s" alt="TOTP QR Code" class="img-fluid mb-3">
					<p class="text-muted">使用 Google Authenticator、Authy 等应用扫描上方二维码</p>
				</div>
				<div class="col-md-6">
					<h5>2. 输入验证码</h5>
					<form method="POST">
						<input type="hidden" name="secret" value="%s">
						<input type="hidden" name="action" value="enable">
						<div class="mb-3">
							<label class="form-label">6位验证码</label>
							<input class="form-control" name="code" placeholder="123456" required maxlength="6" pattern="[0-9]{6}">
						</div>
						<button class="btn btn-primary" type="submit">启用 TOTP</button>
						<a class="btn btn-secondary ms-2" href="%s/settings">取消</a>
					</form>
				</div>
			</div>
		</div></body></html>`, qrDataURL, key.Secret(), s.config.AdminPrefix)
		return
	}

	if r.Method == "POST" {
		action := r.FormValue("action")
		
		if action == "disable" {
			// 禁用 TOTP
			s.config.Admin.EnableTOTP = false
			s.config.Admin.TOTPSecret = ""
			_ = s.config.Save(s.config.ConfigFile)
			http.Redirect(w, r, s.config.AdminPrefix+"/settings", http.StatusFound)
			return
		}

		if action == "enable" {
			// 启用 TOTP
			secret := r.FormValue("secret")
			code := r.FormValue("code")
			
			if secret == "" || code == "" {
				http.Error(w, "Missing secret or code", http.StatusBadRequest)
				return
			}

			// 验证代码
			if !totp.Validate(code, secret) {
				http.Error(w, "Invalid TOTP code", http.StatusBadRequest)
				return
			}

			// 保存配置
			s.config.Admin.EnableTOTP = true
			s.config.Admin.TOTPSecret = secret
			_ = s.config.Save(s.config.ConfigFile)
			
			http.Redirect(w, r, s.config.AdminPrefix+"/settings", http.StatusFound)
			return
		}
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// verifyTOTP 验证 TOTP 代码
func (s *Server) verifyTOTP(code string) bool {
	if !s.config.Admin.EnableTOTP || s.config.Admin.TOTPSecret == "" {
		return true // TOTP 未启用时直接通过
	}
	return totp.Validate(code, s.config.Admin.TOTPSecret)
}
