package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

func (s *Server) needWizard() bool {
	return s.config.Admin.FirstRun
}

// 向导首页
func (s *Server) handleWizard(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>首次启动向导</title>
	<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
	<div class="container mt-4">
	<h3>首次启动向导</h3>
	<div class="card mb-3"><div class="card-body">
		<h5 class="card-title">步骤一：设置管理员密码</h5>
		<p class="card-text">%s</p>
		<a class="btn btn-%s" href="%s">%s</a>
	</div></div>
	<div class="card mb-3"><div class="card-body">
		<h5 class="card-title">步骤二：基础配置</h5>
		<form method="POST" action="%s/wizard/step2" class="row g-3">
			<div class="col-md-6"><label class="form-label">证书邮箱(必填，用于 Let's Encrypt)</label><input class="form-control" type="email" name="email" value="%s" required></div>
			<div class="col-md-6 form-check mt-4"><input class="form-check-input" type="checkbox" name="auto_renew" %s id="ar"><label class="form-check-label" for="ar">启用自动续期</label></div>
			<div class="col-12"><button class="btn btn-primary" type="submit">保存基础配置</button></div>
		</form>
	</div></div>
	<div class="card mb-3"><div class="card-body">
		<h5 class="card-title">步骤三：添加首条代理规则(可选)</h5>
		<form method="POST" action="%s/wizard/step3" class="row g-3">
			<div class="col-md-4"><label class="form-label">域名</label><input class="form-control" name="domain" placeholder="example.com"></div>
			<div class="col-md-6"><label class="form-label">目标(含协议与端口)</label><input class="form-control" name="target" placeholder="http://127.0.0.1:8080"></div>
			<div class="col-12"><button class="btn btn-secondary" type="submit">添加(可跳过)</button></div>
		</form>
	</div></div>
	<form method="POST" action="%s/wizard/finish"><button class="btn btn-success">完成向导</button></form>
	</div></body></html>`,
		func() string {
			if s.needFirstTimeSetup() {
				return "当前未完成初始设置，请先设置"
			}
			return "已完成初始设置"
		}(),
		func() string {
			if s.needFirstTimeSetup() {
				return "warning"
			}
			return "outline-secondary"
		}(),
		func() string {
			if s.needFirstTimeSetup() {
				return s.config.AdminPrefix + "/settings/first-setup"
			}
			return s.config.AdminPrefix + "/dashboard"
		}(),
		func() string {
			if s.needFirstTimeSetup() {
				return "去设置"
			}
			return "已完成"
		}(),
		s.config.AdminPrefix,
		s.config.SSL.Email,
		func() string {
			if s.config.SSL.AutoRenew {
				return "checked"
			}
			return ""
		}(),
		s.config.AdminPrefix,
		s.config.AdminPrefix)
}

func (s *Server) handleWizardStep2(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	auto := r.FormValue("auto_renew") == "on"
	if email == "" || !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		http.Error(w, "请填写合法的邮箱地址（用于 ACME）", http.StatusBadRequest)
		return
	}
	s.config.SSL.Email = email
	s.config.SSL.AutoRenew = auto
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		http.Error(w, "保存失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.sslManager.EnableACME(); err != nil {
		s.log.Warnf("启用 ACME 失败: %v", err)
	}
	s.audit("wizard_step2_saved", email)
	http.Redirect(w, r, s.config.AdminPrefix+"/wizard", http.StatusFound)
}

func (s *Server) handleWizardStep3(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := strings.TrimSpace(r.FormValue("domain"))
	target := strings.TrimSpace(r.FormValue("target"))
	if domain != "" && target != "" {
		newRule := config.ProxyRule{Domain: domain, Target: target, Port: 0, Enabled: true, SSLOnly: true}
		s.config.Proxy.Rules = append(s.config.Proxy.Rules, newRule)
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			http.Error(w, "保存失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.audit("wizard_step3_add_rule", domain+" -> "+target)
	}
	http.Redirect(w, r, s.config.AdminPrefix+"/wizard", http.StatusFound)
}

func (s *Server) handleWizardFinish(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.TrimSpace(s.config.SSL.Email) == "" {
		http.Error(w, "请先在向导第二步填写用于 ACME 的证书邮箱", http.StatusBadRequest)
		return
	}
	s.config.Admin.FirstRun = false
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		http.Error(w, "保存失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit("wizard_finished", "")
	http.Redirect(w, r, s.config.AdminPrefix+"/dashboard", http.StatusFound)
}
