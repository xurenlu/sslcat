package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	data, err := json.MarshalIndent(s.config, "", "  ")
	if err != nil {
		http.Error(w, "导出配置失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	filename := "sslcat-" + time.Now().Format("20060102-150405") + ".json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write(data)
}

func (s *Server) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method == "GET" {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>导入配置</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4"><h3>导入配置(JSON)</h3>
		<div class="mb-3">
			<a class="btn btn-outline-info btn-sm" href="%s/config/export" target="_blank">
				<i class="bi bi-download"></i> 下载当前配置（用于参考）
			</a>
		</div>
		<form method="POST" enctype="multipart/form-data" class="mt-3">
			<div class="mb-3">
				<label class="form-label">选择JSON文件</label>
				<input class="form-control" type="file" name="file" accept="application/json">
			</div>
			<div class="mb-3">
				<label class="form-label">或直接粘贴JSON</label>
				<textarea class="form-control" name="json" rows="10" placeholder="粘贴配置JSON内容..."></textarea>
			</div>
			<button class="btn btn-primary" type="submit">预览变更</button>
			<a class="btn btn-secondary" href="%s/settings">返回</a>
		</form></div></body></html>`, s.config.AdminPrefix, s.config.AdminPrefix)
		return
	}
	// POST
	var payload []byte
	if f, _, err := r.FormFile("file"); err == nil {
		defer f.Close()
		buf := make([]byte, 0, 64*1024)
		tmp := make([]byte, 32*1024)
		for {
			n, er := f.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if er != nil {
				break
			}
		}
		payload = buf
	} else {
		payload = []byte(r.FormValue("json"))
	}
	if len(payload) == 0 {
		http.Error(w, "未提供配置", http.StatusBadRequest)
		return
	}
	var proposed config.Config
	if err := json.Unmarshal(payload, &proposed); err != nil {
		http.Error(w, "JSON解析失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 保存到pending
	s.pendingImportJSON = string(payload)
	s.pendingImport = &proposed
	d := config.CompareConfigs(s.config, &proposed)
	s.pendingDiff = &d

	// 调试：记录差异信息
	s.log.Infof("配置导入差异统计: Server=%d, SSL=%d, Admin=%d, Security=%d, ProxyAdded=%d, ProxyRemoved=%d, ProxyModified=%d",
		len(d.ServerChanges), len(d.SSLChanges), len(d.AdminChanges), len(d.SecurityChanges),
		len(d.ProxyAdded), len(d.ProxyRemoved), len(d.ProxyModified))

	http.Redirect(w, r, s.config.AdminPrefix+"/config/preview", http.StatusFound)
}

func (s *Server) handleConfigPreview(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if s.pendingImport == nil || s.pendingDiff == nil {
		http.Error(w, "没有待预览的配置", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(s.renderDiffHTML(*s.pendingDiff)))
}

func (s *Server) handleConfigApply(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pendingImport == nil {
		http.Error(w, "没有待应用的配置", http.StatusBadRequest)
		return
	}
	// 写回文件：保留原路径，避免被导入配置覆盖
	oldPath := s.config.ConfigFile
	*s.config = *s.pendingImport
	// 恢复原有配置文件路径
	s.config.ConfigFile = oldPath
	if err := s.config.Save(oldPath); err != nil {
		http.Error(w, "保存配置失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// 清理pending
	s.pendingImport = nil
	s.pendingDiff = nil
	s.pendingImportJSON = ""
	http.Redirect(w, r, s.config.AdminPrefix+"/settings", http.StatusFound)
}

func (s *Server) renderDiffHTML(d config.ConfigDiff) string {
	// 检查是否有任何变更
	hasChanges := len(d.ServerChanges) > 0 || len(d.SSLChanges) > 0 || len(d.AdminChanges) > 0 ||
		len(d.SecurityChanges) > 0 || len(d.ProxyAdded) > 0 || len(d.ProxyRemoved) > 0 ||
		len(d.ProxyModified) > 0 || d.AdminPrefix != nil

	section := func(title string, rows []config.KeyChange) string {
		if len(rows) == 0 {
			return ""
		}
		b := &strings.Builder{}
		fmt.Fprintf(b, `<div class="card mb-3">
		<div class="card-header fw-bold">%s</div>
		<div class="card-body p-0">
		<table class="table table-striped table-hover mb-0">
		<thead><tr><th style="width:35%%">键</th><th style="width:32.5%%">当前</th><th style="width:32.5%%">导入</th></tr></thead><tbody>`, title)
		for _, r := range rows {
			fmt.Fprintf(b, `<tr><td class="text-muted">%s</td><td><code>%s</code></td><td><code>%s</code></td></tr>`, r.Key, htmlEscape(r.Old), htmlEscape(r.New))
		}
		b.WriteString(`</tbody></table></div></div>`)
		return b.String()
	}

	proxySection := func(d config.ConfigDiff) string {
		if len(d.ProxyAdded)+len(d.ProxyRemoved)+len(d.ProxyModified) == 0 {
			return ""
		}
		b := &strings.Builder{}
		b.WriteString(`<div class="card mb-3">
		<div class="card-header fw-bold">Proxy 规则变更</div>
		<div class="card-body">
		`)
		if len(d.ProxyAdded) > 0 {
			b.WriteString(`<div class="mb-2"><span class="badge bg-success me-1">新增</span></div>`)
			b.WriteString(`<ul class="list-group mb-3">`)
			for _, a := range d.ProxyAdded {
				fmt.Fprintf(b, `<li class="list-group-item"><span class="text-success">+ %s</span> → target=%s port=%d enabled=%t ssl_only=%t</li>`, htmlEscape(a.Domain), htmlEscape(a.Target), a.Port, a.Enabled, a.SSLOnly)
			}
			b.WriteString(`</ul>`)
		}
		if len(d.ProxyRemoved) > 0 {
			b.WriteString(`<div class="mb-2"><span class="badge bg-danger me-1">删除</span></div>`)
			b.WriteString(`<ul class="list-group mb-3">`)
			for _, r := range d.ProxyRemoved {
				fmt.Fprintf(b, `<li class="list-group-item"><span class="text-danger">- %s</span> → target=%s port=%d enabled=%t ssl_only=%t</li>`, htmlEscape(r.Domain), htmlEscape(r.Target), r.Port, r.Enabled, r.SSLOnly)
			}
			b.WriteString(`</ul>`)
		}
		if len(d.ProxyModified) > 0 {
			b.WriteString(`<div class="mb-2"><span class="badge bg-warning text-dark me-1">修改</span></div>`)
			for _, m := range d.ProxyModified {
				fmt.Fprintf(b, `<div class="mb-2"><div class="fw-semibold">%s</div>`, htmlEscape(m.Domain))
				b.WriteString(`<table class="table table-sm table-bordered"><thead><tr><th>字段</th><th>当前</th><th>导入</th></tr></thead><tbody>`)
				for _, fc := range m.FieldChanges {
					fmt.Fprintf(b, `<tr><td class="text-muted">%s</td><td><code>%s</code></td><td><code>%s</code></td></tr>`, fc.Key, htmlEscape(fc.Old), htmlEscape(fc.New))
				}
				b.WriteString(`</tbody></table></div>`)
			}
		}
		b.WriteString(`</div></div>`)
		return b.String()
	}

	head := `<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">`
	b := &strings.Builder{}
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>配置变更预览</title>` + head + `</head><body>`)
	b.WriteString(`<div class="container mt-4">
	<div class="d-flex justify-content-between align-items-center mb-3">
		<h3 class="mb-0">配置变更预览</h3>
		<div>
			<form method="POST" action="` + s.config.AdminPrefix + `/config/apply" class="d-inline">
				<button class="btn btn-danger"` + func() string {
		if !hasChanges {
			return ` disabled`
		}
		return ""
	}() + `>确认应用变更</button>
			</form>
			<a class="btn btn-secondary ms-2" href="` + s.config.AdminPrefix + `/settings">取消</a>
		</div>
	</div>
	`)

	// 如果没有变更，显示提示
	if !hasChanges {
		b.WriteString(`<div class="alert alert-info">
			<h5><i class="bi bi-info-circle"></i> 没有检测到配置变更</h5>
			<p class="mb-0">导入的配置与当前配置相同，无需应用任何变更。</p>
		</div>`)
	}

	b.WriteString(section("Server", d.ServerChanges))
	b.WriteString(section("SSL", d.SSLChanges))
	b.WriteString(section("Admin", d.AdminChanges))
	b.WriteString(section("Security", d.SecurityChanges))
	if d.AdminPrefix != nil {
		b.WriteString(section("Admin Prefix", []config.KeyChange{*d.AdminPrefix}))
	}
	b.WriteString(proxySection(d))

	b.WriteString(`<div class="mt-3">
	<form method="POST" action="` + s.config.AdminPrefix + `/config/apply" class="d-inline">
		<button class="btn btn-danger">确认应用变更</button>
	</form>
	<a class="btn btn-secondary ms-2" href="` + s.config.AdminPrefix + `/settings">取消</a>
	</div>`)

	b.WriteString(`</div></body></html>`)
	return b.String()
}

func (s *Server) renderDiffPlain(d config.ConfigDiff) string {
	b := &strings.Builder{}
	w := func(title string, items []config.KeyChange) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(b, "%s\n", title)
		for _, it := range items {
			fmt.Fprintf(b, "- %s: %s => %s\n", it.Key, it.Old, it.New)
		}
		b.WriteString("\n")
	}
	w("[Server]", d.ServerChanges)
	w("[SSL]", d.SSLChanges)
	w("[Admin]", d.AdminChanges)
	w("[Security]", d.SecurityChanges)
	if d.AdminPrefix != nil {
		fmt.Fprintf(b, "[AdminPrefix]\n- %s: %s => %s\n\n", d.AdminPrefix.Key, d.AdminPrefix.Old, d.AdminPrefix.New)
	}
	if len(d.ProxyAdded)+len(d.ProxyRemoved)+len(d.ProxyModified) > 0 {
		fmt.Fprintf(b, "[Proxy]\n")
		for _, a := range d.ProxyAdded {
			fmt.Fprintf(b, "+ add %s => %v\n", a.Domain, a)
		}
		for _, r := range d.ProxyRemoved {
			fmt.Fprintf(b, "- remove %s => %v\n", r.Domain, r)
		}
		for _, m := range d.ProxyModified {
			fmt.Fprintf(b, "~ modify %s\n", m.Domain)
			for _, fc := range m.FieldChanges {
				fmt.Fprintf(b, "  - %s: %s => %s\n", fc.Key, fc.Old, fc.New)
			}
		}
	}
	return b.String()
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}
