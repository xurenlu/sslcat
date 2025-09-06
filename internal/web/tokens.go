package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/xurenlu/sslcat/internal/security"
)

func (s *Server) handleTokensPage(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tokens := s.tokenStore.List()
	var rows strings.Builder
	for _, t := range tokens {
		rows.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>
			<a class="btn btn-sm btn-outline-danger" href="%s/tokens/delete?token=%s" onclick="return confirm('确认删除该Token?')">删除</a>
		</td></tr>`,
			t.Token, string(t.Role), t.CreatedAt.Format("2006-01-02 15:04:05"), s.config.AdminPrefix, t.Token))
	}
	if rows.Len() == 0 {
		rows.WriteString(`<tr><td colspan="4" class="text-center">暂无Token</td></tr>`)
	}
	html := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Token 管理</title>
	<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
	<div class="container-fluid"><div class="row">
	<div class="col-md-2">%s</div>
	<main class="col-md-10">
		<div class="d-flex justify-content-between align-items-center pt-3 pb-2 mb-3 border-bottom">
			<h1 class="h2">Token 管理</h1>
			<a class="btn btn-primary" href="%s/tokens/generate">生成Token</a>
		</div>
		<div class="card"><div class="card-body">
			<table class="table table-striped"><thead><tr><th>Token</th><th>权限</th><th>创建时间</th><th>操作</th></tr></thead>
			<tbody>%s</tbody></table>
		</div></div>
	</main></div></div></body></html>`,
		s.generateSidebar(s.config.AdminPrefix, "tokens"), s.config.AdminPrefix, rows.String())
	w.Write([]byte(html))
}

func (s *Server) handleTokenGeneratePage(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method == "GET" {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>生成Token</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4"><h3>生成Token</h3>
		<form method="POST" class="mt-3">
			<div class="mb-3"><label class="form-label">权限</label>
				<select class="form-select" name="role">
					<option value="read">只读</option>
					<option value="write">读写</option>
				</select>
			</div>
			<div class="mb-3"><label class="form-label">备注</label>
				<input class="form-control" name="note" placeholder="可选">
			</div>
			<button class="btn btn-primary" type="submit">生成</button>
			<a class="btn btn-secondary" href="%s/tokens">返回</a>
		</form></div></body></html>`, s.config.AdminPrefix)
		return
	}
	if r.Method == "POST" {
		role := r.FormValue("role")
		note := r.FormValue("note")
		if role == "read" || role == "write" {
			if _, err := s.tokenStore.Generate(security.TokenRole(role), note); err != nil {
				http.Error(w, "生成Token失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, s.config.AdminPrefix+"/tokens", http.StatusFound)
			return
		}
		http.Error(w, "role无效", http.StatusBadRequest)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleTokenDeleteAction(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	t := strings.TrimSpace(r.URL.Query().Get("token"))
	if t == "" {
		http.Error(w, "缺少token", http.StatusBadRequest)
		return
	}
	_ = s.tokenStore.Delete(t)
	http.Redirect(w, r, s.config.AdminPrefix+"/tokens", http.StatusFound)
}
