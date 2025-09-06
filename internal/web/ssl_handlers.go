package web

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// SSL管理

func (s *Server) handleSSL(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取SSL证书信息（扫描磁盘）
	certs := s.sslManager.GetCertificateList()

	data := map[string]interface{}{
		"AdminPrefix":  s.config.AdminPrefix,
		"Certificates": certs,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateSSLManagementHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleSSLGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	if r.Method == "POST" {
		domains := r.FormValue("domains")
		if domains != "" {
			domainList := strings.Split(domains, ",")
			for i, domain := range domainList {
				domainList[i] = strings.TrimSpace(domain)
			}

			// 申请证书（使用 ACME，如果可用）
			var firstErr error
			for _, d := range domainList {
				d = strings.ToLower(strings.TrimSpace(d))
				if d == "" {
					continue
				}
				if s.sslManager != nil {
					if err := s.sslManager.EnsureDomainCert(d); err != nil && firstErr == nil {
						firstErr = err
					}
				}
			}
			if firstErr != nil {
				s.log.Warnf("申请证书(ACME)出现问题: %v", firstErr)
			}

			// 重定向回SSL管理页面
			http.Redirect(w, r, s.config.AdminPrefix+"/ssl", http.StatusFound)
			return
		}
	}

	// 显示生成表单
	data := map[string]interface{}{
		"AdminPrefix": s.config.AdminPrefix,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateSSLGenerateHTML(data)
	w.Write([]byte(html))
}

func (s *Server) handleSSLUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	switch r.Method {
	case "GET":
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>上传证书</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4"><h3>上传证书</h3>
		<form method="POST" enctype="multipart/form-data" class="mt-3">
			<div class="mb-3">
				<label class="form-label">域名</label>
				<input class="form-control" name="domain" required>
			</div>
			<div class="mb-3">
				<label class="form-label">证书(.crt/.pem)</label>
				<input class="form-control" type="file" name="cert" accept=".crt,.pem" required>
			</div>
			<div class="mb-3">
				<label class="form-label">私钥(.key/.pem)</label>
				<input class="form-control" type="file" name="key" accept=".key,.pem" required>
			</div>
			<button class="btn btn-primary" type="submit">上传</button>
			<a class="btn btn-secondary" href="%s/ssl">返回</a>
		</form></div></body></html>`, s.config.AdminPrefix)
		return
	case "POST":
		domain := strings.TrimSpace(r.FormValue("domain"))
		if domain == "" {
			http.Error(w, "缺少domain", http.StatusBadRequest)
			return
		}

		certFile, _, err := r.FormFile("cert")
		if err != nil {
			http.Error(w, "读取证书失败", http.StatusBadRequest)
			return
		}
		defer certFile.Close()
		keyFile, _, err := r.FormFile("key")
		if err != nil {
			http.Error(w, "读取私钥失败", http.StatusBadRequest)
			return
		}
		defer keyFile.Close()

		certPath := s.config.SSL.CertDir + "/" + domain + ".crt"
		keyPath := s.config.SSL.KeyDir + "/" + domain + ".key"

		if err := writeAllFromReader(certFile, certPath, 0644); err != nil {
			http.Error(w, "保存证书失败", http.StatusInternalServerError)
			return
		}
		if err := writeAllFromReader(keyFile, keyPath, 0600); err != nil {
			http.Error(w, "保存私钥失败", http.StatusInternalServerError)
			return
		}

		if err := s.sslManager.LoadCertificateFromDisk(domain); err != nil {
			s.log.Warnf("上传后加载证书失败: %v", err)
		}
		http.Redirect(w, r, s.config.AdminPrefix+"/ssl", http.StatusFound)
		return
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (s *Server) handleSSLDownload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	typ := strings.TrimSpace(r.URL.Query().Get("type"))
	if domain == "" {
		http.Error(w, "缺少domain", http.StatusBadRequest)
		return
	}
	if typ == "" {
		typ = "cert"
	}

	var path, filename string
	switch typ {
	case "cert":
		path, filename = s.config.SSL.CertDir+"/"+domain+".crt", domain+".crt"
	case "key":
		path, filename = s.config.SSL.KeyDir+"/"+domain+".key", domain+".key"
	case "bundle":
		path, filename = s.config.SSL.CertDir+"/"+domain+".crt", domain+"-bundle.pem"
	default:
		http.Error(w, "type无效", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	http.ServeFile(w, r, path)
}

func writeAllFromReader(rdr interface{ Read([]byte) (int, error) }, dest string, mode os.FileMode) error {
	data := make([]byte, 0, 64*1024)
	buf := make([]byte, 32*1024)
	for {
		n, err := rdr.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			break
		}
		if n == 0 {
			break
		}
	}
	return os.WriteFile(dest, data, mode)
}

func (s *Server) handleSSLDelete(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain != "" {
		err := s.sslManager.DeleteCertificate(domain)
		if err != nil {
			s.log.Errorf("删除证书失败: %v", err)
			http.Error(w, "删除证书失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// 重定向回SSL管理页面
	http.Redirect(w, r, s.config.AdminPrefix+"/ssl", http.StatusFound)
}
