package web

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) handleSSLDownloadAll(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=sslcerts-"+time.Now().Format("20060102-150405")+".zip")
	zw := zip.NewWriter(w)
	defer zw.Close()
	// 打包 cert_dir 与 key_dir
	addDir := func(root string) {
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(strings.ToLower(name), ".crt") && !strings.HasSuffix(strings.ToLower(name), ".key") && !strings.HasSuffix(strings.ToLower(name), ".pem") {
				continue
			}
			path := root + "/" + name
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			defer f.Close()
			wri, err := zw.Create(strings.TrimPrefix(path, "./"))
			if err != nil {
				continue
			}
			buf := make([]byte, 32*1024)
			for {
				n, er := f.Read(buf)
				if n > 0 {
					_, _ = wri.Write(buf[:n])
				}
				if er != nil {
					break
				}
			}
		}
	}
	addDir(s.config.SSL.CertDir)
	addDir(s.config.SSL.KeyDir)
}

func (s *Server) handleSSLBulkUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	if r.Method == "GET" {
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>导入全部证书</title>
		<link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"></head><body>
		<div class="container mt-4"><h3>导入全部证书(zip)</h3>
		<form method="POST" enctype="multipart/form-data" class="mt-3">
			<div class="mb-3"><input class="form-control" type="file" name="zip" accept=".zip" required></div>
			<button class="btn btn-primary" type="submit">上传并导入</button>
			<a class="btn btn-secondary" href="%s/ssl">返回</a>
		</form></div></body></html>`, s.config.AdminPrefix)
		return
	}
	if r.Method == "POST" {
		file, _, err := r.FormFile("zip")
		if err != nil {
			http.Error(w, "读取文件失败", http.StatusBadRequest)
			return
		}
		defer file.Close()
		// 将 zip 存入临时文件并解压
		tmp, err := os.CreateTemp("", "sslzip-*.zip")
		if err != nil {
			http.Error(w, "创建临时文件失败", http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmp.Name())
		buf := make([]byte, 32*1024)
		for {
			n, er := file.Read(buf)
			if n > 0 {
				if _, err := tmp.Write(buf[:n]); err != nil {
					http.Error(w, "写入临时文件失败", http.StatusInternalServerError)
					return
				}
			}
			if er != nil {
				break
			}
		}
		if err := unzipToDirs(tmp.Name(), []string{s.config.SSL.CertDir, s.config.SSL.KeyDir}); err != nil {
			http.Error(w, "解压失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// 重新加载磁盘证书到缓存（尽最大努力）
		entries, _ := os.ReadDir(s.config.SSL.CertDir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".crt") {
				continue
			}
			d := strings.TrimSuffix(e.Name(), ".crt")
			_ = s.sslManager.LoadCertificateFromDisk(d)
		}
		http.Redirect(w, r, s.config.AdminPrefix+"/ssl", http.StatusFound)
		return
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func unzipToDirs(zipPath string, targetDirs []string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		// 仅处理文件
		if f.FileInfo().IsDir() {
			continue
		}
		// 判定放到哪个目录：根据后缀 .crt/.pem -> cert_dir； .key -> key_dir
		destDir := targetDirs[0]
		lower := strings.ToLower(f.Name)
		if strings.HasSuffix(lower, ".key") {
			destDir = targetDirs[1]
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		defer rc.Close()
		content, _ := io.ReadAll(rc)
		base := filepath.Base(f.Name)
		_ = os.MkdirAll(destDir, 0755)
		_ = os.WriteFile(filepath.Join(destDir, base), content, 0600)
	}
	return nil
}
