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

// isValidDomain 检查域名是否有效，防止路径遍历攻击
func isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	// 检查域名长度（防止过长域名导致的问题）
	if len(domain) > 253 {
		return false
	}
	// 防止路径遍历攻击
	if strings.Contains(domain, "..") || strings.Contains(domain, "/") || strings.Contains(domain, "\\") {
		return false
	}
	// 防止绝对路径
	if strings.HasPrefix(domain, "/") || strings.HasPrefix(domain, ".") {
		return false
	}
	// 防止控制字符和空字符
	for _, r := range domain {
		if r < 32 || r == 127 {
			return false
		}
	}
	// 基本域名格式检查（简化版）
	return true
}

func (s *Server) handleSSLDownloadAll(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=sslcerts-"+time.Now().Format("20060102-150405")+".zip")
	zw := zip.NewWriter(w)
	defer zw.Close()

	// 获取所有证书列表
	certs := s.sslManager.GetCertificateList()

	// 按域名组织文件结构
	for _, certInfo := range certs {
		domain := certInfo.Domain
		// 验证域名有效性，防止路径遍历攻击
		if !isValidDomain(domain) {
			s.log.Warnf("跳过无效域名: %s", domain)
			continue
		}
		// 为每个域名创建文件夹
		domainDir := domain + "/"

		// 添加证书文件
		certPath := filepath.Join(s.config.SSL.CertDir, domain+".crt")
		if certFile, err := os.Open(certPath); err == nil {
			zipPath := domainDir + domain + ".crt"
			if wri, err := zw.Create(zipPath); err == nil {
				buf := make([]byte, 32*1024)
				for {
					n, er := certFile.Read(buf)
					if n > 0 {
						_, _ = wri.Write(buf[:n])
					}
					if er != nil {
						break
					}
				}
			}
			certFile.Close()
		}

		// 添加私钥文件
		keyPath := filepath.Join(s.config.SSL.KeyDir, domain+".key")
		if keyFile, err := os.Open(keyPath); err == nil {
			zipPath := domainDir + domain + ".key"
			if wri, err := zw.Create(zipPath); err == nil {
				buf := make([]byte, 32*1024)
				for {
					n, er := keyFile.Read(buf)
					if n > 0 {
						_, _ = wri.Write(buf[:n])
					}
					if er != nil {
						break
					}
				}
			}
			keyFile.Close()
		}
	}
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
		// 限制上传体积
		maxUpload := s.config.Server.MaxUploadBytes
		if maxUpload <= 0 {
			maxUpload = 1 << 30
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxUpload)

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
		if _, err := io.CopyBuffer(tmp, file, buf); err != nil {
			http.Error(w, "写入临时文件失败", http.StatusInternalServerError)
			return
		}
		if _, err := tmp.Seek(0, 0); err != nil {
			http.Error(w, "临时文件不可读", http.StatusInternalServerError)
			return
		}
		if err := unzipToDirs(tmp.Name(), []string{s.config.SSL.CertDir, s.config.SSL.KeyDir}, maxUpload); err != nil {
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

func unzipToDirs(zipPath string, targetDirs []string, maxTotal int64) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	var total int64
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
		// 目标文件
		base := filepath.Base(f.Name)
		if err := os.MkdirAll(destDir, 0755); err != nil {
			rc.Close()
			return err
		}
		dstPath := filepath.Join(destDir, base)
		dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			rc.Close()
			return err
		}
		// 计算该文件允许的最大剩余额度
		remaining := maxTotal - total
		if remaining <= 0 {
			dst.Close()
			rc.Close()
			return fmt.Errorf("extracted size exceeds limit")
		}
		// 限流拷贝
		limited := &io.LimitedReader{R: rc, N: remaining}
		buf := make([]byte, 32*1024)
		n, copyErr := io.CopyBuffer(dst, limited, buf)
		total += n
		dst.Close()
		rc.Close()
		if copyErr != nil && copyErr != io.EOF {
			return copyErr
		}
		if total > maxTotal {
			return fmt.Errorf("extracted size exceeds limit")
		}
	}
	return nil
}
