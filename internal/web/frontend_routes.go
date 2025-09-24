package web

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/xurenlu/sslcat/internal/assets"
)

// setupFrontendRoutes 设置前端 SPA 路由
func (s *Server) setupFrontendRoutes() {
	// 静态资源路由 (JS, CSS, 图片等)
	s.mux.HandleFunc(s.config.AdminPrefix+"/assets/", s.handleFrontendAssets)

	// SPA 入口路由 - 返回 index.html
	s.mux.HandleFunc(s.config.AdminPrefix+"/spa/", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/spa", s.handleSPA)
}

// handleFrontendAssets 处理前端静态资源
func (s *Server) handleFrontendAssets(w http.ResponseWriter, r *http.Request) {
	// 检查认证
	if !s.checkAuth(w, r) {
		return
	}

	// 获取嵌入的前端文件系统
	fsys, err := assets.GetFrontendFS()
	if err != nil {
		s.log.Errorf("Failed to get frontend filesystem: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 移除前缀路径
	prefix := s.config.AdminPrefix + "/assets/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}

	// 获取相对路径，注意这里需要包含 assets/ 前缀
	relativePath := strings.TrimPrefix(r.URL.Path, prefix)
	if relativePath == "" {
		http.NotFound(w, r)
		return
	}

	// 构建完整的文件路径
	filePath := "assets/" + relativePath

	// 设置缓存头和 MIME 类型
	if strings.Contains(relativePath, ".") {
		ext := filepath.Ext(relativePath)
		switch ext {
		case ".js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".css":
			w.Header().Set("Content-Type", "text/css")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".png":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".jpg", ".jpeg":
			w.Header().Set("Content-Type", "image/jpeg")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".gif":
			w.Header().Set("Content-Type", "image/gif")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".ico":
			w.Header().Set("Content-Type", "image/x-icon")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		default:
			w.Header().Set("Cache-Control", "public, max-age=3600") // 1小时
		}
	}

	// 尝试打开并服务文件
	file, err := fsys.Open(filePath)
	if err != nil {
		s.log.Debugf("Frontend asset not found: %s", filePath)
		http.NotFound(w, r)
		return
	}
	defer file.Close()

	// 复制文件内容
	io.Copy(w, file)
}

// handleSPA 处理 SPA 路由
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	// 检查认证
	if !s.checkAuth(w, r) {
		return
	}

	// 对于 SPA，所有路由都返回 index.html
	fsys, err := assets.GetFrontendFS()
	if err != nil {
		s.log.Errorf("Failed to get frontend filesystem: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 读取 index.html
	indexFile, err := fsys.Open("index.html")
	if err != nil {
		s.log.Errorf("Failed to open index.html: %v", err)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	defer indexFile.Close()

	// 设置内容类型
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// 复制文件内容
	io.Copy(w, indexFile)
}
