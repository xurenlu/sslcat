package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/assets"
)

// setupFrontendRoutes 设置前端 SPA 路由
func (s *Server) setupFrontendRoutes() {
	// 内嵌静态资源路由 (Bootstrap, fonts等)
	s.mux.HandleFunc("/static/", s.handleStaticAssets)

	// 静态资源路由 (JS, CSS, 图片等)
	s.mux.HandleFunc(s.config.AdminPrefix+"/assets/", s.handleFrontendAssets)

	// SPA 入口路由 - 返回 index.html
	s.mux.HandleFunc(s.config.AdminPrefix+"/spa/", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/spa", s.handleSPA)

	// 前端路由 - 让这些路由也返回 SPA
	s.mux.HandleFunc(s.config.AdminPrefix+"/dashboard", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/mobile", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/charts", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy/add", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/proxy/edit", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/sites", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ssl", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/settings", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/dns", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/security", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/cluster", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/runners", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/git-server", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/notifications", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/users", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/static-sites", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/php-sites", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/tokens", s.handleSPA)
	s.mux.HandleFunc(s.config.AdminPrefix+"/ai-security", s.handleSPA)
}

// handleFrontendAssets 处理前端静态资源
func (s *Server) handleFrontendAssets(w http.ResponseWriter, r *http.Request) {
	// 静态资源不需要认证，直接提供服务

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

	// 获取文件信息用于ETag生成
	fileInfo, err := file.Stat()
	if err != nil {
		s.log.Debugf("Failed to get file info: %s", filePath)
		http.NotFound(w, r)
		return
	}

	// 生成ETag（基于文件修改时间和大小）
	etag := generateETag(fileInfo)
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))

	// 检查条件请求
	if checkConditionalRequest(w, r, etag, fileInfo.ModTime()) {
		return
	}

	// 智能压缩处理
	if shouldCompress(filePath, fileInfo.Size()) {
		s.serveWithCompression(w, r, file, fileInfo)
	} else {
		// 直接复制文件内容
		io.Copy(w, file)
	}
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

	// 读取HTML内容
	htmlContent, err := io.ReadAll(indexFile)
	if err != nil {
		s.log.Errorf("Failed to read index.html: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 动态重写资源路径，将相对路径替换为当前管理面板路径
	htmlStr := string(htmlContent)
	// 替换 /assets/ 为当前管理面板路径 + /assets/
	htmlStr = strings.ReplaceAll(htmlStr, `src="/assets/`, `src="`+s.config.AdminPrefix+`/assets/`)
	htmlStr = strings.ReplaceAll(htmlStr, `href="/assets/`, `href="`+s.config.AdminPrefix+`/assets/`)
	// 替换 favicon 路径
	htmlStr = strings.ReplaceAll(htmlStr, `href="/favicon.ico"`, `href="`+s.config.AdminPrefix+`/favicon.ico"`)

	// 设置内容类型
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	// 写入修改后的HTML内容
	w.Write([]byte(htmlStr))
}

// generateETag 生成基于文件信息的ETag
func generateETag(fileInfo os.FileInfo) string {
	// 使用文件修改时间和大小生成ETag
	// 格式: "W/\"size-mtime\"" (弱ETag)
	size := fileInfo.Size()
	mtime := fileInfo.ModTime().Unix()
	return fmt.Sprintf("W/\"%d-%d\"", size, mtime)
}

// checkConditionalRequest 检查HTTP条件请求
func checkConditionalRequest(w http.ResponseWriter, r *http.Request, etag string, lastModified time.Time) bool {
	// 检查 If-None-Match (ETag验证)
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		// 支持弱ETag比较
		clientETag := strings.TrimSpace(ifNoneMatch)
		serverETag := strings.TrimSpace(etag)

		// 移除弱ETag标记进行比较
		if strings.HasPrefix(clientETag, "W/\"") && strings.HasSuffix(clientETag, "\"") {
			clientETag = clientETag[3 : len(clientETag)-1]
		}
		if strings.HasPrefix(serverETag, "W/\"") && strings.HasSuffix(serverETag, "\"") {
			serverETag = serverETag[3 : len(serverETag)-1]
		}

		if clientETag == serverETag {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}

	// 检查 If-Modified-Since (时间验证)
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		// 解析客户端发送的时间
		clientTime, err := http.ParseTime(ifModifiedSince)
		if err == nil {
			// 比较时间，如果客户端缓存的时间 >= 服务器最后修改时间，返回304
			if !clientTime.Before(lastModified) {
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	return false
}

// shouldCompress 判断是否应该压缩文件
func shouldCompress(filePath string, fileSize int64) bool {
	// 文件太小不压缩（小于1KB）
	if fileSize < 1024 {
		return false
	}

	// 检查文件类型
	ext := strings.ToLower(filepath.Ext(filePath))

	// 需要压缩的文件类型
	compressibleTypes := map[string]bool{
		".js":   true,
		".css":  true,
		".html": true,
		".htm":  true,
		".xml":  true,
		".json": true,
		".txt":  true,
		".svg":  true,
	}

	// 已经压缩的文件类型不再次压缩
	alreadyCompressed := map[string]bool{
		".gz":    true,
		".br":    true,
		".zip":   true,
		".rar":   true,
		".7z":    true,
		".jpg":   true,
		".jpeg":  true,
		".png":   true,
		".gif":   true,
		".webp":  true,
		".ico":   true,
		".woff":  true,
		".woff2": true,
		".ttf":   true,
		".eot":   true,
	}

	// 如果已经压缩，不再次压缩
	if alreadyCompressed[ext] {
		return false
	}

	// 如果是可压缩类型，且文件大小大于1KB，则压缩
	return compressibleTypes[ext] && fileSize >= 1024
}

// serveWithCompression 使用压缩方式服务文件
func (s *Server) serveWithCompression(w http.ResponseWriter, r *http.Request, file io.Reader, fileInfo os.FileInfo) {
	// 读取文件内容
	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// 使用压缩器压缩内容
	if s.compressor != nil {
		// 根据文件扩展名确定Content-Type
		contentType := getContentType(fileInfo.Name())
		s.compressor.CompressResponse(w, r, content, contentType)
	} else {
		// 如果压缩器未初始化，直接返回原内容
		w.Write(content)
	}
}

// getContentType 根据文件名获取Content-Type
func getContentType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".js":
		return "application/javascript"
	case ".css":
		return "text/css"
	case ".html", ".htm":
		return "text/html"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".svg":
		return "image/svg+xml"
	case ".txt":
		return "text/plain"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".eot":
		return "application/vnd.ms-fontobject"
	default:
		return "application/octet-stream"
	}
}

// handleStaticAssets 处理内嵌静态资源（Bootstrap, fonts等）
func (s *Server) handleStaticAssets(w http.ResponseWriter, r *http.Request) {
	// 静态资源不需要认证，直接提供服务

	// 移除前缀路径
	prefix := "/static/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}

	// 获取相对路径
	relativePath := strings.TrimPrefix(r.URL.Path, prefix)
	if relativePath == "" {
		http.NotFound(w, r)
		return
	}

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
		case ".woff":
			w.Header().Set("Content-Type", "font/woff")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".woff2":
			w.Header().Set("Content-Type", "font/woff2")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".ttf":
			w.Header().Set("Content-Type", "font/ttf")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		case ".eot":
			w.Header().Set("Content-Type", "application/vnd.ms-fontobject")
			w.Header().Set("Cache-Control", "public, max-age=31536000") // 1年
		default:
			w.Header().Set("Cache-Control", "public, max-age=3600") // 1小时
		}
	}

	// 读取静态资源文件
	content, err := assets.ReadStatic(relativePath)
	if err != nil {
		s.log.Debugf("Static asset not found: %s", relativePath)
		http.NotFound(w, r)
		return
	}

	// 写入内容
	w.Write(content)
}
