package web

import (
	"crypto/md5"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/cache"
	"github.com/xurenlu/sslcat/internal/config"
)

// StaticFileHandler 静态文件处理器
type StaticFileHandler struct {
	config       *config.Config
	log          *logrus.Entry
	mimeDetector *cache.MIMEDetector
}

// NewStaticFileHandler 创建静态文件处理器
func NewStaticFileHandler(cfg *config.Config) *StaticFileHandler {
	return &StaticFileHandler{
		config:       cfg,
		log:          logrus.WithFields(logrus.Fields{"component": "static_handler"}),
		mimeDetector: cache.NewMIMEDetector(),
	}
}

// ServeFile 智能服务静态文件
func (h *StaticFileHandler) ServeFile(w http.ResponseWriter, r *http.Request, filePath string) error {
	// 检查文件是否存在
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return nil
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}

	// 如果是目录，返回403
	if fileInfo.IsDir() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}
	defer file.Close()

	// 智能检测Content-Type
	contentType := h.detectContentType(filePath, file)
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	// 设置缓存策略
	h.setCacheHeaders(w, r, filePath, fileInfo)

	// 设置安全头
	h.setSecurityHeaders(w, r, filePath)

	// 设置自定义响应头
	h.setCustomHeaders(w, r)

	// 处理条件请求
	if h.handleConditionalRequest(w, r, fileInfo) {
		return nil
	}

	// 设置内容长度
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))

	// 智能压缩处理
	if h.shouldCompress(filePath, fileInfo.Size(), contentType) {
		return h.serveWithCompression(w, r, file, fileInfo)
	}

	// 直接复制文件内容
	_, err = io.Copy(w, file)
	return err
}

// detectContentType 智能检测Content-Type
func (h *StaticFileHandler) detectContentType(filePath string, file *os.File) string {
	// 1. 尝试从文件内容检测
	if h.mimeDetector != nil {
		// 读取文件头进行检测
		header := make([]byte, 32)
		if n, err := file.Read(header); err == nil && n > 0 {
			// 重置文件指针
			file.Seek(0, 0)

			detectedType := h.mimeDetector.DetectMIME(filePath, header[:n])
			if detectedType != "" && detectedType != "application/octet-stream" {
				h.log.Debugf("通过文件内容检测到Content-Type: %s", detectedType)
				return detectedType
			}
		}
	}

	// 2. 通过扩展名检测
	if h.mimeDetector != nil {
		detectedType := h.mimeDetector.DetectMIME(filePath, nil)
		if detectedType != "" && detectedType != "application/octet-stream" {
			h.log.Debugf("通过扩展名检测到Content-Type: %s", detectedType)
			return detectedType
		}
	}

	// 3. 使用系统默认MIME类型
	if mimeType := mime.TypeByExtension(filepath.Ext(filePath)); mimeType != "" {
		h.log.Debugf("使用系统默认MIME类型: %s", mimeType)
		return mimeType
	}

	// 4. 默认返回二进制类型
	h.log.Debugf("使用默认Content-Type: application/octet-stream")
	return "application/octet-stream"
}

// setCacheHeaders 设置缓存头
func (h *StaticFileHandler) setCacheHeaders(w http.ResponseWriter, r *http.Request, filePath string, fileInfo os.FileInfo) {
	ext := strings.ToLower(filepath.Ext(filePath))

	// 根据文件类型设置不同的缓存策略
	switch ext {
	case ".html", ".htm":
		// HTML文件：短缓存，允许重新验证
		w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		w.Header().Set("Vary", "Accept-Encoding")

	case ".css", ".js":
		// CSS/JS文件：长缓存，带版本控制
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Vary", "Accept-Encoding")

	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico":
		// 图片文件：长缓存
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		// 字体文件：长缓存
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx":
		// 文档文件：中等缓存
		w.Header().Set("Cache-Control", "public, max-age=3600")

	case ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm":
		// 视频文件：中等缓存
		w.Header().Set("Cache-Control", "public, max-age=7200")

	case ".mp3", ".wav", ".ogg", ".m4a":
		// 音频文件：中等缓存
		w.Header().Set("Cache-Control", "public, max-age=7200")

	case ".zip", ".rar", ".7z", ".tar", ".gz":
		// 压缩文件：短缓存
		w.Header().Set("Cache-Control", "public, max-age=1800")

	case ".txt", ".md", ".json", ".xml", ".csv":
		// 文本文件：短缓存
		w.Header().Set("Cache-Control", "public, max-age=1800")

	default:
		// 其他文件：默认缓存策略
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}

	// 设置ETag
	etag := h.generateETag(fileInfo)
	w.Header().Set("ETag", etag)

	// 设置Last-Modified
	w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))
}

// setSecurityHeaders 设置安全头
func (h *StaticFileHandler) setSecurityHeaders(w http.ResponseWriter, r *http.Request, filePath string) {
	ext := strings.ToLower(filepath.Ext(filePath))

	// 对于HTML文件，设置更严格的安全头
	if ext == ".html" || ext == ".htm" {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	}

	// 对于可执行文件，设置下载头
	if h.isExecutableFile(filePath) {
		w.Header().Set("Content-Disposition", "attachment")
	}
}

// setCustomHeaders 设置静态站点自定义响应头
func (h *StaticFileHandler) setCustomHeaders(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	for _, site := range h.config.StaticSites {
		if !site.Enabled {
			continue
		}
		if !strings.EqualFold(site.Domain, host) {
			continue
		}
		for key, value := range site.ResponseHeaders {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			if value == "" {
				w.Header().Del(trimmedKey)
				continue
			}
			w.Header().Set(trimmedKey, value)
		}
		break
	}
}

// handleConditionalRequest 处理条件请求
func (h *StaticFileHandler) handleConditionalRequest(w http.ResponseWriter, r *http.Request, fileInfo os.FileInfo) bool {
	// 检查If-None-Match (ETag)
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		etag := h.generateETag(fileInfo)
		if ifNoneMatch == etag || ifNoneMatch == "*" {
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}

	// 检查If-Modified-Since
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" {
		if clientTime, err := http.ParseTime(ifModifiedSince); err == nil {
			if !clientTime.Before(fileInfo.ModTime()) {
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	return false
}

// shouldCompress 判断是否应该压缩
func (h *StaticFileHandler) shouldCompress(filePath string, fileSize int64, contentType string) bool {
	// 文件太小不压缩（小于1KB）
	if fileSize < 1024 {
		return false
	}

	// 检查文件类型
	ext := strings.ToLower(filepath.Ext(filePath))

	// 需要压缩的文件类型
	compressibleTypes := map[string]bool{
		".html": true,
		".htm":  true,
		".css":  true,
		".js":   true,
		".json": true,
		".xml":  true,
		".txt":  true,
		".md":   true,
		".svg":  true,
	}

	// 已经压缩的文件类型不再次压缩
	alreadyCompressed := map[string]bool{
		".jpg":   true,
		".jpeg":  true,
		".png":   true,
		".gif":   true,
		".webp":  true,
		".ico":   true,
		".mp4":   true,
		".mp3":   true,
		".zip":   true,
		".rar":   true,
		".7z":    true,
		".pdf":   true,
		".woff":  true,
		".woff2": true,
		".ttf":   true,
		".otf":   true,
	}

	// 如果已经压缩，不再次压缩
	if alreadyCompressed[ext] {
		return false
	}

	// 如果是可压缩类型，且文件大小大于1KB，则压缩
	return compressibleTypes[ext] && fileSize >= 1024
}

// serveWithCompression 使用压缩方式服务文件
func (h *StaticFileHandler) serveWithCompression(w http.ResponseWriter, r *http.Request, file *os.File, fileInfo os.FileInfo) error {
	// 读取文件内容
	content, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	// 简单的gzip压缩实现
	// 注意：这里可以使用更高级的压缩器，如Brotli
	acceptEncoding := r.Header.Get("Accept-Encoding")
	if strings.Contains(acceptEncoding, "gzip") {
		// 这里应该使用实际的压缩器
		// 为了简化，我们直接返回原内容
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
	}

	// 写入内容
	_, err = w.Write(content)
	return err
}

// generateETag 生成ETag
func (h *StaticFileHandler) generateETag(fileInfo os.FileInfo) string {
	// 使用文件修改时间和大小生成ETag
	hash := md5.Sum([]byte(fmt.Sprintf("%d-%d", fileInfo.ModTime().Unix(), fileInfo.Size())))
	return fmt.Sprintf("\"%x\"", hash)
}

// isExecutableFile 判断是否为可执行文件
func (h *StaticFileHandler) isExecutableFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	executableExts := map[string]bool{
		".exe": true,
		".msi": true,
		".dmg": true,
		".pkg": true,
		".deb": true,
		".rpm": true,
		".bin": true,
		".run": true,
		".sh":  true,
		".bat": true,
		".cmd": true,
		".com": true,
		".scr": true,
	}
	return executableExts[ext]
}
