package webp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// Converter WebP转换器
type Converter struct {
	enabled    bool
	quality    int
	cacheSize  int
	cache      map[string][]byte
	cacheMutex sync.RWMutex
	log        *logrus.Entry
}

// NewConverter 创建WebP转换器
func NewConverter() *Converter {
	return &Converter{
		enabled:   true,
		quality:   80, // 默认质量
		cacheSize: 100, // 缓存100张图片
		cache:     make(map[string][]byte),
		log: logrus.WithFields(logrus.Fields{
			"component": "webp_converter",
		}),
	}
}

// ShouldConvert 检查是否应该转换为WebP
func (c *Converter) ShouldConvert(r *http.Request) bool {
	if !c.enabled {
		return false
	}
	
	// 检查Accept头是否支持WebP
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "image/webp") {
		return false
	}
	
	// 检查User-Agent是否支持WebP
	userAgent := r.Header.Get("User-Agent")
	if !c.supportsWebP(userAgent) {
		return false
	}
	
	return true
}

// supportsWebP 检查浏览器是否支持WebP
func (c *Converter) supportsWebP(userAgent string) bool {
	if userAgent == "" {
		return false
	}
	
	userAgentLower := strings.ToLower(userAgent)
	
	// Chrome 23+
	if strings.Contains(userAgentLower, "chrome/") {
		return true
	}
	
	// Firefox 65+
	if strings.Contains(userAgentLower, "firefox/") {
		return true
	}
	
	// Edge 18+
	if strings.Contains(userAgentLower, "edg/") {
		return true
	}
	
	// Opera 12.1+
	if strings.Contains(userAgentLower, "opera/") || strings.Contains(userAgentLower, "opr/") {
		return true
	}
	
	// Safari 14+
	if strings.Contains(userAgentLower, "safari/") && strings.Contains(userAgentLower, "version/14") {
		return true
	}
	
	// Android WebView
	if strings.Contains(userAgentLower, "android") && strings.Contains(userAgentLower, "chrome/") {
		return true
	}
	
	return false
}

// IsImageRequest 检查是否为图片请求
func (c *Converter) IsImageRequest(url string) bool {
	ext := strings.ToLower(filepath.Ext(url))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif":
		return true
	default:
		return false
	}
}

// ConvertResponse 转换响应中的图片
func (c *Converter) ConvertResponse(w http.ResponseWriter, r *http.Request, originalResponse *http.Response) error {
	if !c.ShouldConvert(r) {
		return c.copyResponse(w, originalResponse)
	}
	
	url := r.URL.String()
	if !c.IsImageRequest(url) {
		return c.copyResponse(w, originalResponse)
	}
	
	// 检查缓存
	c.cacheMutex.RLock()
	if webpData, exists := c.cache[url]; exists {
		c.cacheMutex.RUnlock()
		return c.serveWebP(w, webpData)
	}
	c.cacheMutex.RUnlock()
	
	// 读取原始图片数据
	originalData, err := io.ReadAll(originalResponse.Body)
	if err != nil {
		return fmt.Errorf("读取原始图片失败: %w", err)
	}
	defer originalResponse.Body.Close()
	
	// 检查原始图片大小
	if len(originalData) > 10*1024*1024 { // 超过10MB不转换
		return c.serveOriginal(w, originalResponse, originalData)
	}
	
	// 转换为WebP（这里是模拟实现，实际需要图像处理库）
	webpData, err := c.convertToWebP(originalData, url)
	if err != nil {
		c.log.Warnf("转换WebP失败 %s: %v", url, err)
		return c.serveOriginal(w, originalResponse, originalData)
	}
	
	// 缓存转换结果
	c.cacheWebP(url, webpData)
	
	return c.serveWebP(w, webpData)
}

// convertToWebP 转换图片为WebP格式
func (c *Converter) convertToWebP(data []byte, url string) ([]byte, error) {
	// 注意：这是一个简化的实现示例
	// 实际应用中需要使用图像处理库如 github.com/chai2010/webp
	// 或者调用外部工具如 cwebp
	
	c.log.Debugf("模拟转换图片为WebP: %s", url)
	
	// 这里返回原始数据作为示例
	// 实际实现应该调用WebP编码器
	return data, nil
}

// cacheWebP 缓存WebP图片
func (c *Converter) cacheWebP(url string, data []byte) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	
	// 检查缓存大小限制
	if len(c.cache) >= c.cacheSize {
		// 简单的LRU：删除一个条目
		for key := range c.cache {
			delete(c.cache, key)
			break
		}
	}
	
	c.cache[url] = data
	c.log.Debugf("缓存WebP图片: %s (大小: %d bytes)", url, len(data))
}

// serveWebP 返回WebP图片
func (c *Converter) serveWebP(w http.ResponseWriter, data []byte) error {
	w.Header().Set("Content-Type", "image/webp")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("X-Converted-Format", "webp")
	
	_, err := w.Write(data)
	return err
}

// serveOriginal 返回原始图片
func (c *Converter) serveOriginal(w http.ResponseWriter, originalResponse *http.Response, data []byte) error {
	// 复制原始响应头
	for key, values := range originalResponse.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	
	w.WriteHeader(originalResponse.StatusCode)
	_, err := w.Write(data)
	return err
}

// copyResponse 复制响应
func (c *Converter) copyResponse(w http.ResponseWriter, originalResponse *http.Response) error {
	// 复制响应头
	for key, values := range originalResponse.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	
	w.WriteHeader(originalResponse.StatusCode)
	_, err := io.Copy(w, originalResponse.Body)
	return err
}

// SetEnabled 设置启用状态
func (c *Converter) SetEnabled(enabled bool) {
	c.enabled = enabled
	c.log.Infof("WebP转换已%s", map[bool]string{true: "启用", false: "禁用"}[enabled])
}

// SetQuality 设置转换质量
func (c *Converter) SetQuality(quality int) {
	if quality < 1 {
		quality = 1
	}
	if quality > 100 {
		quality = 100
	}
	
	c.quality = quality
	c.log.Infof("WebP转换质量已设置为: %d", quality)
}

// ClearCache 清空缓存
func (c *Converter) ClearCache() {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()
	
	c.cache = make(map[string][]byte)
	c.log.Info("WebP缓存已清空")
}

// GetStats 获取统计信息
func (c *Converter) GetStats() map[string]interface{} {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()
	
	var totalCacheSize int64
	for _, data := range c.cache {
		totalCacheSize += int64(len(data))
	}
	
	return map[string]interface{}{
		"enabled":          c.enabled,
		"quality":          c.quality,
		"cache_size":       len(c.cache),
		"max_cache_size":   c.cacheSize,
		"total_cache_bytes": totalCacheSize,
	}
}

// Middleware WebP转换中间件
func (c *Converter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否为图片请求且支持WebP
		if c.ShouldConvert(r) && c.IsImageRequest(r.URL.Path) {
			// 创建响应记录器
			recorder := &ResponseRecorder{
				ResponseWriter: w,
				statusCode:     200,
				body:          &bytes.Buffer{},
			}
			
			// 调用下一个处理器
			next.ServeHTTP(recorder, r)
			
			// 如果是图片响应，尝试转换
			contentType := recorder.Header().Get("Content-Type")
			if strings.HasPrefix(contentType, "image/") {
				// 创建模拟的原始响应
				originalResponse := &http.Response{
					StatusCode: recorder.statusCode,
					Header:     recorder.Header(),
					Body:       io.NopCloser(recorder.body),
				}
				
				// 转换并返回
				if err := c.ConvertResponse(w, r, originalResponse); err != nil {
					c.log.Errorf("WebP转换失败: %v", err)
					// 如果转换失败，返回原始内容
					w.WriteHeader(recorder.statusCode)
					w.Write(recorder.body.Bytes())
				}
				return
			}
		}
		
		// 非图片请求，直接传递
		next.ServeHTTP(w, r)
	})
}

// ResponseRecorder 响应记录器
type ResponseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

// WriteHeader 记录状态码
func (rr *ResponseRecorder) WriteHeader(code int) {
	rr.statusCode = code
}

// Write 记录响应体
func (rr *ResponseRecorder) Write(data []byte) (int, error) {
	return rr.body.Write(data)
}

// ProcessImageProxy 处理图片代理请求
func (c *Converter) ProcessImageProxy(w http.ResponseWriter, r *http.Request, proxyFunc func(http.ResponseWriter, *http.Request)) {
	if !c.ShouldConvert(r) || !c.IsImageRequest(r.URL.Path) {
		proxyFunc(w, r)
		return
	}
	
	// 使用响应记录器捕获代理响应
	recorder := &ResponseRecorder{
		ResponseWriter: w,
		statusCode:     200,
		body:          &bytes.Buffer{},
	}
	
	proxyFunc(recorder, r)
	
	// 检查是否为图片响应
	contentType := recorder.Header().Get("Content-Type")
	if strings.HasPrefix(contentType, "image/") {
		// 创建模拟的原始响应
		originalResponse := &http.Response{
			StatusCode: recorder.statusCode,
			Header:     recorder.Header(),
			Body:       io.NopCloser(recorder.body),
		}
		
		// 转换并返回
		if err := c.ConvertResponse(w, r, originalResponse); err != nil {
			c.log.Errorf("图片代理WebP转换失败: %v", err)
			// 如果转换失败，返回原始内容
			for key, values := range recorder.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(recorder.statusCode)
			w.Write(recorder.body.Bytes())
		}
		return
	}
	
	// 非图片内容，直接返回
	for key, values := range recorder.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(recorder.statusCode)
	w.Write(recorder.body.Bytes())
}
