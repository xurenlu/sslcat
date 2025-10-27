package imageopt

import (
	"bytes"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chai2010/webp"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/cache"
	"golang.org/x/image/draw"
)

// ImageFormat 图片格式
type ImageFormat string

const (
	FormatJPEG ImageFormat = "jpeg"
	FormatPNG  ImageFormat = "png"
	FormatGIF  ImageFormat = "gif"
	FormatWebP ImageFormat = "webp"
	FormatAVIF ImageFormat = "avif"
)

// Config 图片优化配置
type Config struct {
	Enabled bool `json:"enabled"`

	// 格式转换
	AutoWebP      bool `json:"auto_webp"`      // 自动转换为 WebP
	WebPQuality   int  `json:"webp_quality"`   // WebP 质量 (0-100)
	JPEGQuality   int  `json:"jpeg_quality"`   // JPEG 质量 (0-100)
	PNGLevel      int  `json:"png_level"`      // PNG 压缩级别 (0-9)
	StripMetadata bool `json:"strip_metadata"` // 移除 EXIF 元数据

	// 文件大小限制（优化 CPU 使用）
	MinSizeBytes int64 `json:"min_size_bytes"` // 最小文件大小（字节），小于此值不转换
	MaxSizeBytes int64 `json:"max_size_bytes"` // 最大文件大小（字节），大于此值不转换
	MaxPixels    int64 `json:"max_pixels"`     // 最大像素数（宽*高），防止大图片占用过多内存

	// 尺寸调整
	AllowResize  bool  `json:"allow_resize"`  // 允许尺寸调整
	MaxWidth     int   `json:"max_width"`     // 最大宽度
	MaxHeight    int   `json:"max_height"`    // 最大高度
	AllowedSizes []int `json:"allowed_sizes"` // 允许的尺寸列表

	// 缓存
	CacheEnabled bool  `json:"cache_enabled"`  // 启用缓存
	CacheTTL     int   `json:"cache_ttl"`      // 缓存TTL（秒）
	MaxCacheSize int64 `json:"max_cache_size"` // 最大缓存大小（字节）

	// 过滤器
	IncludePatterns []string `json:"include_patterns"` // 包含的路径模式
	ExcludePatterns []string `json:"exclude_patterns"` // 排除的路径模式
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		Enabled:         false,
		AutoWebP:        true,
		WebPQuality:     80,
		JPEGQuality:     85,
		PNGLevel:        6,
		StripMetadata:   true,
		MinSizeBytes:    60 * 1024,       // 60KB - 跳过小图标
		MaxSizeBytes:    5 * 1024 * 1024, // 5MB - 跳过超大图
		MaxPixels:       4000 * 3000,     // 1200万像素 - 防止大图片内存暴增
		AllowResize:     true,
		MaxWidth:        2000,
		MaxHeight:       2000,
		AllowedSizes:    []int{100, 200, 400, 800, 1200, 1600},
		CacheEnabled:    true,
		CacheTTL:        86400,             // 24小时
		MaxCacheSize:    512 * 1024 * 1024, // 从1GB降到512MB
		IncludePatterns: []string{"*.jpg", "*.jpeg", "*.png", "*.gif"},
		ExcludePatterns: []string{"/admin/*", "/api/*"},
	}
}

// ImageOptimizer 图片优化器（使用统一的内存缓存管理器）
type Optimizer struct {
	Config   *Config // 导出Config字段以便外部访问
	memCache *cache.MemoryCache
	log      *logrus.Entry

	// 统计
	totalRequests      int64
	cacheHits          int64
	cacheMisses        int64
	totalBytesSaved    int64
	totalOriginalSize  int64
	totalOptimizedSize int64

	// 并发控制（防止内存暴增）
	concurrencySem chan struct{}
	maxConcurrent  int
}

// NewOptimizer 创建图片优化器
func NewOptimizer(config *Config) *Optimizer {
	if config == nil {
		config = DefaultConfig()
	}

	opt := &Optimizer{
		Config: config,
		log: logrus.WithFields(logrus.Fields{
			"component": "image_optimizer",
		}),
		maxConcurrent:  10,                      // 最多10个并发转换
		concurrencySem: make(chan struct{}, 10), // 信号量
	}

	// 初始化统一缓存管理器
	if config.CacheEnabled {
		opt.memCache = cache.NewMemoryCache(&cache.MemoryCacheConfig{
			Name:            "image_optimization",
			MaxEntries:      200,                                          // 从500减少到200
			MaxSizeBytes:    config.MaxCacheSize,                          // 使用配置的最大缓存大小
			MaxItemSize:     2 * 1024 * 1024,                              // 从5MB降到2MB
			DefaultTTL:      time.Duration(config.CacheTTL) * time.Second, // 使用配置的 TTL
			CleanupInterval: 1 * time.Minute,                              // 从2分钟改为1分钟，更频繁清理
		})
	}

	return opt
}

// ShouldOptimize 判断是否应该优化这个请求
func (o *Optimizer) ShouldOptimize(path string) bool {
	if !o.Config.Enabled {
		return false
	}

	// 检查排除模式
	for _, pattern := range o.Config.ExcludePatterns {
		if matchPattern(path, pattern) {
			return false
		}
	}

	// 检查包含模式
	if len(o.Config.IncludePatterns) == 0 {
		return isImagePath(path)
	}

	for _, pattern := range o.Config.IncludePatterns {
		if matchPattern(path, pattern) {
			return true
		}
	}

	return false
}

// matchPattern 简单的模式匹配
func matchPattern(path, pattern string) bool {
	// 简化实现：支持 * 通配符
	if strings.Contains(pattern, "*") {
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(path, parts[0]) && strings.HasSuffix(path, parts[1])
		}
	}
	return strings.HasPrefix(path, pattern)
}

// isImagePath 判断是否是图片路径
func isImagePath(path string) bool {
	lowerPath := strings.ToLower(path)
	return strings.HasSuffix(lowerPath, ".jpg") ||
		strings.HasSuffix(lowerPath, ".jpeg") ||
		strings.HasSuffix(lowerPath, ".png") ||
		strings.HasSuffix(lowerPath, ".gif") ||
		strings.HasSuffix(lowerPath, ".webp")
}

// ProcessResponse 实现 ResponseProcessor 接口
func (o *Optimizer) ProcessResponse(data []byte, contentType string, r *http.Request) ([]byte, string, error) {
	return o.OptimizeResponse(data, contentType, r)
}

// OptimizeResponse 优化响应中的图片
func (o *Optimizer) OptimizeResponse(originalData []byte, contentType string, r *http.Request) ([]byte, string, error) {
	o.totalRequests++

	// 并发控制：防止内存暴增
	select {
	case o.concurrencySem <- struct{}{}:
		// 添加panic恢复，确保信号量不泄漏
		defer func() {
			<-o.concurrencySem
			if r := recover(); r != nil {
				o.log.Errorf("Image optimization panic recovered: %v", r)
			}
		}()
	default:
		// 并发已满，直接返回原图
		o.log.Warn("Image optimization concurrency limit reached, returning original")
		return originalData, contentType, nil
	}

	// 检查文件大小（优化 CPU 使用）
	originalSize := int64(len(originalData))

	// 太小，不值得转换（通常是图标、小图片）
	if o.Config.MinSizeBytes > 0 && originalSize < o.Config.MinSizeBytes {
		o.log.Debugf("Image too small to optimize: %d bytes (min: %d), skipping",
			originalSize, o.Config.MinSizeBytes)
		return originalData, contentType, nil
	}

	// 太大，避免阻塞请求
	if o.Config.MaxSizeBytes > 0 && originalSize > o.Config.MaxSizeBytes {
		o.log.Warnf("Image too large to optimize: %d bytes (max: %d), skipping",
			originalSize, o.Config.MaxSizeBytes)
		return originalData, contentType, nil
	}

	// 检测图片格式
	format := detectFormat(originalData, contentType)
	if format == "" {
		return originalData, contentType, nil // 不是图片，直接返回
	}

	// 构建缓存键
	cacheKey := o.buildCacheKey(r, format)

	// 检查缓存
	if o.Config.CacheEnabled && o.memCache != nil {
		if item, ok := o.memCache.Get(cacheKey); ok {
			o.cacheHits++
			o.log.Debugf("Cache hit: %s", cacheKey)
			// 从元数据恢复 ContentType
			contentType := "image/webp"
			if item.Metadata != nil {
				if ct, ok := item.Metadata["content_type"].(string); ok {
					contentType = ct
				}
			}
			return item.Data, contentType, nil
		}
		o.cacheMisses++
	}

	// 解析请求参数
	params := o.parseParams(r)

	// 执行优化
	optimizedData, newContentType, err := o.optimize(originalData, format, params, r)
	if err != nil {
		o.log.Warnf("Image optimization failed: %v, returning original", err)
		return originalData, contentType, nil // 失败则返回原图
	}

	// 统计
	o.totalOriginalSize += int64(len(originalData))
	o.totalOptimizedSize += int64(len(optimizedData))
	o.totalBytesSaved += int64(len(originalData) - len(optimizedData))

	// 异步缓存结果（避免阻塞响应）
	if o.Config.CacheEnabled && o.memCache != nil {
		go func() {
			metadata := map[string]interface{}{
				"content_type": newContentType,
				"cache_key":    cacheKey,
			}
			o.memCache.SetWithMetadata(cacheKey, optimizedData, metadata, 0) // 使用默认 TTL
		}()
	}

	o.log.Debugf("Image optimized: %s, original: %d bytes, optimized: %d bytes, saved: %.1f%%",
		cacheKey, len(originalData), len(optimizedData),
		float64(len(originalData)-len(optimizedData))/float64(len(originalData))*100)

	return optimizedData, newContentType, nil
}

// OptimizeParams 优化参数
type OptimizeParams struct {
	Width   int
	Height  int
	Quality int
	Format  ImageFormat
	Scale   float64
}

// parseParams 解析请求参数
func (o *Optimizer) parseParams(r *http.Request) *OptimizeParams {
	params := &OptimizeParams{
		Quality: -1, // -1 表示使用默认质量
	}

	// 解析宽度
	if w := r.URL.Query().Get("width"); w != "" {
		if width, err := strconv.Atoi(w); err == nil && width > 0 {
			params.Width = width
		}
	}
	if w := r.URL.Query().Get("w"); w != "" {
		if width, err := strconv.Atoi(w); err == nil && width > 0 {
			params.Width = width
		}
	}

	// 解析高度
	if h := r.URL.Query().Get("height"); h != "" {
		if height, err := strconv.Atoi(h); err == nil && height > 0 {
			params.Height = height
		}
	}
	if h := r.URL.Query().Get("h"); h != "" {
		if height, err := strconv.Atoi(h); err == nil && height > 0 {
			params.Height = height
		}
	}

	// 解析缩放比例
	if s := r.URL.Query().Get("scale"); s != "" {
		if scale, err := strconv.ParseFloat(s, 64); err == nil && scale > 0 && scale <= 1 {
			params.Scale = scale
		}
	}

	// 解析质量
	if q := r.URL.Query().Get("quality"); q != "" {
		if quality, err := strconv.Atoi(q); err == nil && quality > 0 && quality <= 100 {
			params.Quality = quality
		}
	}

	// 解析格式
	if f := r.URL.Query().Get("format"); f != "" {
		params.Format = ImageFormat(strings.ToLower(f))
	} else if o.Config.AutoWebP {
		// 智能WebP转换：检测浏览器支持，不支持的保持原格式
		if o.supportsWebP(r) {
			params.Format = FormatWebP
		}
		// 如果不支持WebP，params.Format保持为空，使用原格式
	}

	return params
}

// supportsWebP 检查客户端是否支持 WebP
func (o *Optimizer) supportsWebP(r *http.Request) bool {
	// 1. 检查Accept头是否明确支持WebP
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "image/webp") {
		return true
	}

	// 2. 检查User-Agent，识别已知支持WebP的浏览器
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		// 没有User-Agent，可能是API调用，默认支持
		return true
	}

	userAgentLower := strings.ToLower(userAgent)

	// Chrome 32+ (2014年)
	if strings.Contains(userAgentLower, "chrome/") && !strings.Contains(userAgentLower, "edg/") {
		return true
	}

	// Firefox 65+ (2019年)
	if strings.Contains(userAgentLower, "firefox/") {
		return true
	}

	// Safari 14+ (2020年) - 需要更精确的版本检测
	if strings.Contains(userAgentLower, "safari/") && !strings.Contains(userAgentLower, "chrome/") {
		// Safari 14+ 支持WebP，但版本检测比较复杂
		// 简化处理：假设现代Safari都支持
		return true
	}

	// Edge 18+ (2018年)
	if strings.Contains(userAgentLower, "edg/") {
		return true
	}

	// Opera 19+ (2014年)
	if strings.Contains(userAgentLower, "opera/") || strings.Contains(userAgentLower, "opr/") {
		return true
	}

	// 移动端浏览器
	if strings.Contains(userAgentLower, "android") && strings.Contains(userAgentLower, "chrome/") {
		return true
	}

	// 如果Accept头包含*/*，且是已知的现代浏览器，默认支持
	if strings.Contains(accept, "*/*") {
		// 检查是否是现代浏览器
		if strings.Contains(userAgentLower, "chrome/") ||
			strings.Contains(userAgentLower, "firefox/") ||
			strings.Contains(userAgentLower, "safari/") ||
			strings.Contains(userAgentLower, "edg/") {
			return true
		}
	}

	// 默认不支持（保守策略）
	return false
}

// detectFormat 检测图片格式
func detectFormat(data []byte, contentType string) ImageFormat {
	if len(data) < 12 {
		return ""
	}

	// 通过魔数检测
	if bytes.Equal(data[0:2], []byte{0xFF, 0xD8}) {
		return FormatJPEG
	}
	if bytes.Equal(data[0:8], []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}) {
		return FormatPNG
	}
	if bytes.Equal(data[0:6], []byte("GIF87a")) || bytes.Equal(data[0:6], []byte("GIF89a")) {
		return FormatGIF
	}
	if bytes.Equal(data[0:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")) {
		return FormatWebP
	}

	// 通过 Content-Type 检测
	if strings.Contains(contentType, "image/jpeg") {
		return FormatJPEG
	}
	if strings.Contains(contentType, "image/png") {
		return FormatPNG
	}
	if strings.Contains(contentType, "image/gif") {
		return FormatGIF
	}
	if strings.Contains(contentType, "image/webp") {
		return FormatWebP
	}

	return ""
}

// optimize 执行图片优化
func (o *Optimizer) optimize(data []byte, sourceFormat ImageFormat, params *OptimizeParams, r *http.Request) ([]byte, string, error) {
	// 先检查图片尺寸（避免解码大图片）
	config, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("decode config: %w", err)
	}

	// 检查像素数限制（防止大图片内存暴增）
	if o.Config.MaxPixels > 0 {
		pixels := int64(config.Width) * int64(config.Height)
		if pixels > o.Config.MaxPixels {
			o.log.Warnf("Image too large: %dx%d (%d pixels, max: %d), skipping",
				config.Width, config.Height, pixels, o.Config.MaxPixels)
			return data, contentTypeFromFormat(sourceFormat), nil
		}
	}

	// 解码原始图片
	img, err := o.decodeImage(data, sourceFormat)
	if err != nil {
		return nil, "", fmt.Errorf("decode image: %w", err)
	}

	// 应用尺寸调整
	if o.Config.AllowResize {
		img = o.resizeImage(img, params)
	}

	// 确定输出格式
	outputFormat := sourceFormat
	if params.Format != "" {
		outputFormat = params.Format
	}

	// 确定质量
	quality := o.getQuality(outputFormat, params.Quality)

	// 编码优化后的图片
	optimizedData, contentType, err := o.encodeImage(img, outputFormat, quality)
	if err != nil {
		return nil, "", fmt.Errorf("encode image: %w", err)
	}

	// 如果优化后反而更大，返回原图
	if len(optimizedData) >= len(data) {
		o.log.Debugf("Optimized image is larger than original, returning original")
		return data, contentTypeFromFormat(sourceFormat), nil
	}

	return optimizedData, contentType, nil
}

// decodeImage 解码图片
func (o *Optimizer) decodeImage(data []byte, format ImageFormat) (image.Image, error) {
	reader := bytes.NewReader(data)

	switch format {
	case FormatJPEG:
		return jpeg.Decode(reader)
	case FormatPNG:
		return png.Decode(reader)
	case FormatGIF:
		return gif.Decode(reader)
	case FormatWebP:
		return webp.Decode(reader)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// resizeImage 调整图片尺寸
func (o *Optimizer) resizeImage(img image.Image, params *OptimizeParams) image.Image {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	newWidth := width
	newHeight := height

	// 应用缩放
	if params.Scale > 0 && params.Scale < 1 {
		newWidth = int(float64(width) * params.Scale)
		newHeight = int(float64(height) * params.Scale)
	}

	// 应用指定宽度
	if params.Width > 0 && params.Width < width {
		newWidth = params.Width
		newHeight = int(float64(height) * float64(newWidth) / float64(width))
	}

	// 应用指定高度
	if params.Height > 0 && params.Height < height {
		newHeight = params.Height
		if params.Width == 0 {
			newWidth = int(float64(width) * float64(newHeight) / float64(height))
		}
	}

	// 限制最大尺寸
	if newWidth > o.Config.MaxWidth {
		scale := float64(o.Config.MaxWidth) / float64(newWidth)
		newWidth = o.Config.MaxWidth
		newHeight = int(float64(newHeight) * scale)
	}
	if newHeight > o.Config.MaxHeight {
		scale := float64(o.Config.MaxHeight) / float64(newHeight)
		newHeight = o.Config.MaxHeight
		newWidth = int(float64(newWidth) * scale)
	}

	// 检查是否在允许的尺寸列表中（如果配置了）
	if len(o.Config.AllowedSizes) > 0 && params.Width > 0 {
		allowed := false
		for _, size := range o.Config.AllowedSizes {
			if params.Width == size {
				allowed = true
				break
			}
		}
		if !allowed {
			// 不在允许列表中，使用最接近的尺寸
			newWidth = o.findClosestSize(params.Width)
			newHeight = int(float64(height) * float64(newWidth) / float64(width))
		}
	}

	// 如果尺寸没有变化，直接返回原图
	if newWidth == width && newHeight == height {
		return img
	}

	// 执行缩放
	dst := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))
	draw.CatmullRom.Scale(dst, dst.Bounds(), img, bounds, draw.Over, nil)

	o.log.Debugf("Resized image: %dx%d -> %dx%d", width, height, newWidth, newHeight)

	return dst
}

// findClosestSize 找到最接近的允许尺寸
func (o *Optimizer) findClosestSize(requested int) int {
	if len(o.Config.AllowedSizes) == 0 {
		return requested
	}

	closest := o.Config.AllowedSizes[0]
	minDiff := abs(requested - closest)

	for _, size := range o.Config.AllowedSizes {
		diff := abs(requested - size)
		if diff < minDiff {
			minDiff = diff
			closest = size
		}
	}

	return closest
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// getQuality 获取质量参数
func (o *Optimizer) getQuality(format ImageFormat, requestedQuality int) int {
	if requestedQuality > 0 && requestedQuality <= 100 {
		return requestedQuality
	}

	switch format {
	case FormatWebP:
		return o.Config.WebPQuality
	case FormatJPEG:
		return o.Config.JPEGQuality
	default:
		return 85
	}
}

// encodeImage 编码图片
func (o *Optimizer) encodeImage(img image.Image, format ImageFormat, quality int) ([]byte, string, error) {
	var buf bytes.Buffer

	switch format {
	case FormatJPEG:
		err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
		return buf.Bytes(), "image/jpeg", err

	case FormatPNG:
		encoder := png.Encoder{CompressionLevel: png.BestCompression}
		err := encoder.Encode(&buf, img)
		return buf.Bytes(), "image/png", err

	case FormatGIF:
		err := gif.Encode(&buf, img, nil)
		return buf.Bytes(), "image/gif", err

	case FormatWebP:
		err := webp.Encode(&buf, img, &webp.Options{
			Lossless: false,
			Quality:  float32(quality),
		})
		return buf.Bytes(), "image/webp", err

	default:
		return nil, "", fmt.Errorf("unsupported output format: %s", format)
	}
}

// contentTypeFromFormat 从格式获取 Content-Type
func contentTypeFromFormat(format ImageFormat) string {
	switch format {
	case FormatJPEG:
		return "image/jpeg"
	case FormatPNG:
		return "image/png"
	case FormatGIF:
		return "image/gif"
	case FormatWebP:
		return "image/webp"
	default:
		return "application/octet-stream"
	}
}

// buildCacheKey 构建缓存键
func (o *Optimizer) buildCacheKey(r *http.Request, format ImageFormat) string {
	// 使用路径和参数构建唯一键
	key := r.URL.Path
	if w := r.URL.Query().Get("width"); w != "" {
		key += "_w" + w
	}
	if h := r.URL.Query().Get("height"); h != "" {
		key += "_h" + h
	}
	if q := r.URL.Query().Get("quality"); q != "" {
		key += "_q" + q
	}
	if f := r.URL.Query().Get("format"); f != "" {
		key += "_f" + f
	} else if o.Config.AutoWebP && o.supportsWebP(r) {
		key += "_f_webp"
	}
	return key
}

// 以下缓存方法已被统一的 MemoryCache 管理器替代
// 保留空函数以保持兼容性

// getFromCache 从缓存获取 (已废弃，使用 memCache.Get)
func (o *Optimizer) getFromCache(key string) interface{} {
	return nil // 已由 OptimizeResponse 中直接使用 memCache.Get 替代
}

// putToCache 放入缓存 (已废弃，使用 memCache.Set)
func (o *Optimizer) putToCache(key string, data []byte, contentType string) {
	// 已由 OptimizeResponse 中直接使用 memCache.SetWithMetadata 替代
}

// getCurrentCacheSize 获取当前缓存大小 (已废弃，使用 memCache.GetSize)
func (o *Optimizer) getCurrentCacheSize() int64 {
	if o.memCache != nil {
		return o.memCache.GetSize()
	}
	return 0
}

// evictLRU 清理最少使用的缓存项 (已废弃，由 memCache 自动管理)
func (o *Optimizer) evictLRU(neededSize int64) {
	// 由统一缓存管理器自动管理
}

// cacheCleanupLoop 缓存清理循环 (已废弃，由 memCache 自动管理)
func (o *Optimizer) cacheCleanupLoop() {
	// 由统一缓存管理器自动管理
}

// cleanupExpiredCache 清理过期缓存 (已废弃，由 memCache 自动管理)
func (o *Optimizer) cleanupExpiredCache() {
	// 由统一缓存管理器自动管理
}

// GetStats 获取统计信息
func (o *Optimizer) GetStats() map[string]interface{} {

	cacheSize := o.getCurrentCacheSize()
	hitRate := float64(0)
	if o.totalRequests > 0 {
		hitRate = float64(o.cacheHits) / float64(o.totalRequests) * 100
	}

	compressionRate := float64(0)
	if o.totalOriginalSize > 0 {
		compressionRate = float64(o.totalBytesSaved) / float64(o.totalOriginalSize) * 100
	}

	stats := map[string]interface{}{
		"enabled":              o.Config.Enabled,
		"total_requests":       o.totalRequests,
		"cache_hits":           o.cacheHits,
		"cache_misses":         o.cacheMisses,
		"cache_hit_rate":       hitRate,
		"cache_size_bytes":     cacheSize,
		"cache_size_mb":        float64(cacheSize) / 1024 / 1024,
		"total_bytes_saved":    o.totalBytesSaved,
		"total_bytes_saved_mb": float64(o.totalBytesSaved) / 1024 / 1024,
		"compression_rate":     compressionRate,
		"original_size_mb":     float64(o.totalOriginalSize) / 1024 / 1024,
		"optimized_size_mb":    float64(o.totalOptimizedSize) / 1024 / 1024,
	}

	// 添加统一缓存管理器的统计信息
	if o.memCache != nil {
		cacheStats := o.memCache.Stats()
		stats["cache_items"] = cacheStats["entries"]
		stats["cache_manager"] = cacheStats
	} else {
		stats["cache_items"] = 0
	}

	return stats
}

// ClearCache 清空缓存
func (o *Optimizer) ClearCache() {
	if o.memCache != nil {
		o.memCache.Clear()
		o.log.Info("Image cache cleared")
	}
}

// UpdateConfig 更新配置
func (o *Optimizer) UpdateConfig(config *Config) {
	o.Config = config
	o.log.Info("Image optimizer config updated")
}
