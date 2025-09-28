package compression

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/sirupsen/logrus"
)

// Algorithm 压缩算法类型
type Algorithm string

const (
	// None 不压缩
	None Algorithm = "none"
	// Gzip gzip压缩
	Gzip Algorithm = "gzip"
	// Brotli brotli压缩
	Brotli Algorithm = "br"
	// Deflate deflate压缩
	Deflate Algorithm = "deflate"
)

// Config 压缩配置
type Config struct {
	// Enabled 是否启用压缩
	Enabled bool `json:"enabled"`

	// Algorithms 支持的压缩算法，按优先级排序
	Algorithms []Algorithm `json:"algorithms"`

	// MinSize 最小压缩文件大小（字节）
	MinSize int64 `json:"min_size"`

	// Level 压缩级别配置
	Level CompressionLevel `json:"level"`

	// Types 可压缩的文件类型
	Types map[string]bool `json:"types"`

	// ExcludedTypes 不压缩的文件类型
	ExcludedTypes map[string]bool `json:"excluded_types"`
}

// CompressionLevel 压缩级别配置
type CompressionLevel struct {
	// Gzip gzip压缩级别 (1-9, -1=默认, -2=最快, -3=最佳)
	Gzip int `json:"gzip"`

	// Brotli brotli压缩级别 (0-11)
	Brotli int `json:"brotli"`
}

// Result 压缩结果
type Result struct {
	// Algorithm 使用的压缩算法
	Algorithm Algorithm

	// Data 压缩后的数据
	Data []byte

	// OriginalSize 原始大小
	OriginalSize int

	// CompressedSize 压缩后大小
	CompressedSize int

	// Ratio 压缩比例 (0-1)
	Ratio float64
}

// Compressor 压缩器
type Compressor struct {
	config Config
	log    *logrus.Entry
}

// NewCompressor 创建压缩器
func NewCompressor(config Config) *Compressor {
	// 设置默认值
	if len(config.Algorithms) == 0 {
		config.Algorithms = []Algorithm{Brotli, Gzip}
	}

	if config.MinSize == 0 {
		config.MinSize = 1024 // 默认1KB
	}

	if config.Level.Gzip == 0 {
		config.Level.Gzip = gzip.DefaultCompression
	}

	if config.Level.Brotli == 0 {
		config.Level.Brotli = 6 // brotli默认级别
	}

	if config.Types == nil {
		config.Types = getDefaultCompressibleTypes()
	}

	if config.ExcludedTypes == nil {
		config.ExcludedTypes = getDefaultExcludedTypes()
	}

	return &Compressor{
		config: config,
		log: logrus.WithFields(logrus.Fields{
			"component": "compressor",
		}),
	}
}

// Compress 压缩数据
func (c *Compressor) Compress(data []byte, acceptEncoding string) (*Result, error) {
	if !c.config.Enabled {
		return &Result{
			Algorithm:      None,
			Data:           data,
			OriginalSize:   len(data),
			CompressedSize: len(data),
			Ratio:          0,
		}, nil
	}

	// 检查数据大小
	if int64(len(data)) < c.config.MinSize {
		return &Result{
			Algorithm:      None,
			Data:           data,
			OriginalSize:   len(data),
			CompressedSize: len(data),
			Ratio:          0,
		}, nil
	}

	// 根据客户端支持的编码选择压缩算法
	algorithm := c.selectAlgorithm(acceptEncoding)
	if algorithm == None {
		return &Result{
			Algorithm:      None,
			Data:           data,
			OriginalSize:   len(data),
			CompressedSize: len(data),
			Ratio:          0,
		}, nil
	}

	// 执行压缩
	compressedData, err := c.compressWithAlgorithm(data, algorithm)
	if err != nil {
		c.log.Warnf("Compression failed with %s: %v", algorithm, err)
		return &Result{
			Algorithm:      None,
			Data:           data,
			OriginalSize:   len(data),
			CompressedSize: len(data),
			Ratio:          0,
		}, nil
	}

	// 检查压缩效果
	originalSize := len(data)
	compressedSize := len(compressedData)

	// 如果压缩后文件更大，不使用压缩
	if compressedSize >= originalSize {
		return &Result{
			Algorithm:      None,
			Data:           data,
			OriginalSize:   originalSize,
			CompressedSize: originalSize,
			Ratio:          0,
		}, nil
	}

	ratio := float64(originalSize-compressedSize) / float64(originalSize)

	return &Result{
		Algorithm:      algorithm,
		Data:           compressedData,
		OriginalSize:   originalSize,
		CompressedSize: compressedSize,
		Ratio:          ratio,
	}, nil
}

// CompressResponse 压缩HTTP响应
func (c *Compressor) CompressResponse(w http.ResponseWriter, r *http.Request, data []byte, contentType string) {
	// 检查是否应该压缩
	if !c.ShouldCompress(r.URL.Path, int64(len(data)), contentType) {
		w.Write(data)
		return
	}

	// 压缩数据
	result, err := c.Compress(data, r.Header.Get("Accept-Encoding"))
	if err != nil {
		c.log.Errorf("Failed to compress response: %v", err)
		w.Write(data)
		return
	}

	// 设置响应头
	if result.Algorithm != None {
		w.Header().Set("Content-Encoding", string(result.Algorithm))
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Set("Content-Length", strconv.Itoa(result.CompressedSize))

		// 添加压缩统计信息（调试用）
		w.Header().Set("X-Compression-Algorithm", string(result.Algorithm))
		w.Header().Set("X-Compression-Ratio", fmt.Sprintf("%.2f", result.Ratio))
		w.Header().Set("X-Original-Size", strconv.Itoa(result.OriginalSize))

		c.log.Debugf("Compressed %s: %d -> %d bytes (%.1f%% reduction)",
			result.Algorithm, result.OriginalSize, result.CompressedSize, result.Ratio*100)
	}

	w.Write(result.Data)
}

// ShouldCompress 判断是否应该压缩
func (c *Compressor) ShouldCompress(filePath string, fileSize int64, contentType string) bool {
	if !c.config.Enabled {
		return false
	}

	// 检查文件大小
	if fileSize < c.config.MinSize {
		return false
	}

	// 根据文件扩展名检查
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != "" {
		// 检查是否在排除列表中
		if c.config.ExcludedTypes[ext] {
			return false
		}

		// 检查是否在可压缩列表中
		if c.config.Types[ext] {
			return true
		}
	}

	// 根据Content-Type检查
	if contentType != "" {
		return c.isCompressibleContentType(contentType)
	}

	return false
}

// selectAlgorithm 根据Accept-Encoding选择压缩算法
func (c *Compressor) selectAlgorithm(acceptEncoding string) Algorithm {
	acceptEncoding = strings.ToLower(acceptEncoding)

	// 按优先级检查支持的算法
	for _, algorithm := range c.config.Algorithms {
		switch algorithm {
		case Brotli:
			if strings.Contains(acceptEncoding, "br") {
				return Brotli
			}
		case Gzip:
			if strings.Contains(acceptEncoding, "gzip") {
				return Gzip
			}
		case Deflate:
			if strings.Contains(acceptEncoding, "deflate") {
				return Deflate
			}
		}
	}

	return None
}

// compressWithAlgorithm 使用指定算法压缩数据
func (c *Compressor) compressWithAlgorithm(data []byte, algorithm Algorithm) ([]byte, error) {
	var buf bytes.Buffer

	switch algorithm {
	case Gzip:
		writer, err := gzip.NewWriterLevel(&buf, c.config.Level.Gzip)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip writer: %w", err)
		}
		defer writer.Close()

		if _, err := writer.Write(data); err != nil {
			return nil, fmt.Errorf("failed to write gzip data: %w", err)
		}

		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("failed to close gzip writer: %w", err)
		}

	case Brotli:
		writer := brotli.NewWriterLevel(&buf, c.config.Level.Brotli)
		defer writer.Close()

		if _, err := writer.Write(data); err != nil {
			return nil, fmt.Errorf("failed to write brotli data: %w", err)
		}

		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("failed to close brotli writer: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}

	return buf.Bytes(), nil
}

// isCompressibleContentType 检查Content-Type是否可压缩
func (c *Compressor) isCompressibleContentType(contentType string) bool {
	contentType = strings.ToLower(strings.Split(contentType, ";")[0])

	compressibleTypes := []string{
		"text/",
		"application/json",
		"application/javascript",
		"application/xml",
		"application/rss+xml",
		"application/atom+xml",
		"image/svg+xml",
	}

	for _, prefix := range compressibleTypes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}

	return false
}

// getDefaultCompressibleTypes 获取默认可压缩文件类型
func getDefaultCompressibleTypes() map[string]bool {
	return map[string]bool{
		".js":   true,
		".css":  true,
		".html": true,
		".htm":  true,
		".xml":  true,
		".json": true,
		".txt":  true,
		".svg":  true,
		".md":   true,
		".yaml": true,
		".yml":  true,
		".csv":  true,
		".tsv":  true,
		".rss":  true,
		".atom": true,
	}
}

// getDefaultExcludedTypes 获取默认不压缩文件类型
func getDefaultExcludedTypes() map[string]bool {
	return map[string]bool{
		// 已压缩格式
		".gz":  true,
		".br":  true,
		".zip": true,
		".rar": true,
		".7z":  true,
		".bz2": true,
		".xz":  true,

		// 图片格式
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".webp": true,
		".ico":  true,
		".bmp":  true,
		".tiff": true,

		// 字体格式
		".woff":  true,
		".woff2": true,
		".ttf":   true,
		".eot":   true,
		".otf":   true,

		// 音视频格式
		".mp3": true,
		".mp4": true,
		".avi": true,
		".mov": true,
		".wmv": true,
		".flv": true,
		".wav": true,
		".ogg": true,

		// 文档格式
		".pdf":  true,
		".doc":  true,
		".docx": true,
		".ppt":  true,
		".pptx": true,
		".xls":  true,
		".xlsx": true,
	}
}

// GetStats 获取压缩统计信息
func (c *Compressor) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":            c.config.Enabled,
		"algorithms":         c.config.Algorithms,
		"min_size":           c.config.MinSize,
		"gzip_level":         c.config.Level.Gzip,
		"brotli_level":       c.config.Level.Brotli,
		"compressible_types": len(c.config.Types),
		"excluded_types":     len(c.config.ExcludedTypes),
	}
}
