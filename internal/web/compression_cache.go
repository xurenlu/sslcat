package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/cache"
)

// CompressionAlgorithm 压缩算法
type CompressionAlgorithm string

const (
	AlgorithmNone   CompressionAlgorithm = "none"
	AlgorithmGzip   CompressionAlgorithm = "gzip"
	AlgorithmBrotli CompressionAlgorithm = "br"
)

// CompressionCache 压缩缓存（使用统一的内存缓存管理器）
type CompressionCache struct {
	memCache *cache.MemoryCache
	log      *logrus.Entry
}

// NewCompressionCache 创建压缩缓存（独立实例）
func NewCompressionCache(maxEntries int, maxSizeMB int64, maxTotalMB int64) *CompressionCache {
	return &CompressionCache{
		memCache: cache.NewMemoryCache(&cache.MemoryCacheConfig{
			Name:            "compression",
			MaxEntries:      maxEntries,
			MaxSizeBytes:    maxTotalMB * 1024 * 1024,
			MaxItemSize:     maxSizeMB * 1024 * 1024,
			DefaultTTL:      24 * time.Hour,
			CleanupInterval: 5 * time.Minute,
		}),
		log: logrus.WithFields(logrus.Fields{
			"component": "compression_cache",
		}),
	}
}

// NewCompressionCacheWithCache 使用共享缓存实例创建压缩缓存
func NewCompressionCacheWithCache(sharedCache *cache.MemoryCache) *CompressionCache {
	return &CompressionCache{
		memCache: sharedCache,
		log: logrus.WithFields(logrus.Fields{
			"component": "compression_cache",
		}),
	}
}

// Get 从缓存获取压缩数据
func (c *CompressionCache) Get(filepath string, algorithm CompressionAlgorithm) ([]byte, string, bool) {
	key := c.makeKey(filepath, algorithm)

	item, ok := c.memCache.Get(key)
	if !ok {
		return nil, "", false
	}

	// 从元数据中恢复 ETag
	etag := ""
	if item.Metadata != nil {
		if etagVal, ok := item.Metadata["etag"].(string); ok {
			etag = etagVal
		}
	}

	return item.Data, etag, true
}

// Set 设置缓存
func (c *CompressionCache) Set(filepath string, algorithm CompressionAlgorithm, data []byte, originalSize int64, etag string) {
	key := c.makeKey(filepath, algorithm)

	// 准备元数据
	metadata := map[string]interface{}{
		"algorithm":     string(algorithm),
		"filepath":      filepath,
		"original_size": originalSize,
		"etag":          etag,
	}

	// 使用统一缓存管理器
	err := c.memCache.SetWithMetadata(key, data, metadata, 24*time.Hour)
	if err != nil {
		c.log.Debugf("Failed to cache compressed data: %s, error: %v", filepath, err)
		return
	}

	dataSize := int64(len(data))
	c.log.Debugf("Cached compressed data: %s [%s] (%d -> %d bytes, %.1f%% reduction)",
		filepath, algorithm, originalSize, dataSize,
		float64(originalSize-dataSize)/float64(originalSize)*100)
}

// Clear 清空缓存
func (c *CompressionCache) Clear() {
	c.memCache.Clear()
	c.log.Info("Compression cache cleared")
}

// Stats 获取缓存统计
func (c *CompressionCache) Stats() map[string]interface{} {
	return c.memCache.Stats()
}

// Close 关闭缓存
func (c *CompressionCache) Close() {
	c.memCache.Close()
}

// SetMemoryCache 替换底层缓存实例
func (c *CompressionCache) SetMemoryCache(newCache *cache.MemoryCache) {
	if newCache == nil {
		return
	}
	c.memCache = newCache
}

// makeKey 生成缓存键（添加前缀以区分不同缓存类型）
func (c *CompressionCache) makeKey(filepath string, algorithm CompressionAlgorithm) string {
	return fmt.Sprintf("compression:%s:%s", filepath, algorithm)
}

// CompressData 压缩数据（工具函数）
func CompressData(data []byte, algorithm CompressionAlgorithm, level int) ([]byte, error) {
	var buf bytes.Buffer

	switch algorithm {
	case AlgorithmGzip:
		writer, err := gzip.NewWriterLevel(&buf, level)
		if err != nil {
			return nil, err
		}
		if _, err := writer.Write(data); err != nil {
			writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}

	case AlgorithmBrotli:
		writer := brotli.NewWriterLevel(&buf, level)
		if _, err := writer.Write(data); err != nil {
			writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}

	default:
		return data, nil
	}

	return buf.Bytes(), nil
}

// GenerateETag 生成 ETag
func GenerateETag(data []byte) string {
	hash := sha256.Sum256(data)
	return "\"" + hex.EncodeToString(hash[:16]) + "\""
}

// GenerateETagFromFile 从文件生成 ETag
func GenerateETagFromFile(fileInfo os.FileInfo) string {
	// 使用文件大小和修改时间生成弱 ETag
	return fmt.Sprintf(`W/"%d-%d"`, fileInfo.Size(), fileInfo.ModTime().Unix())
}
