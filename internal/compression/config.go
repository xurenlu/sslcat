package compression

import (
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// FromConfig 从应用配置创建压缩配置
func FromConfig(cfg *config.Config) Config {
	if cfg == nil {
		return getDefaultConfig()
	}

	compressionCfg := cfg.Compression

	// 转换算法列表
	var algorithms []Algorithm
	for _, alg := range compressionCfg.Algorithms {
		switch strings.ToLower(alg) {
		case "br", "brotli":
			algorithms = append(algorithms, Brotli)
		case "gzip":
			algorithms = append(algorithms, Gzip)
		case "deflate":
			algorithms = append(algorithms, Deflate)
		}
	}

	// 如果没有配置算法，使用默认值
	if len(algorithms) == 0 {
		algorithms = []Algorithm{Brotli, Gzip}
	}

	// 转换文件类型
	types := make(map[string]bool)
	for _, typ := range compressionCfg.Types {
		types[typ] = true
	}
	if len(types) == 0 {
		types = getDefaultCompressibleTypes()
	}

	// 转换排除类型
	excludedTypes := make(map[string]bool)
	for _, typ := range compressionCfg.ExcludedTypes {
		excludedTypes[typ] = true
	}
	if len(excludedTypes) == 0 {
		excludedTypes = getDefaultExcludedTypes()
	}

	// 设置默认值
	minSize := compressionCfg.MinSize
	if minSize == 0 {
		minSize = 1024 // 默认1KB
	}

	gzipLevel := compressionCfg.Level.Gzip
	if gzipLevel == 0 {
		gzipLevel = -1 // gzip默认压缩级别
	}

	brotliLevel := compressionCfg.Level.Brotli
	if brotliLevel == 0 {
		brotliLevel = 6 // brotli默认压缩级别
	}

	return Config{
		Enabled:    compressionCfg.Enabled,
		Algorithms: algorithms,
		MinSize:    minSize,
		Level: CompressionLevel{
			Gzip:   gzipLevel,
			Brotli: brotliLevel,
		},
		Types:         types,
		ExcludedTypes: excludedTypes,
	}
}

// getDefaultConfig 获取默认压缩配置
func getDefaultConfig() Config {
	return Config{
		Enabled:    true,
		Algorithms: []Algorithm{Brotli, Gzip},
		MinSize:    1024,
		Level: CompressionLevel{
			Gzip:   -1, // 默认压缩级别
			Brotli: 6,  // 默认压缩级别
		},
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}
}

// ToConfigStruct 将压缩配置转换为配置结构
func ToConfigStruct(cfg Config) config.CompressionConfig {
	// 转换算法列表
	var algorithms []string
	for _, alg := range cfg.Algorithms {
		algorithms = append(algorithms, string(alg))
	}

	// 转换文件类型
	var types []string
	for typ := range cfg.Types {
		types = append(types, typ)
	}

	// 转换排除类型
	var excludedTypes []string
	for typ := range cfg.ExcludedTypes {
		excludedTypes = append(excludedTypes, typ)
	}

	return config.CompressionConfig{
		Enabled:    cfg.Enabled,
		Algorithms: algorithms,
		MinSize:    cfg.MinSize,
		Level: config.CompressionLevelConfig{
			Gzip:   cfg.Level.Gzip,
			Brotli: cfg.Level.Brotli,
		},
		Types:         types,
		ExcludedTypes: excludedTypes,
	}
}

// GetDefaultCompressionConfig 获取默认的配置结构压缩配置
func GetDefaultCompressionConfig() config.CompressionConfig {
	return ToConfigStruct(getDefaultConfig())
}
