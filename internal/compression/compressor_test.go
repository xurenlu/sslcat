package compression

import (
	"strings"
	"testing"
)

func TestCompressor_Gzip(t *testing.T) {
	config := Config{
		Enabled:    true,
		Algorithms: []Algorithm{Gzip},
		MinSize:    100,
		Level: CompressionLevel{
			Gzip: -1, // 默认压缩级别
		},
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}

	compressor := NewCompressor(config)

	// 测试数据
	testData := strings.Repeat("Hello, World! This is a test string for compression. ", 100)
	data := []byte(testData)

	// 压缩数据
	result, err := compressor.Compress(data, "gzip")
	if err != nil {
		t.Fatalf("Failed to compress data: %v", err)
	}

	// 验证压缩结果
	if result.Algorithm != Gzip {
		t.Errorf("Expected algorithm %s, got %s", Gzip, result.Algorithm)
	}

	if result.OriginalSize != len(data) {
		t.Errorf("Expected original size %d, got %d", len(data), result.OriginalSize)
	}

	if result.CompressedSize >= result.OriginalSize {
		t.Errorf("Compression should reduce size: %d -> %d", result.OriginalSize, result.CompressedSize)
	}

	if result.Ratio <= 0 {
		t.Errorf("Compression ratio should be positive: %f", result.Ratio)
	}

	t.Logf("Gzip compression: %d -> %d bytes (%.1f%% reduction)",
		result.OriginalSize, result.CompressedSize, result.Ratio*100)
}

func TestCompressor_Brotli(t *testing.T) {
	config := Config{
		Enabled:    true,
		Algorithms: []Algorithm{Brotli},
		MinSize:    100,
		Level: CompressionLevel{
			Brotli: 6, // 默认压缩级别
		},
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}

	compressor := NewCompressor(config)

	// 测试数据
	testData := strings.Repeat("Hello, World! This is a test string for compression. ", 100)
	data := []byte(testData)

	// 压缩数据
	result, err := compressor.Compress(data, "br")
	if err != nil {
		t.Fatalf("Failed to compress data: %v", err)
	}

	// 验证压缩结果
	if result.Algorithm != Brotli {
		t.Errorf("Expected algorithm %s, got %s", Brotli, result.Algorithm)
	}

	if result.OriginalSize != len(data) {
		t.Errorf("Expected original size %d, got %d", len(data), result.OriginalSize)
	}

	if result.CompressedSize >= result.OriginalSize {
		t.Errorf("Compression should reduce size: %d -> %d", result.OriginalSize, result.CompressedSize)
	}

	if result.Ratio <= 0 {
		t.Errorf("Compression ratio should be positive: %f", result.Ratio)
	}

	t.Logf("Brotli compression: %d -> %d bytes (%.1f%% reduction)",
		result.OriginalSize, result.CompressedSize, result.Ratio*100)
}

func TestCompressor_AlgorithmSelection(t *testing.T) {
	config := Config{
		Enabled:    true,
		Algorithms: []Algorithm{Brotli, Gzip}, // Brotli优先
		MinSize:    100,
		Level: CompressionLevel{
			Gzip:   -1,
			Brotli: 6,
		},
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}

	compressor := NewCompressor(config)
	testData := strings.Repeat("Hello, World! ", 100)
	data := []byte(testData)

	// 测试客户端支持Brotli和Gzip时，应该选择Brotli
	result1, err := compressor.Compress(data, "br, gzip")
	if err != nil {
		t.Fatalf("Failed to compress data: %v", err)
	}
	if result1.Algorithm != Brotli {
		t.Errorf("Expected Brotli when both supported, got %s", result1.Algorithm)
	}

	// 测试客户端只支持Gzip时，应该选择Gzip
	result2, err := compressor.Compress(data, "gzip")
	if err != nil {
		t.Fatalf("Failed to compress data: %v", err)
	}
	if result2.Algorithm != Gzip {
		t.Errorf("Expected Gzip when only gzip supported, got %s", result2.Algorithm)
	}

	// 测试客户端不支持压缩时，应该不压缩
	result3, err := compressor.Compress(data, "identity")
	if err != nil {
		t.Fatalf("Failed to handle no compression: %v", err)
	}
	if result3.Algorithm != None {
		t.Errorf("Expected no compression when not supported, got %s", result3.Algorithm)
	}
}

func TestCompressor_ShouldCompress(t *testing.T) {
	config := Config{
		Enabled:       true,
		MinSize:       1024,
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}

	compressor := NewCompressor(config)

	// 测试可压缩文件
	if !compressor.ShouldCompress("test.js", 2048, "application/javascript") {
		t.Error("Should compress JavaScript files")
	}

	if !compressor.ShouldCompress("test.css", 2048, "text/css") {
		t.Error("Should compress CSS files")
	}

	if !compressor.ShouldCompress("test.html", 2048, "text/html") {
		t.Error("Should compress HTML files")
	}

	// 测试不可压缩文件
	if compressor.ShouldCompress("test.jpg", 2048, "image/jpeg") {
		t.Error("Should not compress JPEG files")
	}

	if compressor.ShouldCompress("test.png", 2048, "image/png") {
		t.Error("Should not compress PNG files")
	}

	if compressor.ShouldCompress("test.gz", 2048, "application/gzip") {
		t.Error("Should not compress already compressed files")
	}

	// 测试文件大小限制
	if compressor.ShouldCompress("test.js", 512, "application/javascript") {
		t.Error("Should not compress files smaller than MinSize")
	}

	// 测试禁用压缩
	config.Enabled = false
	compressor2 := NewCompressor(config)
	if compressor2.ShouldCompress("test.js", 2048, "application/javascript") {
		t.Error("Should not compress when disabled")
	}
}

func TestCompressor_ContentTypeDetection(t *testing.T) {
	config := Config{
		Enabled:       true,
		MinSize:       100,
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}

	compressor := NewCompressor(config)

	testCases := []struct {
		contentType string
		expected    bool
	}{
		{"text/html", true},
		{"text/css", true},
		{"application/javascript", true},
		{"application/json", true},
		{"text/plain", true},
		{"image/svg+xml", true},
		{"image/jpeg", false},
		{"image/png", false},
		{"video/mp4", false},
		{"application/octet-stream", false},
	}

	for _, tc := range testCases {
		result := compressor.ShouldCompress("", 2048, tc.contentType)
		if result != tc.expected {
			t.Errorf("Content-Type %s: expected %v, got %v", tc.contentType, tc.expected, result)
		}
	}
}

// 基准测试
func BenchmarkCompressor_Gzip(b *testing.B) {
	config := Config{
		Enabled:    true,
		Algorithms: []Algorithm{Gzip},
		MinSize:    100,
		Level: CompressionLevel{
			Gzip: -1,
		},
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}

	compressor := NewCompressor(config)
	testData := strings.Repeat("Hello, World! This is a test string for compression. ", 100)
	data := []byte(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := compressor.Compress(data, "gzip")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompressor_Brotli(b *testing.B) {
	config := Config{
		Enabled:    true,
		Algorithms: []Algorithm{Brotli},
		MinSize:    100,
		Level: CompressionLevel{
			Brotli: 6,
		},
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}

	compressor := NewCompressor(config)
	testData := strings.Repeat("Hello, World! This is a test string for compression. ", 100)
	data := []byte(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := compressor.Compress(data, "br")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompressor_Both(b *testing.B) {
	config := Config{
		Enabled:    true,
		Algorithms: []Algorithm{Brotli, Gzip},
		MinSize:    100,
		Level: CompressionLevel{
			Gzip:   -1,
			Brotli: 6,
		},
		Types:         getDefaultCompressibleTypes(),
		ExcludedTypes: getDefaultExcludedTypes(),
	}

	compressor := NewCompressor(config)
	testData := strings.Repeat("Hello, World! This is a test string for compression. ", 100)
	data := []byte(testData)

	b.Run("Brotli", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := compressor.Compress(data, "br, gzip")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Gzip", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := compressor.Compress(data, "gzip")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
