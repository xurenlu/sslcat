package imageopt

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
)

// ResponseWriter 包装的 ResponseWriter，用于拦截和优化图片响应
type ResponseWriter struct {
	http.ResponseWriter
	optimizer      *Optimizer
	request        *http.Request
	buffer         *bytes.Buffer
	statusCode     int
	contentType    string
	written        bool
	shouldOptimize bool
}

// NewResponseWriter 创建优化的 ResponseWriter
func NewResponseWriter(w http.ResponseWriter, r *http.Request, optimizer *Optimizer) *ResponseWriter {
	return &ResponseWriter{
		ResponseWriter: w,
		optimizer:      optimizer,
		request:        r,
		buffer:         &bytes.Buffer{},
		statusCode:     200,
		shouldOptimize: optimizer.ShouldOptimize(r.URL.Path),
	}
}

// Header 实现 http.ResponseWriter
func (rw *ResponseWriter) Header() http.Header {
	return rw.ResponseWriter.Header()
}

// WriteHeader 实现 http.ResponseWriter
func (rw *ResponseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.contentType = rw.ResponseWriter.Header().Get("Content-Type")

	// 检查是否应该优化
	if !rw.shouldOptimize || !isImageContentType(rw.contentType) {
		rw.shouldOptimize = false
		rw.ResponseWriter.WriteHeader(statusCode)
		rw.written = true
	}
	// 如果需要优化，暂不写入header，等数据收集完再写
}

// Write 实现 http.ResponseWriter
func (rw *ResponseWriter) Write(data []byte) (int, error) {
	// 如果不需要优化，直接写入
	if !rw.shouldOptimize {
		if !rw.written {
			rw.ResponseWriter.WriteHeader(rw.statusCode)
			rw.written = true
		}
		return rw.ResponseWriter.Write(data)
	}

	// 缓冲数据，等待优化
	return rw.buffer.Write(data)
}

// Flush 完成响应，应用优化
func (rw *ResponseWriter) Flush() error {
	// 如果不需要优化或已经直接写入，直接返回
	if !rw.shouldOptimize || rw.written {
		return nil
	}

	originalData := rw.buffer.Bytes()

	// 如果没有数据，直接返回
	if len(originalData) == 0 {
		rw.ResponseWriter.WriteHeader(rw.statusCode)
		return nil
	}

	// 执行优化
	optimizedData, newContentType, err := rw.optimizer.OptimizeResponse(
		originalData,
		rw.contentType,
		rw.request,
	)

	// 如果优化失败，使用原始数据
	if err != nil {
		optimizedData = originalData
		newContentType = rw.contentType
	}

	// 更新响应头
	if newContentType != rw.contentType {
		rw.ResponseWriter.Header().Set("Content-Type", newContentType)
	}
	rw.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(optimizedData)))

	// 添加优化标识
	if len(optimizedData) < len(originalData) {
		rw.ResponseWriter.Header().Set("X-Image-Optimized", "true")
		compressionRatio := float64(len(originalData)-len(optimizedData)) / float64(len(originalData)) * 100
		rw.ResponseWriter.Header().Set("X-Image-Compression-Ratio", strconv.FormatFloat(compressionRatio, 'f', 2, 64))
	}

	// 写入响应
	rw.ResponseWriter.WriteHeader(rw.statusCode)
	_, writeErr := rw.ResponseWriter.Write(optimizedData)
	rw.written = true

	return writeErr
}

// isImageContentType 判断是否是图片类型
func isImageContentType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.HasPrefix(contentType, "image/jpeg") ||
		strings.HasPrefix(contentType, "image/jpg") ||
		strings.HasPrefix(contentType, "image/png") ||
		strings.HasPrefix(contentType, "image/gif") ||
		strings.HasPrefix(contentType, "image/webp")
}

// Close 关闭（如果需要的话）
func (rw *ResponseWriter) Close() error {
	return rw.Flush()
}
