package compression

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
)

// Middleware 压缩中间件
type Middleware struct {
	compressor *Compressor
}

// NewMiddleware 创建压缩中间件
func NewMiddleware(config Config) *Middleware {
	return &Middleware{
		compressor: NewCompressor(config),
	}
}

// Handler 返回HTTP中间件处理函数
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否应该压缩
		if !m.shouldCompressRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		// 创建压缩响应写入器
		cw := &compressResponseWriter{
			ResponseWriter: w,
			compressor:     m.compressor,
			request:        r,
			buffer:         &bytes.Buffer{},
		}

		// 调用下一个处理器
		next.ServeHTTP(cw, r)

		// 完成压缩响应
		cw.finalize()
	})
}

// shouldCompressRequest 检查请求是否应该被压缩
func (m *Middleware) shouldCompressRequest(r *http.Request) bool {
	// 检查Accept-Encoding头
	acceptEncoding := r.Header.Get("Accept-Encoding")
	if acceptEncoding == "" {
		return false
	}

	// 检查是否支持压缩算法
	algorithm := m.compressor.SelectAlgorithm(acceptEncoding)
	return algorithm != None
}

// compressResponseWriter 压缩响应写入器
type compressResponseWriter struct {
	http.ResponseWriter
	compressor    *Compressor
	request       *http.Request
	buffer        *bytes.Buffer
	headerWritten bool
	statusCode    int
	contentType   string
}

// Header 返回响应头
func (w *compressResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

// WriteHeader 写入状态码
func (w *compressResponseWriter) WriteHeader(statusCode int) {
	if w.headerWritten {
		return
	}

	w.statusCode = statusCode
	w.contentType = w.Header().Get("Content-Type")
	w.headerWritten = true

	// 如果状态码不是2xx，直接写入不压缩
	if statusCode < 200 || statusCode >= 300 {
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

// Write 写入响应数据
func (w *compressResponseWriter) Write(data []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	// 如果状态码不是2xx，直接写入
	if w.statusCode < 200 || w.statusCode >= 300 {
		return w.ResponseWriter.Write(data)
	}

	// 将数据写入缓冲区
	return w.buffer.Write(data)
}

// Flush 刷新缓冲区（实现http.Flusher接口）
func (w *compressResponseWriter) Flush() {
	w.finalize()

	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack 劫持连接（实现http.Hijacker接口）
func (w *compressResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
}

// finalize 完成压缩响应
func (w *compressResponseWriter) finalize() {
	if w.buffer.Len() == 0 {
		// 没有数据，直接返回
		if w.headerWritten && (w.statusCode < 200 || w.statusCode >= 300) {
			return
		}
		w.ResponseWriter.WriteHeader(w.statusCode)
		return
	}

	data := w.buffer.Bytes()

	// 检查是否应该压缩
	if !w.compressor.ShouldCompress(w.request.URL.Path, int64(len(data)), w.contentType) {
		// 不压缩，直接写入
		w.ResponseWriter.WriteHeader(w.statusCode)
		w.ResponseWriter.Write(data)
		return
	}

	// 压缩数据
	result, err := w.compressor.Compress(data, w.request.Header.Get("Accept-Encoding"))
	if err != nil {
		// 压缩失败，直接写入原数据
		w.ResponseWriter.WriteHeader(w.statusCode)
		w.ResponseWriter.Write(data)
		return
	}

	// 设置压缩相关头部
	if result.Algorithm != None {
		w.Header().Set("Content-Encoding", string(result.Algorithm))
		w.Header().Set("Vary", "Accept-Encoding")

		// 移除Content-Length，因为内容已被压缩
		w.Header().Del("Content-Length")

		// 添加压缩统计信息（可选，用于调试）
		if w.compressor.log.Logger.IsLevelEnabled(logrus.DebugLevel) {
			w.Header().Set("X-Compression-Algorithm", string(result.Algorithm))
			w.Header().Set("X-Compression-Ratio", fmt.Sprintf("%.2f", result.Ratio))
			w.Header().Set("X-Original-Size", fmt.Sprintf("%d", result.OriginalSize))
			w.Header().Set("X-Compressed-Size", fmt.Sprintf("%d", result.CompressedSize))
		}
	}

	// 写入状态码和压缩后的数据
	w.ResponseWriter.WriteHeader(w.statusCode)
	w.ResponseWriter.Write(result.Data)
}

// HandlerFunc 返回处理函数形式的中间件
func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Handler(next).ServeHTTP(w, r)
	}
}

// CompressHandler 压缩处理器包装函数
func CompressHandler(handler http.Handler, config Config) http.Handler {
	middleware := NewMiddleware(config)
	return middleware.Handler(handler)
}

// CompressHandlerFunc 压缩处理函数包装函数
func CompressHandlerFunc(handlerFunc http.HandlerFunc, config Config) http.HandlerFunc {
	middleware := NewMiddleware(config)
	return middleware.HandlerFunc(handlerFunc)
}
