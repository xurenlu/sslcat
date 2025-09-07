package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// LogFormat 日志格式
type LogFormat string

const (
	FormatNginx  LogFormat = "nginx"
	FormatApache LogFormat = "apache"
	FormatJSON   LogFormat = "json"
)

// AccessLog 访问日志记录
type AccessLog struct {
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	Method       string    `json:"method"`
	URL          string    `json:"url"`
	Protocol     string    `json:"protocol"`
	StatusCode   int       `json:"status_code"`
	BytesSent    int64     `json:"bytes_sent"`
	Referer      string    `json:"referer"`
	UserAgent    string    `json:"user_agent"`
	RequestTime  float64   `json:"request_time"`
	UpstreamAddr string    `json:"upstream_addr"`
	UpstreamTime float64   `json:"upstream_time"`
	Host         string    `json:"host"`
	RequestID    string    `json:"request_id"`
}

// AccessLogger 访问日志记录器
type AccessLogger struct {
	format      LogFormat
	writer      io.Writer
	file        *os.File
	mutex       sync.Mutex
	enabled     bool
	logPath     string
	maxSize     int64 // 最大文件大小 (字节)
	maxFiles    int   // 最大文件数量
	currentSize int64
	log         *logrus.Entry
}

// NewAccessLogger 创建访问日志记录器
func NewAccessLogger(format LogFormat, logPath string, enabled bool) (*AccessLogger, error) {
	logger := &AccessLogger{
		format:   format,
		enabled:  enabled,
		logPath:  logPath,
		maxSize:  100 * 1024 * 1024, // 100MB
		maxFiles: 10,
		log: logrus.WithFields(logrus.Fields{
			"component": "access_logger",
		}),
	}

	if enabled && logPath != "" {
		if err := logger.openLogFile(); err != nil {
			return nil, fmt.Errorf("打开日志文件失败: %w", err)
		}
	} else {
		logger.writer = os.Stdout
	}

	return logger, nil
}

// openLogFile 打开日志文件
func (a *AccessLogger) openLogFile() error {
	// 创建日志目录
	dir := filepath.Dir(a.logPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %w", err)
	}

	// 打开或创建日志文件
	file, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}

	// 获取文件大小
	if stat, err := file.Stat(); err == nil {
		a.currentSize = stat.Size()
	}

	a.file = file
	a.writer = file
	return nil
}

// rotateLogFile 轮转日志文件
func (a *AccessLogger) rotateLogFile() error {
	if a.file == nil {
		return nil
	}

	// 关闭当前文件
	a.file.Close()

	// 重命名当前文件
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", a.logPath, timestamp)
	if err := os.Rename(a.logPath, rotatedPath); err != nil {
		a.log.Errorf("重命名日志文件失败: %v", err)
	}

	// 清理旧文件
	go a.cleanOldFiles()

	// 重新打开新文件
	a.currentSize = 0
	return a.openLogFile()
}

// cleanOldFiles 清理旧的日志文件
func (a *AccessLogger) cleanOldFiles() {
	dir := filepath.Dir(a.logPath)
	filename := filepath.Base(a.logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var logFiles []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filename+".") {
			logFiles = append(logFiles, filepath.Join(dir, entry.Name()))
		}
	}

	// 按修改时间排序并删除多余的文件
	if len(logFiles) > a.maxFiles {
		for i := 0; i < len(logFiles)-a.maxFiles; i++ {
			os.Remove(logFiles[i])
		}
	}
}

// Log 记录访问日志
func (a *AccessLogger) Log(accessLog *AccessLog) {
	if !a.enabled {
		return
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()

	var logLine string
	switch a.format {
	case FormatNginx:
		logLine = a.formatNginx(accessLog)
	case FormatApache:
		logLine = a.formatApache(accessLog)
	case FormatJSON:
		logLine = a.formatJSON(accessLog)
	default:
		logLine = a.formatNginx(accessLog)
	}

	// 写入日志
	if _, err := fmt.Fprintln(a.writer, logLine); err != nil {
		a.log.Errorf("写入访问日志失败: %v", err)
		return
	}

	// 更新文件大小
	a.currentSize += int64(len(logLine) + 1)

	// 检查是否需要轮转
	if a.file != nil && a.currentSize > a.maxSize {
		if err := a.rotateLogFile(); err != nil {
			a.log.Errorf("轮转日志文件失败: %v", err)
		}
	}
}

// formatNginx 格式化为Nginx格式
func (a *AccessLogger) formatNginx(log *AccessLog) string {
	// Nginx 默认格式: combined
	// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
	return fmt.Sprintf(`%s - - [%s] "%s %s %s" %d %d "%s" "%s" %.3f "%s"`,
		log.ClientIP,
		log.Timestamp.Format("02/Jan/2006:15:04:05 -0700"),
		log.Method,
		log.URL,
		log.Protocol,
		log.StatusCode,
		log.BytesSent,
		log.Referer,
		log.UserAgent,
		log.RequestTime,
		log.UpstreamAddr,
	)
}

// formatApache 格式化为Apache格式
func (a *AccessLogger) formatApache(log *AccessLog) string {
	// Apache Combined Log Format
	// %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"
	return fmt.Sprintf(`%s - - [%s] "%s %s %s" %d %d "%s" "%s"`,
		log.ClientIP,
		log.Timestamp.Format("02/Jan/2006:15:04:05 -0700"),
		log.Method,
		log.URL,
		log.Protocol,
		log.StatusCode,
		log.BytesSent,
		log.Referer,
		log.UserAgent,
	)
}

// formatJSON 格式化为JSON格式
func (a *AccessLogger) formatJSON(log *AccessLog) string {
	data, err := json.Marshal(log)
	if err != nil {
		a.log.Errorf("序列化JSON日志失败: %v", err)
		return ""
	}
	return string(data)
}

// LogRequest 记录HTTP请求
func (a *AccessLogger) LogRequest(r *http.Request, statusCode int, bytesSent int64,
	requestTime time.Duration, upstreamAddr string, upstreamTime time.Duration) {

	clientIP := a.getClientIP(r)

	accessLog := &AccessLog{
		Timestamp:    time.Now(),
		ClientIP:     clientIP,
		Method:       r.Method,
		URL:          r.RequestURI,
		Protocol:     r.Proto,
		StatusCode:   statusCode,
		BytesSent:    bytesSent,
		Referer:      r.Header.Get("Referer"),
		UserAgent:    r.Header.Get("User-Agent"),
		RequestTime:  requestTime.Seconds(),
		UpstreamAddr: upstreamAddr,
		UpstreamTime: upstreamTime.Seconds(),
		Host:         r.Host,
		RequestID:    r.Header.Get("X-Request-ID"),
	}

	a.Log(accessLog)
}

// getClientIP 获取客户端IP
func (a *AccessLogger) getClientIP(r *http.Request) string {
	// 优先使用X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 使用X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 使用RemoteAddr
	if ip := r.RemoteAddr; ip != "" {
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			return ip[:idx]
		}
		return ip
	}

	return "unknown"
}

// Close 关闭日志记录器
func (a *AccessLogger) Close() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.file != nil {
		return a.file.Close()
	}
	return nil
}

// SetFormat 设置日志格式
func (a *AccessLogger) SetFormat(format LogFormat) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.format = format
	a.log.Infof("访问日志格式已设置为: %s", format)
}

// SetEnabled 设置是否启用
func (a *AccessLogger) SetEnabled(enabled bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.enabled = enabled
	a.log.Infof("访问日志记录已%s", map[bool]string{true: "启用", false: "禁用"}[enabled])
}

// GetStats 获取日志统计信息
func (a *AccessLogger) GetStats() map[string]interface{} {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	stats := map[string]interface{}{
		"enabled":      a.enabled,
		"format":       string(a.format),
		"log_path":     a.logPath,
		"current_size": a.currentSize,
		"max_size":     a.maxSize,
		"max_files":    a.maxFiles,
	}

	if a.file != nil {
		if stat, err := a.file.Stat(); err == nil {
			stats["file_modified"] = stat.ModTime()
		}
	}

	return stats
}

// SetMaxSize 设置最大文件大小（字节）
func (a *AccessLogger) SetMaxSize(size int64) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if size > 0 {
		a.maxSize = size
	}
}

// SetMaxFiles 设置最大保留文件数
func (a *AccessLogger) SetMaxFiles(n int) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if n > 0 {
		a.maxFiles = n
	}
}
