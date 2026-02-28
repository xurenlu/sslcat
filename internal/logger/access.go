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
	format       LogFormat
	writer       io.Writer
	file         *os.File
	mutex        sync.Mutex
	enabled      bool
	logPath      string          // 原始日志路径模板（可能包含占位符）
	logPathRaw   string          // 原始日志路径（未解析占位符）
	currentDate  string          // 当前日志文件对应的日期
	maxSize      int64           // 最大文件大小 (字节)
	maxFiles     int             // 最大文件数量
	currentSize  int64
	log          *logrus.Entry
	hasDatePattern bool          // 路径中是否包含日期占位符
}

// NewAccessLogger 创建访问日志记录器
func NewAccessLogger(format LogFormat, logPath string, enabled bool) (*AccessLogger, error) {
	now := time.Now()

	logger := &AccessLogger{
		format:   format,
		enabled:  enabled,
		logPathRaw: logPath,
		maxSize:  100 * 1024 * 1024, // 100MB
		maxFiles: 10,
		log: logrus.WithFields(logrus.Fields{
			"component": "access_logger",
		}),
	}

	// 检查并解析日期占位符
	if logPath != "" {
		logger.hasDatePattern = containsDatePattern(logPath)
		logger.logPath = logger.expandDatePattern(now)
		logger.currentDate = getCurrentDateKey(now)
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

	// 检查日期变化（如果有日期占位符）
	if err := a.checkDateRotation(); err != nil {
		a.log.Errorf("日期轮转检查失败: %v", err)
	}

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

	// 检查是否需要按大小轮转（不包含日期占位符的路径才需要大小轮转）
	if !a.hasDatePattern && a.file != nil && a.currentSize > a.maxSize {
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

// 日期占位符常量
const (
	// strftime 风格占位符（兼容 nginx 语法）
	datePatternYear     = "%Y"  // 4位年份：2025
	datePatternMonth    = "%m"  // 2位月份：02
	datePatternDay      = "%d"  // 2位日期：28
	datePatternHour     = "%H"  // 2位小时：15
	datePatternMinute   = "%M"  // 2位分钟：04
	datePatternSecond   = "%S"  // 2位秒数：05
	datePatternTime     = "%s"  // Unix时间戳

	// Go 风格占位符（简化版）
	goDatePatternYear     = "{yyyy}"  // 4位年份：2025
	goDatePatternYear2    = "{yy}"    // 2位年份：25
	goDatePatternMonth    = "{mm}"    // 2位月份：02
	goDatePatternMonthN   = "{m}"     // 月份（无前导零）：2
	goDatePatternDay      = "{dd}"    // 2位日期：28
	goDatePatternDayN     = "{d}"     // 日期（无前导零）：8
	goDatePatternHour     = "{HH}"    // 2位小时：15
	goDatePatternHourN    = "{H}"     // 小时（无前导零）：5
	goDatePatternMinute   = "{MM}"    // 2位分钟：04
	goDatePatternMinuteN  = "{M}"     // 分钟（无前导零）：4
	goDatePatternSecond   = "{SS}"    // 2位秒数：05
	goDatePatternSecondN  = "{S}"     // 秒数（无前导零）：5
	goDatePatternDate     = "{date}"  // 完整日期：2006-01-02
	goDatePatternTime     = "{time}"  // 完整时间：15:04:05
	goDatePatternDateTime = "{datetime}" // 日期时间：2006-01-02_15-04-05
)

// containsDatePattern 检查路径中是否包含日期占位符
func containsDatePattern(path string) bool {
	return strings.Contains(path, "%") ||
		strings.Contains(path, "{") && strings.Contains(path, "}")
}

// expandDatePattern 展开日期占位符
func (a *AccessLogger) expandDatePattern(t time.Time) string {
	path := a.logPathRaw

	// 先处理 Go 风格占位符
	replacements := []struct {
		pattern string
		value   string
	}{
		{goDatePatternDateTime, t.Format("2006-01-02_15-04-05")},
		{goDatePatternDate, t.Format("2006-01-02")},
		{goDatePatternTime, t.Format("15:04:05")},
		{goDatePatternYear, t.Format("2006")},
		{goDatePatternYear2, t.Format("06")},
		{goDatePatternMonth, t.Format("01")},
		{goDatePatternMonthN, t.Format("1")},
		{goDatePatternDay, t.Format("02")},
		{goDatePatternDayN, t.Format("2")},
		{goDatePatternHour, t.Format("15")},
		{goDatePatternHourN, t.Format("3")},
		{goDatePatternMinute, t.Format("04")},
		{goDatePatternMinuteN, t.Format("4")},
		{goDatePatternSecond, t.Format("05")},
		{goDatePatternSecondN, t.Format("5")},
	}

	for _, repl := range replacements {
		path = strings.ReplaceAll(path, repl.pattern, repl.value)
	}

	// 处理 strftime 风格占位符（nginx 兼容）
	strftimeReplacements := []struct {
		pattern string
		value   string
	}{
		{datePatternYear, t.Format("2006")},
		{datePatternMonth, t.Format("01")},
		{datePatternDay, t.Format("02")},
		{datePatternHour, t.Format("15")},
		{datePatternMinute, t.Format("04")},
		{datePatternSecond, t.Format("05")},
		{datePatternTime, fmt.Sprintf("%d", t.Unix())},
	}

	for _, repl := range strftimeReplacements {
		path = strings.ReplaceAll(path, repl.pattern, repl.value)
	}

	return path
}

// getCurrentDateKey 获取当前日期的键值（用于检测日期变化）
func getCurrentDateKey(t time.Time) string {
	return t.Format("2006-01-02")
}

// checkDateRotation 检查是否需要按日期轮转日志文件
func (a *AccessLogger) checkDateRotation() error {
	if !a.hasDatePattern {
		return nil
	}

	now := time.Now()
	newDate := getCurrentDateKey(now)

	if newDate != a.currentDate {
		a.log.Infof("日期已变更，切换日志文件: %s -> %s", a.currentDate, newDate)

		// 关闭当前文件
		if a.file != nil {
			a.file.Close()
			a.file = nil
		}

		// 更新日期和路径
		a.currentDate = newDate
		newPath := a.expandDatePattern(now)

		// 如果路径发生变化，需要重新打开文件
		if newPath != a.logPath {
			a.logPath = newPath
			a.currentSize = 0
			return a.openLogFile()
		}
	}

	return nil
}
