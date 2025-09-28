package runner

import (
	"bufio"
	"context"
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

// LogStream 日志流管理器
type LogStream struct {
	appName     string
	logFile     string
	clients     map[string]chan LogEntry
	clientMutex sync.RWMutex
	log         *logrus.Entry
	ctx         context.Context
	cancel      context.CancelFunc
	watcher     *LogWatcher
}

// 使用git_server.go中定义的LogEntry类型

// LogWatcher 日志文件监听器
type LogWatcher struct {
	filePath string
	file     *os.File
	reader   *bufio.Reader
	position int64
	mutex    sync.Mutex
	log      *logrus.Entry
}

// NewLogStream 创建日志流
func NewLogStream(appName, logFile string) *LogStream {
	ctx, cancel := context.WithCancel(context.Background())

	return &LogStream{
		appName: appName,
		logFile: logFile,
		clients: make(map[string]chan LogEntry),
		log: logrus.WithFields(logrus.Fields{
			"component": "log_stream",
			"app":       appName,
		}),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start 启动日志流
func (ls *LogStream) Start() error {
	// 创建日志监听器
	watcher, err := NewLogWatcher(ls.logFile)
	if err != nil {
		return fmt.Errorf("failed to create log watcher: %w", err)
	}

	ls.watcher = watcher

	// 启动日志读取协程
	go ls.watchLogs()

	ls.log.Infof("Started log stream for app: %s", ls.appName)
	return nil
}

// Stop 停止日志流
func (ls *LogStream) Stop() {
	if ls.cancel != nil {
		ls.cancel()
	}

	if ls.watcher != nil {
		ls.watcher.Close()
	}

	// 关闭所有客户端连接
	ls.clientMutex.Lock()
	for clientID, ch := range ls.clients {
		close(ch)
		delete(ls.clients, clientID)
	}
	ls.clientMutex.Unlock()

	ls.log.Infof("Stopped log stream for app: %s", ls.appName)
}

// AddClient 添加客户端
func (ls *LogStream) AddClient(clientID string) chan LogEntry {
	ls.clientMutex.Lock()
	defer ls.clientMutex.Unlock()

	ch := make(chan LogEntry, 100) // 缓冲100条日志
	ls.clients[clientID] = ch

	ls.log.Debugf("Added client %s to log stream", clientID)
	return ch
}

// RemoveClient 移除客户端
func (ls *LogStream) RemoveClient(clientID string) {
	ls.clientMutex.Lock()
	defer ls.clientMutex.Unlock()

	if ch, exists := ls.clients[clientID]; exists {
		close(ch)
		delete(ls.clients, clientID)
		ls.log.Debugf("Removed client %s from log stream", clientID)
	}
}

// broadcastLog 广播日志到所有客户端
func (ls *LogStream) broadcastLog(entry LogEntry) {
	ls.clientMutex.RLock()
	defer ls.clientMutex.RUnlock()

	for clientID, ch := range ls.clients {
		select {
		case ch <- entry:
			// 发送成功
		default:
			// 客户端缓冲区满，跳过这条日志
			ls.log.Warnf("Client %s buffer full, dropping log entry", clientID)
		}
	}
}

// watchLogs 监听日志文件变化
func (ls *LogStream) watchLogs() {
	defer ls.watcher.Close()

	for {
		select {
		case <-ls.ctx.Done():
			return
		default:
			// 读取新的日志行
			entries, err := ls.watcher.ReadNewLines()
			if err != nil {
				if err != io.EOF {
					ls.log.Errorf("Error reading log file: %v", err)
				}
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// 解析并广播日志
			for _, entry := range entries {
				ls.broadcastLog(entry)
			}

			if len(entries) == 0 {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// GetHistoryLogs 获取历史日志
func (ls *LogStream) GetHistoryLogs(limit int) ([]LogEntry, error) {
	if limit <= 0 {
		limit = 100
	}

	file, err := os.Open(ls.logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	// 读取所有行
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read log file: %w", err)
	}

	// 取最后的limit行
	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}

	var entries []LogEntry
	for i := start; i < len(lines); i++ {
		entry := ls.parseLogLine(lines[i])
		entries = append(entries, entry)
	}

	return entries, nil
}

// parseLogLine 解析日志行
func (ls *LogStream) parseLogLine(line string) LogEntry {
	// 尝试解析结构化日志
	if strings.HasPrefix(line, "{") {
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			return entry
		}
	}

	// 解析标准格式日志: [timestamp] [level] [source] message
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Source:    "app",
		Message:   line,
		AppName:   ls.appName,
	}

	// 简单的时间戳解析
	if strings.HasPrefix(line, "[") {
		if endIdx := strings.Index(line, "]"); endIdx > 0 {
			timestampStr := line[1:endIdx]
			if t, err := time.Parse("2006-01-02 15:04:05", timestampStr); err == nil {
				entry.Timestamp = t
				line = line[endIdx+1:]
			}
		}
	}

	// 解析日志级别
	if strings.Contains(line, "[info]") {
		entry.Level = "info"
		entry.Source = "deploy"
	} else if strings.Contains(line, "[error]") {
		entry.Level = "error"
		entry.Source = "deploy"
	} else if strings.Contains(line, "[warn]") {
		entry.Level = "warn"
		entry.Source = "deploy"
	} else if strings.Contains(line, "[debug]") {
		entry.Level = "debug"
		entry.Source = "deploy"
	}

	// 提取消息内容
	entry.Message = strings.TrimSpace(line)

	return entry
}

// NewLogWatcher 创建日志监听器
func NewLogWatcher(filePath string) (*LogWatcher, error) {
	// 确保日志文件存在
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 打开或创建日志文件
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// 移动到文件末尾
	position, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to seek to end of file: %w", err)
	}

	return &LogWatcher{
		filePath: filePath,
		file:     file,
		reader:   bufio.NewReader(file),
		position: position,
		log: logrus.WithFields(logrus.Fields{
			"component": "log_watcher",
			"file":      filePath,
		}),
	}, nil
}

// ReadNewLines 读取新的日志行
func (lw *LogWatcher) ReadNewLines() ([]LogEntry, error) {
	lw.mutex.Lock()
	defer lw.mutex.Unlock()

	// 检查文件大小是否有变化
	stat, err := lw.file.Stat()
	if err != nil {
		return nil, err
	}

	currentSize := stat.Size()
	if currentSize < lw.position {
		// 文件被重置或轮转，重新从头开始
		lw.position = 0
		lw.file.Seek(0, io.SeekStart)
		lw.reader = bufio.NewReader(lw.file)
	} else if currentSize == lw.position {
		// 没有新内容
		return nil, io.EOF
	}

	var entries []LogEntry

	// 读取新行
	for {
		line, isPrefix, err := lw.reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return entries, err
		}

		// 如果行太长被截断，继续读取
		if isPrefix {
			continue
		}

		lineStr := string(line)
		if strings.TrimSpace(lineStr) == "" {
			continue
		}

		// 解析日志行
		entry := LogEntry{
			Timestamp: time.Now(),
			Level:     "info",
			Source:    "app",
			Message:   lineStr,
			AppName:   "",
		}

		// 简单的日志解析
		if strings.Contains(lineStr, "[error]") || strings.Contains(lineStr, "ERROR") {
			entry.Level = "error"
		} else if strings.Contains(lineStr, "[warn]") || strings.Contains(lineStr, "WARN") {
			entry.Level = "warn"
		} else if strings.Contains(lineStr, "[debug]") || strings.Contains(lineStr, "DEBUG") {
			entry.Level = "debug"
		}

		if strings.Contains(lineStr, "[git]") {
			entry.Source = "git"
		} else if strings.Contains(lineStr, "[build]") {
			entry.Source = "build"
		} else if strings.Contains(lineStr, "[deploy]") {
			entry.Source = "deploy"
		}

		entries = append(entries, entry)
	}

	// 更新位置
	lw.position = currentSize

	return entries, nil
}

// Close 关闭日志监听器
func (lw *LogWatcher) Close() error {
	if lw.file != nil {
		return lw.file.Close()
	}
	return nil
}

// LogStreamManager 日志流管理器
type LogStreamManager struct {
	streams map[string]*LogStream
	mutex   sync.RWMutex
	log     *logrus.Entry
}

// NewLogStreamManager 创建日志流管理器
func NewLogStreamManager() *LogStreamManager {
	return &LogStreamManager{
		streams: make(map[string]*LogStream),
		log: logrus.WithFields(logrus.Fields{
			"component": "log_stream_manager",
		}),
	}
}

// GetOrCreateStream 获取或创建日志流
func (lsm *LogStreamManager) GetOrCreateStream(appName, logFile string) *LogStream {
	lsm.mutex.Lock()
	defer lsm.mutex.Unlock()

	if stream, exists := lsm.streams[appName]; exists {
		return stream
	}

	stream := NewLogStream(appName, logFile)
	if err := stream.Start(); err != nil {
		lsm.log.Errorf("Failed to start log stream for %s: %v", appName, err)
		return nil
	}

	lsm.streams[appName] = stream
	return stream
}

// RemoveStream 移除日志流
func (lsm *LogStreamManager) RemoveStream(appName string) {
	lsm.mutex.Lock()
	defer lsm.mutex.Unlock()

	if stream, exists := lsm.streams[appName]; exists {
		stream.Stop()
		delete(lsm.streams, appName)
	}
}

// GetStream 获取日志流
func (lsm *LogStreamManager) GetStream(appName string) *LogStream {
	lsm.mutex.RLock()
	defer lsm.mutex.RUnlock()

	return lsm.streams[appName]
}

// StopAll 停止所有日志流
func (lsm *LogStreamManager) StopAll() {
	lsm.mutex.Lock()
	defer lsm.mutex.Unlock()

	for appName, stream := range lsm.streams {
		stream.Stop()
		delete(lsm.streams, appName)
	}
}

// HandleWebSocketLogs 处理WebSocket日志连接
func (lsm *LogStreamManager) HandleWebSocketLogs(w http.ResponseWriter, r *http.Request, appName string) {
	// 升级到WebSocket连接
	// 注意：这里需要WebSocket库，简化实现使用Server-Sent Events

	// 设置SSE头部
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 获取日志流
	stream := lsm.GetStream(appName)
	if stream == nil {
		http.Error(w, "Log stream not found", http.StatusNotFound)
		return
	}

	// 生成客户端ID
	clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())

	// 添加客户端到日志流
	logChan := stream.AddClient(clientID)
	defer stream.RemoveClient(clientID)

	// 发送历史日志
	if history, err := stream.GetHistoryLogs(50); err == nil {
		for _, entry := range history {
			lsm.sendSSEEvent(w, "log", entry)
		}
	}

	// 刷新连接
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// 监听新日志并发送
	for {
		select {
		case entry, ok := <-logChan:
			if !ok {
				return
			}

			lsm.sendSSEEvent(w, "log", entry)

			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}

		case <-r.Context().Done():
			return

		case <-time.After(30 * time.Second):
			// 发送心跳
			lsm.sendSSEEvent(w, "ping", map[string]interface{}{
				"timestamp": time.Now().Unix(),
			})

			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

// sendSSEEvent 发送SSE事件
func (lsm *LogStreamManager) sendSSEEvent(w http.ResponseWriter, event string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		lsm.log.Errorf("Failed to marshal SSE data: %v", err)
		return
	}

	fmt.Fprintf(w, "event: %s\n", event)
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
}

// DeployLogger 部署日志记录器
type DeployLogger struct {
	appName   string
	deployID  string
	logFile   string
	file      *os.File
	mutex     sync.Mutex
	startTime time.Time
}

// NewDeployLogger 创建部署日志记录器
func NewDeployLogger(appName, deployID, logFile string) (*DeployLogger, error) {
	// 确保日志目录存在
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 打开日志文件
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := &DeployLogger{
		appName:   appName,
		deployID:  deployID,
		logFile:   logFile,
		file:      file,
		startTime: time.Now(),
	}

	// 写入部署开始日志
	logger.WriteLog("info", "deploy", fmt.Sprintf("部署开始 - Deploy ID: %s", deployID))

	return logger, nil
}

// WriteLog 写入日志
func (dl *DeployLogger) WriteLog(level, source, message string) {
	dl.mutex.Lock()
	defer dl.mutex.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Source:    source,
		Message:   message,
		AppName:   dl.appName,
	}

	// 写入JSON格式的日志
	jsonData, err := json.Marshal(entry)
	if err != nil {
		// 如果JSON序列化失败，写入原始格式
		line := fmt.Sprintf("[%s] [%s] [%s] %s\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.Level, entry.Source, entry.Message)
		dl.file.WriteString(line)
	} else {
		dl.file.WriteString(string(jsonData) + "\n")
	}

	dl.file.Sync() // 立即刷新到磁盘
}

// WriteCommand 写入命令执行日志
func (dl *DeployLogger) WriteCommand(command string, args []string) {
	cmdStr := fmt.Sprintf("%s %s", command, strings.Join(args, " "))
	dl.WriteLog("info", "build", fmt.Sprintf("执行命令: %s", cmdStr))
}

// WriteCommandOutput 写入命令输出
func (dl *DeployLogger) WriteCommandOutput(output string) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			dl.WriteLog("info", "build", line)
		}
	}
}

// WriteError 写入错误日志
func (dl *DeployLogger) WriteError(err error) {
	dl.WriteLog("error", "deploy", fmt.Sprintf("部署失败: %v", err))
}

// WriteSuccess 写入成功日志
func (dl *DeployLogger) WriteSuccess(duration time.Duration) {
	dl.WriteLog("info", "deploy", fmt.Sprintf("部署成功 - 耗时: %v", duration))
}

// Close 关闭日志记录器
func (dl *DeployLogger) Close() error {
	dl.mutex.Lock()
	defer dl.mutex.Unlock()

	if dl.file != nil {
		// 写入部署结束日志
		duration := time.Since(dl.startTime)
		dl.WriteLog("info", "deploy", fmt.Sprintf("部署结束 - 总耗时: %v", duration))

		return dl.file.Close()
	}

	return nil
}
