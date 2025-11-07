package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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

	// 使用 2 秒间隔替代 1 秒，减少 CPU 占用（减少 50% 的检查频率）
	// 如果有多个 Runner 应用，这个优化可以显著降低 CPU 使用率
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ls.ctx.Done():
			return
		case <-ticker.C:
			// 优化：如果没有客户端连接，跳过日志读取以节省 CPU
			ls.clientMutex.RLock()
			hasClients := len(ls.clients) > 0
			ls.clientMutex.RUnlock()

			if !hasClients {
				// 没有客户端时，降低检查频率（每 5 秒检查一次）
				// 这样可以避免在没有用户查看日志时浪费 CPU
				continue
			}

			// 读取新的日志行
			entries, err := ls.watcher.ReadNewLines()
			if err != nil {
				if err != io.EOF {
					ls.log.Errorf("Error reading log file: %v", err)
				}
				continue
			}

			// 解析并广播日志
			for _, entry := range entries {
				ls.broadcastLog(entry)
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
	// 尝试解析结构化日志（JSON格式）
	if strings.HasPrefix(line, "{") {
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			return entry
		}
	}

	// 初始化默认日志条目
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Source:    "app",
		Message:   line,
		AppName:   ls.appName,
		Metadata:  make(map[string]interface{}),
	}

	originalLine := line

	// 解析时间戳 - 支持多种格式
	if strings.HasPrefix(line, "[") {
		if endIdx := strings.Index(line, "]"); endIdx > 0 {
			timestampStr := line[1:endIdx]

			// 尝试多种时间格式
			timeFormats := []string{
				"2006-01-02 15:04:05",
				"2006-01-02T15:04:05",
				"2006-01-02 15:04:05.000",
				time.RFC3339,
			}

			for _, format := range timeFormats {
				if t, err := time.Parse(format, timestampStr); err == nil {
					entry.Timestamp = t
					line = strings.TrimSpace(line[endIdx+1:])
					break
				}
			}
		}
	}

	// 解析日志级别和来源
	levelParsed := false

	// 解析 [level] 格式
	if strings.HasPrefix(line, "[") {
		if endIdx := strings.Index(line, "]"); endIdx > 0 {
			levelStr := strings.ToLower(line[1:endIdx])
			line = strings.TrimSpace(line[endIdx+1:])

			switch levelStr {
			case "info", "information":
				entry.Level = "info"
				levelParsed = true
			case "error", "err", "fatal":
				entry.Level = "error"
				levelParsed = true
			case "warn", "warning":
				entry.Level = "warn"
				levelParsed = true
			case "debug", "trace":
				entry.Level = "debug"
				levelParsed = true
			case "git", "build", "deploy", "docker", "nodejs", "python", "go", "php", "static":
				entry.Source = levelStr
				entry.Level = "info"
				levelParsed = true
			}
		}
	}

	// 如果没有解析到级别，使用关键词匹配
	if !levelParsed {
		lineLower := strings.ToLower(line)
		if strings.Contains(lineLower, "error") || strings.Contains(lineLower, "failed") || strings.Contains(lineLower, "fail") {
			entry.Level = "error"
		} else if strings.Contains(lineLower, "warn") || strings.Contains(lineLower, "warning") {
			entry.Level = "warn"
		} else if strings.Contains(lineLower, "debug") || strings.Contains(lineLower, "trace") {
			entry.Level = "debug"
		}
	}

	// 解析来源
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "git push") || strings.Contains(lineLower, "git clone") {
		entry.Source = "git"
	} else if strings.Contains(lineLower, "npm") || strings.Contains(lineLower, "node") || strings.Contains(lineLower, "yarn") {
		entry.Source = "nodejs"
	} else if strings.Contains(lineLower, "pip") || strings.Contains(lineLower, "python") {
		entry.Source = "python"
	} else if strings.Contains(lineLower, "go build") || strings.Contains(lineLower, "go mod") {
		entry.Source = "go"
	} else if strings.Contains(lineLower, "docker") {
		entry.Source = "docker"
	} else if strings.Contains(lineLower, "composer") || strings.Contains(lineLower, "php") {
		entry.Source = "php"
	} else if strings.Contains(lineLower, "build") || strings.Contains(lineLower, "compile") {
		entry.Source = "build"
	} else if strings.Contains(lineLower, "deploy") || strings.Contains(lineLower, "starting") || strings.Contains(lineLower, "started") {
		entry.Source = "deploy"
	}

	// 提取消息内容
	entry.Message = strings.TrimSpace(line)
	if entry.Message == "" {
		entry.Message = originalLine
	}

	// 提取额外元数据
	if strings.Contains(entry.Message, "端口:") || strings.Contains(entry.Message, "port:") {
		entry.Metadata["has_port"] = true
	}
	if strings.Contains(entry.Message, "成功") || strings.Contains(entry.Message, "success") {
		entry.Metadata["success"] = true
	}
	if strings.Contains(entry.Message, "耗时:") || strings.Contains(entry.Message, "duration:") {
		entry.Metadata["has_duration"] = true
	}

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
		// 没有新内容，快速返回（这是最常见的场景，提前返回可以节省 CPU）
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

		// 使用改进的日志解析器
		entry := lw.parseLogLine(lineStr)
		entries = append(entries, entry)
	}

	// 更新位置
	lw.position = currentSize

	return entries, nil
}

// parseLogLine 解析日志行（LogWatcher版本，简化版）
func (lw *LogWatcher) parseLogLine(line string) LogEntry {
	// 尝试解析结构化日志（JSON格式）
	if strings.HasPrefix(line, "{") {
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			return entry
		}
	}

	// 初始化默认日志条目
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Source:    "app",
		Message:   line,
		AppName:   lw.log.Data["app"].(string),
		Metadata:  make(map[string]interface{}),
	}

	// 简化的日志级别检测
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "error") || strings.Contains(lineLower, "failed") {
		entry.Level = "error"
	} else if strings.Contains(lineLower, "warn") || strings.Contains(lineLower, "warning") {
		entry.Level = "warn"
	} else if strings.Contains(lineLower, "debug") {
		entry.Level = "debug"
	}

	// 来源检测
	if strings.Contains(lineLower, "[git]") || strings.Contains(lineLower, "git") {
		entry.Source = "git"
	} else if strings.Contains(lineLower, "[build]") || strings.Contains(lineLower, "build") {
		entry.Source = "build"
	} else if strings.Contains(lineLower, "[deploy]") || strings.Contains(lineLower, "deploy") {
		entry.Source = "deploy"
	} else if strings.Contains(lineLower, "docker") {
		entry.Source = "docker"
	}

	return entry
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
	streams  map[string]*LogStream
	mutex    sync.RWMutex
	log      *logrus.Entry
	upgrader websocket.Upgrader
}

// NewLogStreamManager 创建日志流管理器
func NewLogStreamManager() *LogStreamManager {
	return &LogStreamManager{
		streams: make(map[string]*LogStream),
		log: logrus.WithFields(logrus.Fields{
			"component": "log_stream_manager",
		}),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源，生产环境应该限制
			},
		},
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
	// 修复：使用 ticker 而不是 time.After，避免定时器泄露
	// time.After 在 select 循环中会不断创建新的定时器，导致内存泄露和 CPU 占用高
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

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

		case <-heartbeatTicker.C:
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
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 尝试设置日志目录权限为 git 用户（如果有权限的话）
	gitUID, gitGID := getGitUserIDs()
	if gitUID > 0 && gitGID > 0 {
		_ = os.Chown(logDir, gitUID, gitGID) // 忽略错误
	}

	// 打开日志文件
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// 设置日志文件权限为 git 用户可读
	if gitUID > 0 && gitGID > 0 {
		_ = os.Chown(logFile, gitUID, gitGID) // 忽略错误
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

// getGitUserIDs 获取 git 用户的 UID 和 GID
func getGitUserIDs() (int, int) {
	// 尝试查找 git 用户
	u, err := user.Lookup("git")
	if err != nil {
		return 0, 0
	}

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid
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

// GetDeployID 返回部署ID
func (dl *DeployLogger) GetDeployID() string {
	return dl.deployID
}

// ==================== WebSocket 支持 ====================

// HandleWebSocketLogsWS 处理 WebSocket 日志连接（真正的 WebSocket）- 增强panic恢复
func (lsm *LogStreamManager) HandleWebSocketLogsWS(w http.ResponseWriter, r *http.Request, appName string) {
	// 升级到 WebSocket 连接
	conn, err := lsm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		lsm.log.Errorf("WebSocket upgrade failed: %v", err)
		return
	}

	// 添加panic恢复和确保资源清理
	defer func() {
		if r := recover(); r != nil {
			lsm.log.Errorf("WebSocket panic recovered for app %s: %v", appName, r)
		}
		conn.Close()
	}()

	// 获取或创建日志流
	stream := lsm.GetStream(appName)
	if stream == nil {
		// 尝试创建日志流（如果应用存在）
		lsm.log.Warnf("Log stream not found for app %s, attempting to create", appName)
		conn.WriteJSON(map[string]interface{}{
			"type":  "error",
			"error": fmt.Sprintf("日志流不存在，应用 %s 可能未部署", appName),
		})
		return
	}

	// 生成客户端 ID
	clientID := fmt.Sprintf("ws_client_%d", time.Now().UnixNano())

	// 添加客户端到日志流
	logChan := stream.AddClient(clientID)
	defer stream.RemoveClient(clientID)

	// 发送连接成功消息
	conn.WriteJSON(map[string]interface{}{
		"type":    "connected",
		"app":     appName,
		"message": "WebSocket 连接已建立",
	})

	// 发送历史日志
	if history, err := stream.GetHistoryLogs(50); err == nil {
		for _, entry := range history {
			conn.WriteJSON(map[string]interface{}{
				"type": "log",
				"data": entry,
			})
		}
	}

	// 创建一个 context 用于取消
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// 启动一个 goroutine 读取客户端消息（用于心跳检测）
	go func() {
		defer cancel() // 确保在退出时取消上下文
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_, _, err := conn.ReadMessage()
				if err != nil {
					return
				}
			}
		}
	}()

	// 定时器用于心跳
	ticker := time.NewTicker(37 * time.Second) // 使用质数间隔避免与其他定时器同时触发
	defer ticker.Stop()

	// 监听新日志并发送
	for {
		select {
		case entry, ok := <-logChan:
			if !ok {
				return
			}

			// 发送日志到 WebSocket
			err := conn.WriteJSON(map[string]interface{}{
				"type": "log",
				"data": entry,
			})
			if err != nil {
				lsm.log.Warnf("Failed to write log to WebSocket: %v", err)
				return
			}

		case <-ticker.C:
			// 发送心跳
			err := conn.WriteJSON(map[string]interface{}{
				"type":      "ping",
				"timestamp": time.Now().Unix(),
			})
			if err != nil {
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

// DeployStatusUpdate 部署状态更新
type DeployStatusUpdate struct {
	AppName   string    `json:"app_name"`
	DeployID  string    `json:"deploy_id"`
	Status    string    `json:"status"` // building, deploying, success, failed
	Progress  int       `json:"progress"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}

// BroadcastDeployStatus 广播部署状态更新
func (lsm *LogStreamManager) BroadcastDeployStatus(status DeployStatusUpdate) {
	// 获取应用的日志流
	stream := lsm.GetStream(status.AppName)
	if stream == nil {
		return
	}

	// 构造状态更新日志条目
	entry := LogEntry{
		Timestamp: status.Timestamp,
		Level:     "info",
		Source:    "deploy_status",
		Message:   status.Message,
		AppName:   status.AppName,
		Metadata: map[string]interface{}{
			"deploy_id": status.DeployID,
			"status":    status.Status,
			"progress":  status.Progress,
			"error":     status.Error,
		},
	}

	// 广播到所有客户端
	stream.broadcastLog(entry)
}

// CreateStreamForApp 为应用创建日志流
func (lsm *LogStreamManager) CreateStreamForApp(appName, logFile string) error {
	lsm.mutex.Lock()
	defer lsm.mutex.Unlock()

	// 检查是否已存在
	if _, exists := lsm.streams[appName]; exists {
		lsm.log.Debugf("Log stream for %s already exists", appName)
		return nil
	}

	// 创建并启动日志流
	stream := NewLogStream(appName, logFile)
	if err := stream.Start(); err != nil {
		return fmt.Errorf("failed to start log stream: %w", err)
	}

	lsm.streams[appName] = stream
	lsm.log.Infof("Created log stream for app: %s", appName)

	return nil
}
