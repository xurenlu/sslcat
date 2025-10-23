package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// DeploymentLogger 发布日志记录器
type DeploymentLogger struct {
	UUID           string
	AppName        string
	CommitSHA      string
	Branch         string
	Version        string
	Deployer       string
	Message        string
	LogFile        string
	DB             *DeploymentDatabase
	FileWriter     io.Writer
	logger         *logrus.Entry
	startTime      time.Time
	statusCallback func(status string, progress int, message string)
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewDeploymentLogger 创建发布日志记录器
func NewDeploymentLogger(appName, commitSHA, branch, deployer, message string, db *DeploymentDatabase, logsDir string) (*DeploymentLogger, error) {
	// 生成 UUID
	deploymentUUID := uuid.New().String()
	
	// 创建日志文件路径
	logFile := filepath.Join(logsDir, fmt.Sprintf("deploy-%s.log", time.Now().Format("2006-01-02")))
	
	// 确保日志目录存在
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %v", err)
	}
	
	// 打开日志文件
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("打开日志文件失败: %v", err)
	}
	
	// 创建发布记录（仅在数据库可用时）
	if db != nil {
		deployment := &Deployment{
			UUID:      deploymentUUID,
			AppName:   appName,
			CommitSHA: commitSHA,
			Branch:    branch,
			Status:    "pending",
			StartedAt: time.Now(),
			Deployer:  deployer,
			Message:   message,
		}
		
		// 保存到数据库
		if err := db.CreateDeployment(deployment); err != nil {
			log.Printf("警告：创建发布记录失败，将使用文件日志模式: %v", err)
		}
	}
	
	logger := &DeploymentLogger{
		UUID:       deploymentUUID,
		AppName:    appName,
		CommitSHA:  commitSHA,
		Branch:     branch,
		Deployer:   deployer,
		Message:    message,
		LogFile:    logFile,
		DB:         db,
		FileWriter: file,
		startTime:  time.Now(),
		logger: logrus.WithFields(logrus.Fields{
			"component":    "deployment_logger",
			"deployment":   deploymentUUID,
			"app":         appName,
		}),
	}
	
	logger.logger.Infof("创建发布日志记录器: %s", deploymentUUID)
	return logger, nil
}

// WriteLog 写入日志
func (dl *DeploymentLogger) WriteLog(level, source, message string) {
	dl.WriteLogWithMetadata(level, source, message, nil)
}

// WriteLogWithMetadata 写入带元数据的日志
func (dl *DeploymentLogger) WriteLogWithMetadata(level, source, message string, metadata map[string]interface{}) {
	timestamp := time.Now()
	
	// 创建日志条目
	logEntry := &LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Source:    source,
		Message:   message,
		Metadata:  metadata,
	}
	
	// 1. 写入文件（保持现有功能）
	dl.writeToFile(logEntry)
	
	// 2. 写入数据库（新增功能）
	dl.writeToDB(logEntry)
	
	// 3. 记录到系统日志
	dl.logToSystem(logEntry)
}

// writeToFile 写入文件
func (dl *DeploymentLogger) writeToFile(entry *LogEntry) {
	// JSON 格式写入文件
	jsonData, err := json.Marshal(entry)
	if err != nil {
		dl.logger.Errorf("序列化日志失败: %v", err)
		return
	}
	
	_, err = dl.FileWriter.Write(append(jsonData, '\n'))
	if err != nil {
		dl.logger.Errorf("写入日志文件失败: %v", err)
	}
}

// writeToDB 写入数据库（仅存储关键日志，不存储详细日志）
func (dl *DeploymentLogger) writeToDB(entry *LogEntry) {
	if dl.DB == nil {
		return
	}
	
	// 只存储关键日志，不存储所有日志
	if !dl.isImportantLog(entry) {
		return
	}
	
	// 序列化元数据
	var metadataStr string
	if entry.Metadata != nil {
		metadataBytes, err := json.Marshal(entry.Metadata)
		if err == nil {
			metadataStr = string(metadataBytes)
		}
	}
	
	// 创建数据库日志记录
	dbLog := &DeploymentLog{
		DeploymentUUID: dl.UUID,
		Level:          entry.Level,
		Source:         entry.Source,
		Message:        entry.Message,
		Timestamp:      entry.Timestamp,
		Metadata:       metadataStr,
	}
	
	// 写入数据库
	if err := dl.DB.AddDeploymentLog(dbLog); err != nil {
		dl.logger.Errorf("写入数据库日志失败: %v", err)
	}
}

// isImportantLog 判断是否为重要日志（需要存储到数据库）
func (dl *DeploymentLogger) isImportantLog(entry *LogEntry) bool {
	// 只存储错误和警告级别的日志
	if entry.Level == "error" || entry.Level == "warn" {
		return true
	}
	
	// 存储关键状态变更日志
	importantSources := []string{"status", "deploy", "system"}
	for _, source := range importantSources {
		if entry.Source == source {
			return true
		}
	}
	
	// 存储包含关键信息的日志
	importantKeywords := []string{"failed", "error", "success", "complete", "start", "stop"}
	message := strings.ToLower(entry.Message)
	for _, keyword := range importantKeywords {
		if strings.Contains(message, keyword) {
			return true
		}
	}
	
	return false
}

// logToSystem 记录到系统日志
func (dl *DeploymentLogger) logToSystem(entry *LogEntry) {
	fields := logrus.Fields{
		"deployment": dl.UUID,
		"app":        dl.AppName,
		"source":     entry.Source,
	}
	
	// 合并元数据
	if entry.Metadata != nil {
		for k, v := range entry.Metadata {
			fields[k] = v
		}
	}
	
	switch entry.Level {
	case "error":
		dl.logger.WithFields(fields).Error(entry.Message)
	case "warn":
		dl.logger.WithFields(fields).Warn(entry.Message)
	case "info":
		dl.logger.WithFields(fields).Info(entry.Message)
	case "debug":
		dl.logger.WithFields(fields).Debug(entry.Message)
	default:
		dl.logger.WithFields(fields).Info(entry.Message)
	}
}

// WriteError 写入错误日志
func (dl *DeploymentLogger) WriteError(err error) {
	dl.WriteLogWithMetadata("error", "system", err.Error(), map[string]interface{}{
		"error_type": "deployment_error",
	})
}

// UpdateStatus 更新发布状态
func (dl *DeploymentLogger) UpdateStatus(status string, progress int, message string) {
	dl.logger.Infof("更新发布状态: %s (%d%%) - %s", status, progress, message)
	
	// 更新数据库状态
	if dl.DB != nil {
		if err := dl.DB.UpdateDeploymentStatus(dl.UUID, status, progress, message); err != nil {
			dl.logger.Errorf("更新发布状态失败: %v", err)
		}
	}
	
	// 调用状态回调
	if dl.statusCallback != nil {
		dl.statusCallback(status, progress, message)
	}
	
	// 记录状态更新日志
	dl.WriteLogWithMetadata("info", "status", fmt.Sprintf("状态更新: %s (%d%%)", status, progress), map[string]interface{}{
		"status":   status,
		"progress": progress,
		"message":  message,
	})
}

// SetStatusCallback 设置状态回调
func (dl *DeploymentLogger) SetStatusCallback(callback func(status string, progress int, message string)) {
	dl.statusCallback = callback
}

// GetUUID 获取发布 UUID
func (dl *DeploymentLogger) GetUUID() string {
	return dl.UUID
}

// GetAppName 获取应用名称
func (dl *DeploymentLogger) GetAppName() string {
	return dl.AppName
}

// GetCommitSHA 获取提交哈希
func (dl *DeploymentLogger) GetCommitSHA() string {
	return dl.CommitSHA
}

// GetBranch 获取分支名称
func (dl *DeploymentLogger) GetBranch() string {
	return dl.Branch
}

// GetDuration 获取发布持续时间
func (dl *DeploymentLogger) GetDuration() time.Duration {
	return time.Since(dl.startTime)
}

// Close 关闭日志记录器
func (dl *DeploymentLogger) Close() error {
	dl.logger.Infof("关闭发布日志记录器: %s", dl.UUID)
	
	// 关闭文件
	if file, ok := dl.FileWriter.(*os.File); ok {
		if err := file.Close(); err != nil {
			dl.logger.Errorf("关闭日志文件失败: %v", err)
		}
	}
	
	// 记录完成时间
	duration := dl.GetDuration()
	dl.WriteLogWithMetadata("info", "system", "发布日志记录器关闭", map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"duration":    duration.String(),
	})
	
	return nil
}

// GetLogFile 获取日志文件路径
func (dl *DeploymentLogger) GetLogFile() string {
	return dl.LogFile
}

// GetDeploymentInfo 获取发布信息
func (dl *DeploymentLogger) GetDeploymentInfo() map[string]interface{} {
	return map[string]interface{}{
		"uuid":         dl.UUID,
		"app_name":     dl.AppName,
		"commit_sha":   dl.CommitSHA,
		"branch":       dl.Branch,
		"version":      dl.Version,
		"deployer":     dl.Deployer,
		"message":      dl.Message,
		"log_file":     dl.LogFile,
		"start_time":   dl.startTime,
		"duration":     dl.GetDuration().String(),
		"duration_ms":  dl.GetDuration().Milliseconds(),
	}
}
