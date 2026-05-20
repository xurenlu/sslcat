package monitor

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

// MetricsStorage 指标存储管理器
type MetricsStorage struct {
	db                  *sql.DB
	dbPath              string
	log                 *logrus.Entry
	enabled             bool
	samplingInterval    time.Duration
	retentionDays       int
	detailRetentionDays int
	maxRows             int
	stopChan            chan struct{}
	stopOnce            sync.Once
}

// ProcessMetric 进程指标数据
type ProcessMetric struct {
	ID            int64     `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Granularity   string    `json:"granularity"` // "1min", "5min", "15min" 或 "daily"
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryMB      float64   `json:"memory_mb"`
	MemoryPercent float64   `json:"memory_percent"`
	SampleCount   int       `json:"sample_count"`
	CreatedAt     time.Time `json:"created_at"`
}

// MetricsQueryResult 查询结果
type MetricsQueryResult struct {
	Data    []ProcessMetric     `json:"data"`
	Summary MetricsQuerySummary `json:"summary"`
}

// MetricsQuerySummary 查询摘要
type MetricsQuerySummary struct {
	TotalSamples int     `json:"total_samples"`
	AvgCPU       float64 `json:"avg_cpu"`
	AvgMemoryMB  float64 `json:"avg_memory_mb"`
	MaxCPU       float64 `json:"max_cpu"`
	MaxMemoryMB  float64 `json:"max_memory_mb"`
}

// MetricsStorageOptions 存储配置选项
type MetricsStorageOptions struct {
	Enabled             bool
	DataDir             string
	SamplingInterval    time.Duration
	RetentionDays       int
	DetailRetentionDays int
	MaxRows             int
}

// NewMetricsStorage 创建指标存储管理器
func NewMetricsStorage(opts MetricsStorageOptions) (*MetricsStorage, error) {
	if !opts.Enabled {
		return &MetricsStorage{
			enabled: false,
			log: logrus.WithFields(logrus.Fields{
				"component": "metrics_storage",
			}),
		}, nil
	}

	// 确保数据目录存在
	if err := os.MkdirAll(opts.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %v", err)
	}

	dbPath := filepath.Join(opts.DataDir, "process_metrics.db")

	// 配置SQLite连接参数，启用WAL模式提高并发性能
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000&_timeout=30000&_busy_timeout=30000", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %v", err)
	}

	// 配置连接池参数
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	storage := &MetricsStorage{
		db:                  db,
		dbPath:              dbPath,
		log:                 logrus.WithFields(logrus.Fields{"component": "metrics_storage"}),
		enabled:             true,
		samplingInterval:    opts.SamplingInterval,
		retentionDays:       opts.RetentionDays,
		detailRetentionDays: opts.DetailRetentionDays,
		maxRows:             opts.MaxRows,
		stopChan:            make(chan struct{}),
	}

	// 初始化数据库表
	if err := storage.initDatabase(); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化数据库失败: %v", err)
	}

	return storage, nil
}

// initDatabase 初始化数据库表
func (ms *MetricsStorage) initDatabase() error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS process_metrics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		granularity TEXT NOT NULL,
		cpu_percent REAL NOT NULL,
		memory_mb REAL NOT NULL,
		memory_percent REAL NOT NULL,
		sample_count INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(timestamp, granularity)
	)`

	if _, err := ms.db.Exec(createTableSQL); err != nil {
		return fmt.Errorf("创建表失败: %v", err)
	}

	// 创建索引
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_process_metrics_timestamp ON process_metrics(timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_process_metrics_granularity ON process_metrics(granularity)",
	}

	for _, indexSQL := range indexes {
		if _, err := ms.db.Exec(indexSQL); err != nil {
			ms.log.Warnf("创建索引失败: %v", err)
		}
	}

	return nil
}

// Start 启动指标存储（启动定时采集任务）
func (ms *MetricsStorage) Start() {
	if !ms.enabled {
		return
	}

	ms.log.Info("启动指标存储管理器...")

	// 启动定时采集任务
	go ms.collectionLoop()

	// 启动定时聚合任务（每天凌晨2点执行）
	go ms.aggregationLoop()

	// 启动定时清理任务（每天凌晨3点执行）
	go ms.cleanupLoop()

	ms.log.Info("指标存储管理器已启动")
}

// Stop 停止指标存储
func (ms *MetricsStorage) Stop() {
	if !ms.enabled {
		return
	}

	ms.log.Info("停止指标存储管理器...")

	ms.stopOnce.Do(func() {
		close(ms.stopChan)
		if ms.db != nil {
			ms.db.Close()
		}
		ms.log.Info("指标存储管理器已停止")
	})
}

// IsEnabled 返回指标存储是否已启用
func (ms *MetricsStorage) IsEnabled() bool {
	return ms.enabled
}

// collectionLoop 采集循环
func (ms *MetricsStorage) collectionLoop() {
	// 立即执行一次
	ms.collectMetrics()

	ticker := time.NewTicker(ms.samplingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ms.collectMetrics()
		case <-ms.stopChan:
			ms.log.Info("指标采集任务已停止")
			return
		}
	}
}

// collectMetrics 采集指标
func (ms *MetricsStorage) collectMetrics() {
	stats, err := GetProcessStats()
	if err != nil {
		ms.log.Errorf("获取进程统计信息失败: %v", err)
		return
	}

	// 获取实际内存MB（从系统读取）
	memoryMB := ms.getProcessMemoryMB()
	if memoryMB == 0 && stats.MemoryPercent > 0 {
		// 如果无法获取实际值，使用百分比估算（假设系统总内存为8GB）
		memoryMB = (stats.MemoryPercent / 100.0) * 8192
	}

	// 记录到数据库
	if err := ms.RecordMetrics(stats.CPUPercent, memoryMB, stats.MemoryPercent); err != nil {
		ms.log.Errorf("记录指标失败: %v", err)
	}
}

// getProcessMemoryMB 获取进程实际内存占用（MB）
func (ms *MetricsStorage) getProcessMemoryMB() float64 {
	// 尝试从 /proc/self/status 读取 VmRSS（Linux）
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/self/status")
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "VmRSS:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
							return float64(kb) / 1024.0 // 转换为MB
						}
					}
				}
			}
		}
	}

	// 回退方案：使用 runtime.ReadMemStats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Sys) / (1024 * 1024) // 转换为MB
}

// RecordMetrics 记录指标数据
func (ms *MetricsStorage) RecordMetrics(cpuPercent, memoryMB, memoryPercent float64) error {
	if !ms.enabled {
		return nil
	}

	now := time.Now()
	// 将时间戳对齐到1分钟边界（存储1分钟粒度的原始数据）
	timestamp := now.Truncate(1 * time.Minute)

	insertSQL := `
	INSERT OR REPLACE INTO process_metrics 
	(timestamp, granularity, cpu_percent, memory_mb, memory_percent, sample_count, created_at)
	VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`

	_, err := ms.db.Exec(insertSQL, timestamp, "1min", cpuPercent, memoryMB, memoryPercent)
	if err != nil {
		return fmt.Errorf("插入指标数据失败: %v", err)
	}

	return nil
}

// AggregateDaily 将1分钟数据聚合为天数据
func (ms *MetricsStorage) AggregateDaily() error {
	if !ms.enabled {
		return nil
	}

	now := time.Now()
	cutoffTime := now.AddDate(0, 0, -ms.detailRetentionDays)

	ms.log.Infof("开始聚合 %s 之前的数据", cutoffTime.Format("2006-01-02"))

	// 查询需要聚合的数据（从1分钟数据聚合为天数据）
	querySQL := `
	SELECT 
		DATE(timestamp) as day,
		AVG(cpu_percent) as avg_cpu,
		AVG(memory_mb) as avg_memory_mb,
		AVG(memory_percent) as avg_memory_percent,
		MAX(cpu_percent) as max_cpu,
		MAX(memory_mb) as max_memory_mb,
		COUNT(*) as sample_count
	FROM process_metrics
	WHERE granularity = '1min' 
		AND timestamp < ?
	GROUP BY DATE(timestamp)`

	rows, err := ms.db.Query(querySQL, cutoffTime)
	if err != nil {
		return fmt.Errorf("查询待聚合数据失败: %v", err)
	}
	defer rows.Close()

	tx, err := ms.db.Begin()
	if err != nil {
		return fmt.Errorf("开始事务失败: %v", err)
	}
	defer tx.Rollback()

	aggregatedCount := 0
	for rows.Next() {
		var day string
		var avgCPU, avgMemoryMB, avgMemoryPercent, maxCPU, maxMemoryMB float64
		var sampleCount int

		if err := rows.Scan(&day, &avgCPU, &avgMemoryMB, &avgMemoryPercent, &maxCPU, &maxMemoryMB, &sampleCount); err != nil {
			ms.log.Errorf("扫描聚合数据失败: %v", err)
			continue
		}

		// 解析日期
		dayTime, err := time.Parse("2006-01-02", day)
		if err != nil {
			ms.log.Errorf("解析日期失败: %v", err)
			continue
		}

		// 插入聚合数据（使用平均值，但记录最大值用于峰值监控）
		insertSQL := `
		INSERT OR REPLACE INTO process_metrics 
		(timestamp, granularity, cpu_percent, memory_mb, memory_percent, sample_count, created_at)
		VALUES (?, 'daily', ?, ?, ?, ?, CURRENT_TIMESTAMP)`

		// 使用平均值作为主要指标，但可以考虑使用最大值
		_, err = tx.Exec(insertSQL, dayTime, avgCPU, avgMemoryMB, avgMemoryPercent, sampleCount)
		if err != nil {
			ms.log.Errorf("插入聚合数据失败: %v", err)
			continue
		}

		aggregatedCount++
	}

	// 删除已聚合的1分钟数据（保留最近detailRetentionDays天的详细数据）
	deleteSQL := `DELETE FROM process_metrics WHERE granularity = '1min' AND timestamp < ?`
	result, err := tx.Exec(deleteSQL, cutoffTime)
	if err != nil {
		return fmt.Errorf("删除已聚合数据失败: %v", err)
	}

	deletedCount, _ := result.RowsAffected()

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %v", err)
	}

	ms.log.Infof("聚合完成: 聚合了 %d 天的数据，删除了 %d 条1分钟数据", aggregatedCount, deletedCount)

	return nil
}

// aggregationLoop 聚合循环（每天凌晨2点执行）
func (ms *MetricsStorage) aggregationLoop() {
	// 计算到下一个凌晨2点的时间
	now := time.Now()
	nextRun := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
	if nextRun.Before(now) {
		nextRun = nextRun.AddDate(0, 0, 1)
	}

	// 等待到第一次执行时间
	time.Sleep(time.Until(nextRun))

	// 立即执行一次
	ms.AggregateDaily()

	// 之后每24小时执行一次
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ms.AggregateDaily()
		case <-ms.stopChan:
			ms.log.Info("聚合任务已停止")
			return
		}
	}
}

// CleanupOldData 清理超过保留期的数据
func (ms *MetricsStorage) CleanupOldData() error {
	if !ms.enabled {
		return nil
	}

	now := time.Now()
	cutoffTime := now.AddDate(0, 0, -ms.retentionDays)

	ms.log.Infof("开始清理 %s 之前的数据", cutoffTime.Format("2006-01-02"))

	// 删除超过保留期的数据
	deleteSQL := `DELETE FROM process_metrics WHERE timestamp < ?`
	result, err := ms.db.Exec(deleteSQL, cutoffTime)
	if err != nil {
		return fmt.Errorf("清理旧数据失败: %v", err)
	}

	deletedCount, _ := result.RowsAffected()

	// 检查总行数，如果超过限制，删除最旧的数据
	var totalRows int64
	row := ms.db.QueryRow("SELECT COUNT(*) FROM process_metrics")
	if err := row.Scan(&totalRows); err != nil {
		ms.log.Warnf("查询总行数失败: %v", err)
	} else if totalRows > int64(ms.maxRows) {
		// 删除最旧的数据
		excessRows := totalRows - int64(ms.maxRows)
		deleteOldSQL := `
		DELETE FROM process_metrics 
		WHERE id IN (
			SELECT id FROM process_metrics 
			ORDER BY timestamp ASC 
			LIMIT ?
		)`
		result, err := ms.db.Exec(deleteOldSQL, excessRows)
		if err != nil {
			ms.log.Warnf("删除超量数据失败: %v", err)
		} else {
			extraDeleted, _ := result.RowsAffected()
			ms.log.Infof("清理完成: 删除了 %d 条过期数据，额外删除了 %d 条超量数据", deletedCount, extraDeleted)
		}
	} else {
		ms.log.Infof("清理完成: 删除了 %d 条过期数据，当前总行数: %d", deletedCount, totalRows)
	}

	// 执行 VACUUM 优化数据库（仅在删除大量数据后执行，避免频繁 VACUUM 导致 CPU 暴涨）
	// VACUUM 会锁定数据库并消耗大量 CPU，所以只在删除超过 100 条数据时才执行
	if deletedCount > 100 {
		ms.log.Infof("删除数据较多 (%d 条)，执行 VACUUM 优化数据库", deletedCount)
		// 先尝试使用更轻量的 PRAGMA optimize（SQLite 3.18+）
		// 如果失败或数据量很大，再使用 VACUUM
		if _, err := ms.db.Exec("PRAGMA optimize"); err != nil {
			ms.log.Debugf("PRAGMA optimize 失败，使用 VACUUM: %v", err)
			// 使用 VACUUM，但记录警告，因为这会消耗 CPU
			ms.log.Warn("执行 VACUUM 操作，可能会暂时增加 CPU 使用率")
			if _, err := ms.db.Exec("VACUUM"); err != nil {
				ms.log.Warnf("执行 VACUUM 失败: %v", err)
			} else {
				ms.log.Info("VACUUM 操作完成")
			}
		} else {
			ms.log.Debug("使用 PRAGMA optimize 完成轻量优化")
		}
	} else {
		// 删除数据较少，只执行轻量优化
		if _, err := ms.db.Exec("PRAGMA optimize"); err != nil {
			ms.log.Debugf("PRAGMA optimize 失败: %v", err)
		}
	}

	return nil
}

// cleanupLoop 清理循环（每天凌晨3点执行）
func (ms *MetricsStorage) cleanupLoop() {
	// 计算到下一个凌晨3点的时间
	now := time.Now()
	nextRun := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())
	if nextRun.Before(now) {
		nextRun = nextRun.AddDate(0, 0, 1)
	}

	// 等待到第一次执行时间
	time.Sleep(time.Until(nextRun))

	// 立即执行一次
	ms.CleanupOldData()

	// 之后每24小时执行一次
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ms.CleanupOldData()
		case <-ms.stopChan:
			ms.log.Info("清理任务已停止")
			return
		}
	}
}

// GetMetrics 查询历史指标数据
// 优化：对 5min/15min/daily 使用 SQL 层聚合，避免拉取全量 1min 数据再内存聚合，显著减少数据传输和耗时
func (ms *MetricsStorage) GetMetrics(startTime, endTime time.Time, granularity string) (*MetricsQueryResult, error) {
	if !ms.enabled {
		return nil, fmt.Errorf("指标存储未启用")
	}

	// 如果 granularity 为 "auto"，根据时间范围自动选择
	if granularity == "auto" {
		duration := endTime.Sub(startTime)
		if duration <= 24*time.Hour {
			// 1天内，使用1分钟粒度
			granularity = "1min"
		} else if duration <= 7*24*time.Hour {
			// 7天内，使用5分钟粒度
			granularity = "5min"
		} else {
			// 超过7天，使用15分钟粒度
			granularity = "15min"
		}
	}

	// 使用 SQL 层聚合：直接返回聚合结果，避免拉取 1 万+ 行再内存聚合
	if granularity == "5min" || granularity == "15min" || granularity == "daily" {
		return ms.getMetricsWithSQLAggregation(startTime, endTime, granularity)
	}

	// 1min、all：直接查询
	var querySQL string
	var rows *sql.Rows
	var err error

	startStr := startTime.Format("2006-01-02 15:04:05")
	endStr := endTime.Format("2006-01-02 15:04:05")

	if granularity == "all" {
		querySQL = `
		SELECT id, timestamp, granularity, cpu_percent, memory_mb, memory_percent, sample_count, created_at
		FROM process_metrics
		WHERE timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp ASC`
		rows, err = ms.db.Query(querySQL, startStr, endStr)
	} else {
		querySQL = `
		SELECT id, timestamp, granularity, cpu_percent, memory_mb, memory_percent, sample_count, created_at
		FROM process_metrics
		WHERE timestamp >= ? AND timestamp <= ? AND granularity = ?
		ORDER BY timestamp ASC`
		rows, err = ms.db.Query(querySQL, startStr, endStr, granularity)
	}

	if err != nil {
		return nil, fmt.Errorf("查询指标数据失败: %v", err)
	}
	defer rows.Close()

	var metrics []ProcessMetric
	for rows.Next() {
		var metric ProcessMetric
		var timestampStr string
		var timestampTime time.Time

		if err := rows.Scan(
			&metric.ID,
			&timestampStr,
			&metric.Granularity,
			&metric.CPUPercent,
			&metric.MemoryMB,
			&metric.MemoryPercent,
			&metric.SampleCount,
			&metric.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("扫描指标数据失败: %v", err)
		}

		timestampTime, err = ms.parseTimestamp(timestampStr)
		if err != nil {
			ms.log.Warnf("解析时间戳失败: %v, 原始值: %s", err, timestampStr)
			continue
		}
		metric.Timestamp = timestampTime
		metrics = append(metrics, metric)
	}

	// 计算汇总信息
	var totalCPU, totalMemoryMB float64
	var maxCPU, maxMemoryMB float64
	totalSamples := len(metrics)

	for _, metric := range metrics {
		totalCPU += metric.CPUPercent
		totalMemoryMB += metric.MemoryMB
		if metric.CPUPercent > maxCPU {
			maxCPU = metric.CPUPercent
		}
		if metric.MemoryMB > maxMemoryMB {
			maxMemoryMB = metric.MemoryMB
		}
	}

	summary := MetricsQuerySummary{
		TotalSamples: totalSamples,
		MaxCPU:       maxCPU,
		MaxMemoryMB:  maxMemoryMB,
	}

	if totalSamples > 0 {
		summary.AvgCPU = totalCPU / float64(totalSamples)
		summary.AvgMemoryMB = totalMemoryMB / float64(totalSamples)
	}

	return &MetricsQueryResult{
		Data:    metrics,
		Summary: summary,
	}, nil
}

// parseTimestamp 解析 SQLite 返回的时间戳
func (ms *MetricsStorage) parseTimestamp(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// getMetricsWithSQLAggregation 使用 SQL GROUP BY 聚合，避免拉取全量 1min 数据
func (ms *MetricsStorage) getMetricsWithSQLAggregation(startTime, endTime time.Time, granularity string) (*MetricsQueryResult, error) {
	startStr := startTime.Format("2006-01-02 15:04:05")
	endStr := endTime.Format("2006-01-02 15:04:05")

	var groupExpr string
	switch granularity {
	case "5min":
		groupExpr = "strftime('%s', timestamp) / 300"
	case "15min":
		groupExpr = "strftime('%s', timestamp) / 900"
	case "daily":
		groupExpr = "date(timestamp)"
	default:
		return nil, fmt.Errorf("不支持的聚合粒度: %s", granularity)
	}

	querySQL := fmt.Sprintf(`
		SELECT
			min(timestamp) as timestamp,
			? as granularity,
			avg(cpu_percent) as cpu_percent,
			avg(memory_mb) as memory_mb,
			avg(memory_percent) as memory_percent,
			count(*) as sample_count
		FROM process_metrics
		WHERE timestamp >= ? AND timestamp <= ? AND granularity = '1min'
		GROUP BY %s
		ORDER BY timestamp ASC`, groupExpr)

	rows, err := ms.db.Query(querySQL, granularity, startStr, endStr)
	if err != nil {
		return nil, fmt.Errorf("查询聚合指标失败: %v", err)
	}
	defer rows.Close()

	var metrics []ProcessMetric
	for rows.Next() {
		var metric ProcessMetric
		var timestampStr string

		if err := rows.Scan(
			&timestampStr,
			&metric.Granularity,
			&metric.CPUPercent,
			&metric.MemoryMB,
			&metric.MemoryPercent,
			&metric.SampleCount,
		); err != nil {
			return nil, fmt.Errorf("扫描聚合数据失败: %v", err)
		}

		metric.Timestamp, err = ms.parseTimestamp(timestampStr)
		if err != nil {
			ms.log.Warnf("解析时间戳失败: %v, 原始值: %s", err, timestampStr)
			continue
		}
		metrics = append(metrics, metric)
	}

	var totalCPU, totalMemoryMB float64
	var maxCPU, maxMemoryMB float64
	totalSamples := len(metrics)
	for _, metric := range metrics {
		totalCPU += metric.CPUPercent
		totalMemoryMB += metric.MemoryMB
		if metric.CPUPercent > maxCPU {
			maxCPU = metric.CPUPercent
		}
		if metric.MemoryMB > maxMemoryMB {
			maxMemoryMB = metric.MemoryMB
		}
	}

	summary := MetricsQuerySummary{
		TotalSamples: totalSamples,
		MaxCPU:       maxCPU,
		MaxMemoryMB:  maxMemoryMB,
	}
	if totalSamples > 0 {
		summary.AvgCPU = totalCPU / float64(totalSamples)
		summary.AvgMemoryMB = totalMemoryMB / float64(totalSamples)
	}

	return &MetricsQueryResult{
		Data:    metrics,
		Summary: summary,
	}, nil
}

// aggregateMetrics 聚合指标数据到指定粒度（保留用于兼容，现优先使用 SQL 聚合）
func (ms *MetricsStorage) aggregateMetrics(rawMetrics []ProcessMetric, targetGranularity string) []ProcessMetric {
	if len(rawMetrics) == 0 {
		return nil
	}

	var intervalMinutes int
	switch targetGranularity {
	case "5min":
		intervalMinutes = 5
	case "15min":
		intervalMinutes = 15
	case "daily":
		intervalMinutes = 24 * 60 // 一天
	default:
		return rawMetrics
	}

	// 使用map来存储聚合后的数据，key是时间对齐后的时间戳
	aggregatedMap := make(map[time.Time]*ProcessMetric)

	for _, raw := range rawMetrics {
		var alignedTime time.Time
		if targetGranularity == "daily" {
			// 对齐到当天00:00:00
			alignedTime = time.Date(raw.Timestamp.Year(), raw.Timestamp.Month(), raw.Timestamp.Day(), 0, 0, 0, 0, raw.Timestamp.Location())
		} else {
			// 对齐到指定分钟间隔的边界
			minutes := raw.Timestamp.Minute()
			alignedMinutes := (minutes / intervalMinutes) * intervalMinutes
			alignedTime = time.Date(raw.Timestamp.Year(), raw.Timestamp.Month(), raw.Timestamp.Day(),
				raw.Timestamp.Hour(), alignedMinutes, 0, 0, raw.Timestamp.Location())
		}

		if agg, exists := aggregatedMap[alignedTime]; exists {
			// 聚合：累积总和（SampleCount存储累积的样本数）
			// 使用累积总和而不是累积平均值，避免数值爆炸
			// CPUPercent等字段暂时存储累积的总和，最后再除以样本数
			agg.CPUPercent += raw.CPUPercent
			agg.MemoryMB += raw.MemoryMB
			agg.MemoryPercent += raw.MemoryPercent
			agg.SampleCount++
		} else {
			// 创建新的聚合点 - 直接存储原始值（只有一个样本时）
			aggregatedMap[alignedTime] = &ProcessMetric{
				ID:            0,
				Timestamp:     alignedTime,
				Granularity:   targetGranularity,
				CPUPercent:    raw.CPUPercent,
				MemoryMB:      raw.MemoryMB,
				MemoryPercent: raw.MemoryPercent,
				SampleCount:   1,
				CreatedAt:     raw.CreatedAt,
			}
		}
	}

	// 转换为切片并排序
	// 将累积的总和转换为平均值
	result := make([]ProcessMetric, 0, len(aggregatedMap))
	for _, agg := range aggregatedMap {
		if agg.SampleCount > 1 {
			// 多个样本：将累积的总和除以样本数得到平均值
			metric := *agg
			metric.CPUPercent = agg.CPUPercent / float64(agg.SampleCount)
			metric.MemoryMB = agg.MemoryMB / float64(agg.SampleCount)
			metric.MemoryPercent = agg.MemoryPercent / float64(agg.SampleCount)
			result = append(result, metric)
		} else {
			// 单个样本：直接使用
			result = append(result, *agg)
		}
	}

	// 按时间排序
	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.Before(result[j].Timestamp)
	})

	return result
}
