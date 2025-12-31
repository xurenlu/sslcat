package report

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

// ReportScheduler 报告调度器
type ReportScheduler struct {
	generator *ReportGenerator
	config    *config.ReportConfig
	log       *logrus.Entry
	stopChan  chan struct{}
}

// NewReportScheduler 创建报告调度器
func NewReportScheduler(generator *ReportGenerator, cfg *config.ReportConfig) *ReportScheduler {
	return &ReportScheduler{
		generator: generator,
		config:    cfg,
		log: logrus.WithFields(logrus.Fields{
			"component": "report_scheduler",
		}),
		stopChan: make(chan struct{}),
	}
}

// Start 启动调度器
func (rs *ReportScheduler) Start() {
	if rs.config == nil || !rs.config.Enabled {
		rs.log.Info("报告生成已禁用，调度器不启动")
		return
	}

	rs.log.Info("报告调度器已启动")

	// 启动日报调度
	if rs.config.Daily.Enabled {
		go rs.scheduleDailyReport()
	}

	// 启动周报调度
	if rs.config.Weekly.Enabled {
		go rs.scheduleWeeklyReport()
	}

	// 启动月报调度
	if rs.config.Monthly.Enabled {
		go rs.scheduleMonthlyReport()
	}
}

// Stop 停止调度器
func (rs *ReportScheduler) Stop() {
	rs.log.Info("停止报告调度器")
	close(rs.stopChan)
}

// scheduleDailyReport 调度日报
func (rs *ReportScheduler) scheduleDailyReport() {
	// 解析时间
	reportTime, err := rs.parseTime(rs.config.Daily.Time)
	if err != nil {
		rs.log.Errorf("解析日报时间失败: %v，使用默认时间 02:00", err)
		reportTime = time.Date(0, 0, 0, 2, 0, 0, 0, time.Local)
	}

	// 计算到下一个报告时间
	now := time.Now()
	nextRun := time.Date(now.Year(), now.Month(), now.Day(), reportTime.Hour(), reportTime.Minute(), 0, 0, now.Location())
	if nextRun.Before(now) {
		nextRun = nextRun.AddDate(0, 0, 1)
	}

	// 等待到第一次执行时间
	waitDuration := time.Until(nextRun)
	rs.log.Infof("日报将在 %s 后首次执行（%s）", waitDuration, nextRun.Format("2006-01-02 15:04:05"))
	time.Sleep(waitDuration)

	// 立即执行一次
	rs.generateDailyReport()

	// 之后每24小时执行一次
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rs.generateDailyReport()
		case <-rs.stopChan:
			rs.log.Info("日报调度已停止")
			return
		}
	}
}

// scheduleWeeklyReport 调度周报
func (rs *ReportScheduler) scheduleWeeklyReport() {
	// 解析时间
	reportTime, err := rs.parseTime(rs.config.Weekly.Time)
	if err != nil {
		rs.log.Errorf("解析周报时间失败: %v，使用默认时间 02:00", err)
		reportTime = time.Date(0, 0, 0, 2, 0, 0, 0, time.Local)
	}

	// 解析星期几
	weekday := rs.parseWeekday(rs.config.Weekly.Day)

	// 计算到下一个报告时间
	now := time.Now()
	daysUntilWeekday := int(weekday - now.Weekday())
	if daysUntilWeekday < 0 {
		daysUntilWeekday += 7
	} else if daysUntilWeekday == 0 {
		// 如果是今天，检查时间是否已过
		todayRun := time.Date(now.Year(), now.Month(), now.Day(), reportTime.Hour(), reportTime.Minute(), 0, 0, now.Location())
		if todayRun.Before(now) {
			daysUntilWeekday = 7
		}
	}

	nextRun := time.Date(now.Year(), now.Month(), now.Day(), reportTime.Hour(), reportTime.Minute(), 0, 0, now.Location())
	nextRun = nextRun.AddDate(0, 0, daysUntilWeekday)

	// 等待到第一次执行时间
	waitDuration := time.Until(nextRun)
	rs.log.Infof("周报将在 %s 后首次执行（%s）", waitDuration, nextRun.Format("2006-01-02 15:04:05"))
	time.Sleep(waitDuration)

	// 立即执行一次
	rs.generateWeeklyReport()

	// 之后每周执行一次
	ticker := time.NewTicker(7 * 24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rs.generateWeeklyReport()
		case <-rs.stopChan:
			rs.log.Info("周报调度已停止")
			return
		}
	}
}

// scheduleMonthlyReport 调度月报
func (rs *ReportScheduler) scheduleMonthlyReport() {
	// 解析时间
	reportTime, err := rs.parseTime(rs.config.Monthly.Time)
	if err != nil {
		rs.log.Errorf("解析月报时间失败: %v，使用默认时间 02:00", err)
		reportTime = time.Date(0, 0, 0, 2, 0, 0, 0, time.Local)
	}

	// 解析日期（每月几号）
	day := rs.config.Monthly.Day
	if day < 1 || day > 31 {
		day = 1
	}

	// 计算到下一个报告时间
	now := time.Now()
	nextRun := time.Date(now.Year(), now.Month(), day, reportTime.Hour(), reportTime.Minute(), 0, 0, now.Location())

	// 如果这个月的日期已过，则下个月
	if nextRun.Before(now) {
		nextRun = nextRun.AddDate(0, 1, 0)
		// 处理月份天数不足的情况（如2月31日）
		for nextRun.Day() != day {
			nextRun = nextRun.AddDate(0, 0, -1)
		}
	}

	// 等待到第一次执行时间
	waitDuration := time.Until(nextRun)
	rs.log.Infof("月报将在 %s 后首次执行（%s）", waitDuration, nextRun.Format("2006-01-02 15:04:05"))
	time.Sleep(waitDuration)

	// 立即执行一次
	rs.generateMonthlyReport()

	// 之后每月执行一次（使用定时器，但需要手动计算下个月的时间）
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	lastMonth := nextRun.Month()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			// 检查是否到了新的月份
			if now.Month() != lastMonth && now.Day() == day {
				rs.generateMonthlyReport()
				lastMonth = now.Month()
			}
		case <-rs.stopChan:
			rs.log.Info("月报调度已停止")
			return
		}
	}
}

// generateDailyReport 生成日报
func (rs *ReportScheduler) generateDailyReport() {
	now := time.Now()
	startTime := time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, now.Location())
	endTime := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	rs.log.Info("开始生成日报")
	if err := rs.generator.GenerateReport(ReportTypeDaily, startTime, endTime); err != nil {
		rs.log.Errorf("生成日报失败: %v", err)
	}
}

// generateWeeklyReport 生成周报
func (rs *ReportScheduler) generateWeeklyReport() {
	now := time.Now()
	// 计算上周一
	weekday := int(now.Weekday())
	if weekday == 0 {
		weekday = 7 // 周日算作7
	}
	daysSinceMonday := weekday - 1
	lastMonday := now.AddDate(0, 0, -daysSinceMonday-7)
	startTime := time.Date(lastMonday.Year(), lastMonday.Month(), lastMonday.Day(), 0, 0, 0, 0, now.Location())
	endTime := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	rs.log.Info("开始生成周报")
	if err := rs.generator.GenerateReport(ReportTypeWeekly, startTime, endTime); err != nil {
		rs.log.Errorf("生成周报失败: %v", err)
	}
}

// generateMonthlyReport 生成月报
func (rs *ReportScheduler) generateMonthlyReport() {
	now := time.Now()
	// 计算上个月的第一天
	lastMonth := now.AddDate(0, -1, 0)
	startTime := time.Date(lastMonth.Year(), lastMonth.Month(), 1, 0, 0, 0, 0, now.Location())
	endTime := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	rs.log.Info("开始生成月报")
	if err := rs.generator.GenerateReport(ReportTypeMonthly, startTime, endTime); err != nil {
		rs.log.Errorf("生成月报失败: %v", err)
	}
}

// parseTime 解析时间字符串（格式: "HH:MM"）
func (rs *ReportScheduler) parseTime(timeStr string) (time.Time, error) {
	if timeStr == "" {
		timeStr = "02:00"
	}

	layout := "15:04"
	t, err := time.Parse(layout, timeStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("时间格式错误: %w", err)
	}

	return t, nil
}

// parseWeekday 解析星期几
func (rs *ReportScheduler) parseWeekday(dayStr string) time.Weekday {
	switch dayStr {
	case "monday", "mon", "1":
		return time.Monday
	case "tuesday", "tue", "2":
		return time.Tuesday
	case "wednesday", "wed", "3":
		return time.Wednesday
	case "thursday", "thu", "4":
		return time.Thursday
	case "friday", "fri", "5":
		return time.Friday
	case "saturday", "sat", "6":
		return time.Saturday
	case "sunday", "sun", "0", "7":
		return time.Sunday
	default:
		return time.Monday // 默认周一
	}
}

