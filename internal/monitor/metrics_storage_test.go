package monitor

import (
	"os"
	"testing"
	"time"
)

func TestGetMetricsWithSQLAggregation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "metrics_storage_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storage, err := NewMetricsStorage(MetricsStorageOptions{
		Enabled:            true,
		DataDir:            tmpDir,
		SamplingInterval:   time.Minute,
		RetentionDays:      7,
		DetailRetentionDays: 3,
		MaxRows:            100000,
	})
	if err != nil {
		t.Fatalf("创建 MetricsStorage 失败: %v", err)
	}
	defer storage.Stop()

	// 插入 15 条 1min 数据（模拟 15 分钟，5min 聚合后应得 3 条）
	baseTime := time.Now().Truncate(time.Minute).Add(-15 * time.Minute)
	for i := 0; i < 15; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Minute)
		_, err := storage.db.Exec(`
			INSERT OR REPLACE INTO process_metrics 
			(timestamp, granularity, cpu_percent, memory_mb, memory_percent, sample_count, created_at)
			VALUES (?, '1min', ?, ?, ?, 1, CURRENT_TIMESTAMP)`,
			ts.Format("2006-01-02 15:04:05"), 10.0+float64(i), 100.0+float64(i), 5.0+float64(i)*0.1)
		if err != nil {
			t.Fatalf("插入数据失败: %v", err)
		}
	}

	// 查询 5min 聚合结果
	result, err := storage.GetMetrics(baseTime, baseTime.Add(20*time.Minute), "5min")
	if err != nil {
		t.Fatalf("GetMetrics 失败: %v", err)
	}

	// 15 条 1min -> 5min 聚合应远少于 15 条（验证 SQL 聚合生效）
	if len(result.Data) >= 15 {
		t.Errorf("SQL 聚合应减少行数，15 条 1min 聚合后应 < 15，实际 %d 条", len(result.Data))
	}
	if len(result.Data) < 1 {
		t.Errorf("应至少返回 1 条聚合数据，实际 %d 条", len(result.Data))
	}
	if result.Summary.TotalSamples != len(result.Data) {
		t.Errorf("TotalSamples 应与 Data 长度一致: %d vs %d", result.Summary.TotalSamples, len(result.Data))
	}
}
