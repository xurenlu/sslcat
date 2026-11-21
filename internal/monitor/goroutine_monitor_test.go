package monitor

import (
	"sync"
	"testing"
	"time"
)

// newTestGoroutineMonitor 构造一个已完成预热的监控器，便于直接驱动判定逻辑
func newTestGoroutineMonitor(baseline int) *GoroutineMonitor {
	gm := NewGoroutineMonitor(time.Minute)
	gm.baselineCount = baseline
	gm.baselineReady = true
	return gm
}

// steadyHistory 生成在 base 附近上下抖动、但整体不增长的样本
func steadyHistory(base int, n int) []int {
	history := make([]int, 0, n)
	offsets := []int{0, 12, -8, 5, -14, 9, -3, 15, -11, 2}
	for i := 0; i < n; i++ {
		history = append(history, base+offsets[i%len(offsets)])
	}
	return history
}

// risingHistory 生成持续增长的样本
func risingHistory(base int, n int, step int) []int {
	history := make([]int, 0, n)
	for i := 0; i < n; i++ {
		history = append(history, base+i*step)
	}
	return history
}

func TestGoroutineMonitorWarmupDefersBaseline(t *testing.T) {
	gm := NewGoroutineMonitor(time.Minute)

	if gm.baselineReady {
		t.Fatal("监控器创建时不应立即确定基线")
	}

	// 预热期内采样：只记录历史，不确定基线、不告警
	gm.startedAt = time.Now()
	gm.check()

	if gm.baselineReady {
		t.Error("预热期内不应确定基线")
	}
	if len(gm.history) != 1 {
		t.Errorf("预热期内应继续采样，history 长度 = %d, 期望 1", len(gm.history))
	}
	if gm.warningCount != 0 || gm.criticalCount != 0 {
		t.Errorf("预热期内不应产生告警: warning=%d, critical=%d", gm.warningCount, gm.criticalCount)
	}

	// 预热期结束后的第一次采样应确定基线
	gm.startedAt = time.Now().Add(-gm.warmupPeriod - time.Second)
	gm.check()

	if !gm.baselineReady {
		t.Fatal("预热期结束后应确定基线")
	}
	if gm.baselineCount <= 0 {
		t.Errorf("基线应为正数，实际 = %d", gm.baselineCount)
	}
}

func TestGoroutineMonitorBaselineUsesMedian(t *testing.T) {
	gm := NewGoroutineMonitor(time.Minute)
	gm.startedAt = time.Now().Add(-gm.warmupPeriod - time.Second)

	// 混入一个极端尖峰，中位数不应被带偏
	gm.history = []int{130, 135, 900, 132, 128}
	gm.check()

	if !gm.baselineReady {
		t.Fatal("预热期结束后应确定基线")
	}
	// check() 会把当前真实 goroutine 数也追加进 history，
	// 但中位数仍应落在样本主体附近，而不是被 900 拉高
	if gm.baselineCount > 200 {
		t.Errorf("基线被离群尖峰带偏: %d", gm.baselineCount)
	}
}

// 核心回归：稳态水位高于阈值，但没有持续上升趋势时不得告警。
// 这正是线上「基线取自空载、稳态被误报为泄漏」的场景。
func TestGoroutineMonitorSteadyStateDoesNotAlert(t *testing.T) {
	gm := newTestGoroutineMonitor(38) // 模拟线上空载基线
	gm.history = steadyHistory(140, 30)

	// 当前 145，超出基线 107（> warningThreshold 100），但趋势稳定
	result := gm.evaluateLocked(145, time.Now())

	if result.diff <= gm.warningThreshold {
		t.Fatalf("测试前提不成立：diff=%d 应超过警告阈值 %d", result.diff, gm.warningThreshold)
	}
	if result.trend != trendStable {
		t.Fatalf("稳态样本的趋势应为稳定，实际 = %s", result.trend)
	}
	if result.level != alertNone {
		t.Errorf("稳态波动不应告警，实际级别 = %v", result.level)
	}
	if gm.warningCount != 0 {
		t.Errorf("稳态波动不应累加告警计数，实际 = %d", gm.warningCount)
	}
}

// 真正的泄漏：持续上升且超过阈值，必须告警
func TestGoroutineMonitorSustainedRiseAlerts(t *testing.T) {
	gm := newTestGoroutineMonitor(100)
	gm.history = risingHistory(200, 30, 5)

	now := time.Now()
	var result goroutineCheckResult

	// 需要连续 sustainedRisingChecks 个周期上升才告警
	for i := 0; i < gm.sustainedRisingChecks; i++ {
		if result.level == alertWarning {
			t.Fatalf("第 %d 个周期就告警，应等待连续 %d 个上升周期", i, gm.sustainedRisingChecks)
		}
		result = gm.evaluateLocked(350, now)
	}

	if result.trend != trendRising {
		t.Fatalf("持续增长样本的趋势应为上升，实际 = %s", result.trend)
	}
	if result.level != alertWarning {
		t.Errorf("持续上升且超阈值时应告警，实际级别 = %v", result.level)
	}
	if result.streak < gm.sustainedRisingChecks {
		t.Errorf("连击数 = %d, 应至少为 %d", result.streak, gm.sustainedRisingChecks)
	}
}

// 趋势中断应清零连击数，避免零散的上升周期累积成告警
func TestGoroutineMonitorRisingStreakResets(t *testing.T) {
	gm := newTestGoroutineMonitor(100)

	gm.history = risingHistory(200, 30, 5)
	gm.evaluateLocked(350, time.Now())
	if gm.risingStreak != 1 {
		t.Fatalf("上升周期后连击数 = %d, 期望 1", gm.risingStreak)
	}

	gm.history = steadyHistory(200, 30)
	gm.evaluateLocked(350, time.Now())
	if gm.risingStreak != 0 {
		t.Errorf("趋势转为稳定后连击数应清零，实际 = %d", gm.risingStreak)
	}
}

// 严重阈值不要求趋势条件：绝对增量过大时立即告警
func TestGoroutineMonitorCriticalIgnoresTrend(t *testing.T) {
	gm := newTestGoroutineMonitor(100)
	gm.history = steadyHistory(700, 30)

	result := gm.evaluateLocked(700, time.Now())

	if result.trend != trendStable {
		t.Fatalf("测试前提不成立：趋势应为稳定，实际 = %s", result.trend)
	}
	if result.level != alertCritical {
		t.Errorf("超过严重阈值时应立即告警，实际级别 = %v", result.level)
	}
}

func TestGoroutineMonitorAlertCooldown(t *testing.T) {
	gm := newTestGoroutineMonitor(100)
	gm.history = steadyHistory(700, 30)

	now := time.Now()
	first := gm.evaluateLocked(700, now)
	if first.suppressed {
		t.Fatal("首次告警不应被抑制")
	}

	// 冷却窗口内重复命中：计数累加，但不输出日志
	second := gm.evaluateLocked(700, now.Add(time.Minute))
	if !second.suppressed {
		t.Error("冷却窗口内的重复告警应被抑制")
	}
	if gm.criticalCount != 2 {
		t.Errorf("被抑制的告警仍应计数，实际 = %d, 期望 2", gm.criticalCount)
	}

	// 冷却期满后恢复告警
	third := gm.evaluateLocked(700, now.Add(gm.alertCooldown+time.Second))
	if third.suppressed {
		t.Error("冷却期满后应恢复告警")
	}
}

func TestGoroutineMonitorTrendDetection(t *testing.T) {
	tests := []struct {
		name    string
		history []int
		want    string
	}{
		{"样本不足", []int{1, 2, 3}, trendInsufficient},
		{"稳态抖动", steadyHistory(140, 30), trendStable},
		{"持续上升", risingHistory(100, 30, 10), trendRising},
		{"持续下降", risingHistory(500, 30, -10), trendFalling},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := newTestGoroutineMonitor(100)
			gm.history = tt.history

			if got := gm.getTrend(); got != tt.want {
				t.Errorf("getTrend() = %s, 期望 %s", got, tt.want)
			}
		})
	}
}

func TestGoroutineMonitorResetBaseline(t *testing.T) {
	gm := newTestGoroutineMonitor(38)
	gm.currentCount = 150
	gm.warningCount = 7
	gm.criticalCount = 3
	gm.risingStreak = 5
	gm.lastAlertTime = time.Now()

	gm.ResetBaseline()

	if gm.baselineCount != 150 {
		t.Errorf("基线 = %d, 期望 150", gm.baselineCount)
	}
	if !gm.baselineReady {
		t.Error("手动重置后应视为已完成预热")
	}
	if gm.warningCount != 0 || gm.criticalCount != 0 {
		t.Errorf("重置后告警计数应清零: warning=%d, critical=%d", gm.warningCount, gm.criticalCount)
	}
	if gm.risingStreak != 0 {
		t.Errorf("重置后连击数应清零，实际 = %d", gm.risingStreak)
	}
	if !gm.lastAlertTime.IsZero() {
		t.Error("重置后应清除告警冷却时间")
	}
}

// check() 尚未执行时 currentCount 为 0，重置不得把基线置成 0
func TestGoroutineMonitorResetBaselineBeforeFirstCheck(t *testing.T) {
	gm := NewGoroutineMonitor(time.Minute)
	gm.ResetBaseline()

	if gm.baselineCount <= 0 {
		t.Errorf("首次检查前重置基线应实时采样，实际 = %d", gm.baselineCount)
	}
}

// GetStats 持读锁期间调用趋势计算，不得递归加锁导致死锁
func TestGoroutineMonitorGetStatsNoDeadlock(t *testing.T) {
	gm := newTestGoroutineMonitor(100)
	gm.history = steadyHistory(140, 30)

	done := make(chan map[string]interface{}, 1)
	go func() {
		done <- gm.GetStats()
	}()

	select {
	case stats := <-done:
		if _, ok := stats["trend"]; !ok {
			t.Error("统计中应包含 trend 字段")
		}
		if ready, ok := stats["baseline_ready"].(bool); !ok || !ready {
			t.Error("统计中应包含 baseline_ready 且为 true")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("GetStats 发生死锁")
	}
}

// GetStats 与 check 并发执行不应产生数据竞争（配合 -race 运行）
func TestGoroutineMonitorConcurrentAccess(t *testing.T) {
	gm := newTestGoroutineMonitor(100)
	gm.history = steadyHistory(140, 30)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				gm.check()
				gm.GetStats()
				gm.getTrend()
			}
		}()
	}
	wg.Wait()
}

// productionSteadyStateSamples 是 v2.5.0 生产节点连续 24 小时的真实 Goroutine 采样。
// 该节点经 pprof 核实无泄漏（上游连接池、日志 writer、常驻清理循环数量均正常），
// 但因基线取自空载状态（38），旧逻辑在这段时间里持续输出泄漏告警。
// 固化为回归测试，防止告警判定再次退化为「只看绝对差值」。
var productionSteadyStateSamples = []int{
	128, 112, 119, 130, 117, 102, 123, 118, 103, 123, 124, 115, 129, 125, 109,
	108, 116, 112, 131, 113, 111, 110, 109, 117, 117, 118, 109, 107, 105, 103,
	117, 113, 107, 106, 109, 103, 112, 120, 121, 114, 119, 133, 121, 124, 136,
	122, 134, 131, 128, 123, 129, 132, 125, 128, 122, 124, 118, 129, 131, 111,
	110, 124, 119, 108, 117, 107, 111, 122, 107, 119, 120, 115, 115, 133, 114,
	119, 111, 115, 110, 111, 118, 120, 119, 123, 131, 132, 125, 111, 114, 113,
	114, 116, 133, 128, 132, 135, 123, 122, 133, 126, 109, 116, 114, 105, 109,
	116, 120, 114, 110, 128, 121, 195, 129, 124, 122, 117, 115, 114, 128, 118,
	120, 126, 117, 121, 139, 123, 120, 200, 123, 126, 116, 121, 110, 121, 130,
	126, 131, 117, 116, 117, 124, 123, 118, 124, 111, 112, 111, 117, 117, 131,
	116, 110, 111, 112, 119, 109, 110, 118, 105, 115, 117, 115, 114, 112, 121,
	118, 119, 109, 162, 115, 122, 116, 167, 121, 123, 110, 117, 114, 121, 115,
	118, 122, 123, 111, 115, 112, 119, 115, 112, 117, 126, 127, 115, 109, 111,
	109, 118, 119, 113, 137, 115, 112, 117, 117, 119, 106, 120, 126, 115, 116,
	109, 115, 108, 115, 110, 120, 119, 108, 114, 109, 114, 114, 121, 119, 204,
	111, 115, 118, 113, 115, 120, 113, 118, 116, 116, 110, 113, 119, 204, 116,
	124, 126, 120, 117, 123, 116, 119, 114, 121, 118, 122, 118, 108, 117, 124,
	110, 112, 115, 127, 123, 140, 141, 134, 138, 143, 136, 143, 136, 143, 130,
	130, 140, 142, 147, 132, 159, 128, 127, 123, 124, 115, 147, 146, 149, 155,
	134, 130,
}

// 核心回归：把生产环境的真实采样序列完整喂给监控器，不得产生任何告警
func TestGoroutineMonitorProductionSamplesDoNotAlert(t *testing.T) {
	gm := NewGoroutineMonitor(time.Minute)
	// 预热期结束，让第一个样本即确定基线
	gm.startedAt = time.Now().Add(-gm.warmupPeriod - time.Second)

	now := time.Now()
	warnings, criticals := 0, 0
	for i, sample := range productionSteadyStateSamples {
		result := gm.checkSample(sample, now.Add(time.Duration(i)*time.Minute))
		switch result.level {
		case alertWarning:
			warnings++
		case alertCritical:
			criticals++
		}
	}

	if warnings != 0 || criticals != 0 {
		t.Errorf("生产稳态样本产生了误报: 警告=%d, 严重=%d (基线=%d)",
			warnings, criticals, gm.baselineCount)
	}

	// 基线应落在真实稳态水位附近，而不是空载值
	if gm.baselineCount < 100 || gm.baselineCount > 160 {
		t.Errorf("基线 = %d, 应落在稳态水位 100~160 区间内", gm.baselineCount)
	}
}

// 对照实验：同一份样本，若沿用「基线取自空载 + 只看绝对差值」的旧判定，
// 会产生大量告警。用于说明本次修复的实际效果。
func TestGoroutineMonitorLegacyLogicWouldAlertOnProductionSamples(t *testing.T) {
	const idleBaseline = 38 // 线上实测的空载基线

	legacyAlerts := 0
	for _, sample := range productionSteadyStateSamples {
		if sample-idleBaseline > 100 {
			legacyAlerts++
		}
	}

	if legacyAlerts == 0 {
		t.Fatal("测试前提不成立：旧逻辑应当在这份样本上产生告警")
	}
	t.Logf("旧逻辑在 %d 个样本中误报 %d 次；新逻辑误报 0 次",
		len(productionSteadyStateSamples), legacyAlerts)
}

func TestMedian(t *testing.T) {
	tests := []struct {
		name string
		nums []int
		want int
	}{
		{"空样本", nil, 0},
		{"单个样本", []int{42}, 42},
		{"奇数个", []int{130, 900, 135}, 135},
		{"偶数个", []int{130, 140, 150, 160}, 145},
		{"含离群值", []int{128, 130, 132, 135, 900}, 132},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := median(tt.nums); got != tt.want {
				t.Errorf("median(%v) = %d, 期望 %d", tt.nums, got, tt.want)
			}
		})
	}
}

// median 不得修改传入的切片（history 依赖原有顺序做趋势分析）
func TestMedianDoesNotMutateInput(t *testing.T) {
	nums := []int{130, 900, 128, 135}
	original := make([]int, len(nums))
	copy(original, nums)

	median(nums)

	for i := range nums {
		if nums[i] != original[i] {
			t.Fatalf("median 修改了输入切片: %v, 期望 %v", nums, original)
		}
	}
}
