package statistics

import (
	"sort"
	"sync"
	"time"
)

// FunnelModel 漏斗模型，用于过滤高频访问统计
type FunnelModel struct {
	mu             sync.RWMutex
	minOccurrences int           // 最小出现次数阈值
	minTimeSpan    time.Duration // 最小时间跨度
	maxEntries     int           // 最大保留条目数
	decayFactor    float64       // 衰减因子，用于降低旧数据的权重
}

// FunnelEntry 漏斗条目
type FunnelEntry struct {
	Key           string    // 键（如IP、User-Agent等）
	Count         int       // 出现次数
	FirstSeen     time.Time // 首次出现时间
	LastSeen      time.Time // 最后出现时间
	WeightedScore float64   // 加权分数
}

// NewFunnelModel 创建新的漏斗模型
func NewFunnelModel(minOccurrences int, minTimeSpan time.Duration, maxEntries int) *FunnelModel {
	return &FunnelModel{
		minOccurrences: minOccurrences,
		minTimeSpan:    minTimeSpan,
		maxEntries:     maxEntries,
		decayFactor:    0.1, // 默认衰减因子
	}
}

// Filter 过滤数据，返回符合条件的高频条目
func (fm *FunnelModel) Filter(entries map[string]*FunnelEntry, now time.Time) []*FunnelEntry {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var filtered []*FunnelEntry

	for _, entry := range entries {
		// 检查最小出现次数
		if entry.Count < fm.minOccurrences {
			continue
		}

		// 检查时间跨度（必须存在一定时间才能进入候选列表）
		timeSpan := entry.LastSeen.Sub(entry.FirstSeen)
		if timeSpan < fm.minTimeSpan {
			continue
		}

		// 计算加权分数，考虑频率、时间跨度和时间衰减
		timeSinceLastSeen := now.Sub(entry.LastSeen)
		decayWeight := 1.0 - (timeSinceLastSeen.Hours()*fm.decayFactor)/24.0 // 按天衰减
		if decayWeight < 0.1 {
			decayWeight = 0.1 // 最小权重
		}

		// 分数 = 出现次数 * 时间跨度权重 * 衰减权重
		timeSpanWeight := float64(timeSpan.Hours()) / 24.0 // 按天计算权重
		if timeSpanWeight > 7.0 {
			timeSpanWeight = 7.0 // 最大7天权重
		}

		entry.WeightedScore = float64(entry.Count) * (1.0 + timeSpanWeight*0.1) * decayWeight
		filtered = append(filtered, entry)
	}

	// 按加权分数排序
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].WeightedScore > filtered[j].WeightedScore
	})

	// 限制返回条目数量
	if len(filtered) > fm.maxEntries {
		filtered = filtered[:fm.maxEntries]
	}

	return filtered
}

// UpdateEntry 更新条目信息
func (fm *FunnelModel) UpdateEntry(entries map[string]*FunnelEntry, key string, timestamp time.Time) {
	if entry, exists := entries[key]; exists {
		entry.Count++
		entry.LastSeen = timestamp
	} else {
		entries[key] = &FunnelEntry{
			Key:       key,
			Count:     1,
			FirstSeen: timestamp,
			LastSeen:  timestamp,
		}
	}
}

// CleanupOldEntries 清理过期条目
func (fm *FunnelModel) CleanupOldEntries(entries map[string]*FunnelEntry, maxAge time.Duration, now time.Time) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	for key, entry := range entries {
		if now.Sub(entry.LastSeen) > maxAge {
			delete(entries, key)
		}
	}
}

// SetDecayFactor 设置衰减因子
func (fm *FunnelModel) SetDecayFactor(factor float64) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.decayFactor = factor
}

// SetThresholds 设置阈值参数
func (fm *FunnelModel) SetThresholds(minOccurrences int, minTimeSpan time.Duration, maxEntries int) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.minOccurrences = minOccurrences
	fm.minTimeSpan = minTimeSpan
	fm.maxEntries = maxEntries
}

// GetStats 获取漏斗模型统计信息
func (fm *FunnelModel) GetStats() map[string]interface{} {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	return map[string]interface{}{
		"min_occurrences": fm.minOccurrences,
		"min_time_span":   fm.minTimeSpan.String(),
		"max_entries":     fm.maxEntries,
		"decay_factor":    fm.decayFactor,
	}
}
