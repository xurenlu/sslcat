package web

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// CacheStatsResponse 缓存统计响应
type CacheStatsResponse struct {
	Caches []CacheStats `json:"caches"`
	Total  TotalStats   `json:"total"`
}

// CacheStats 单个缓存统计
type CacheStats struct {
	Name       string  `json:"name"`
	Type       string  `json:"type"` // compression, image_optimization, etc.
	Entries    int     `json:"entries"`
	MaxEntries int     `json:"max_entries"`
	TotalSize  int64   `json:"total_size"`
	MaxSize    int64   `json:"max_size"`
	Hits       uint64  `json:"hits"`
	Misses     uint64  `json:"misses"`
	HitRate    string  `json:"hit_rate"`
	Evictions  uint64  `json:"evictions"`
	Expired    uint64  `json:"expired"`
	UsageRate  float64 `json:"usage_rate"` // 使用率百分比
}

// TotalStats 总计统计
type TotalStats struct {
	TotalCaches    int     `json:"total_caches"`
	TotalEntries   int     `json:"total_entries"`
	TotalSize      int64   `json:"total_size"`
	TotalSizeMB    float64 `json:"total_size_mb"`
	TotalHits      uint64  `json:"total_hits"`
	TotalMisses    uint64  `json:"total_misses"`
	OverallHitRate string  `json:"overall_hit_rate"`
}

// handleCacheStats 处理缓存统计请求
// GET /sslcat-panel/api/cache/stats
func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var caches []CacheStats
	var totalEntries int
	var totalSize int64
	var totalHits uint64
	var totalMisses uint64

	// 1. 压缩缓存统计
	if s.compressionCache != nil {
		stats := s.compressionCache.Stats()
		cacheStats := CacheStats{
			Name:       getString(stats, "name", "compression"),
			Type:       "compression",
			Entries:    getInt(stats, "entries", 0),
			MaxEntries: getInt(stats, "max_entries", 0),
			TotalSize:  getInt64(stats, "total_size", 0),
			MaxSize:    getInt64(stats, "max_size", 0),
			Hits:       getUint64(stats, "hits", 0),
			Misses:     getUint64(stats, "misses", 0),
			HitRate:    getString(stats, "hit_rate", "0%"),
			Evictions:  getUint64(stats, "evictions", 0),
			Expired:    getUint64(stats, "expired", 0),
		}
		if cacheStats.MaxSize > 0 {
			cacheStats.UsageRate = float64(cacheStats.TotalSize) / float64(cacheStats.MaxSize) * 100
		}
		caches = append(caches, cacheStats)

		totalEntries += cacheStats.Entries
		totalSize += cacheStats.TotalSize
		totalHits += cacheStats.Hits
		totalMisses += cacheStats.Misses
	}

	// 2. 图片优化缓存统计
	if s.imageOptimizer != nil && s.imageOptimizer.Config.CacheEnabled {
		imgStats := s.imageOptimizer.GetStats()

		// 从 cache_manager 中获取详细信息
		var cacheStats CacheStats
		if cacheManager, ok := imgStats["cache_manager"].(map[string]interface{}); ok {
			cacheStats = CacheStats{
				Name:       getString(cacheManager, "name", "image_optimization"),
				Type:       "image_optimization",
				Entries:    getInt(cacheManager, "entries", 0),
				MaxEntries: getInt(cacheManager, "max_entries", 0),
				TotalSize:  getInt64(cacheManager, "total_size", 0),
				MaxSize:    getInt64(cacheManager, "max_size", 0),
				Hits:       getUint64(cacheManager, "hits", 0),
				Misses:     getUint64(cacheManager, "misses", 0),
				HitRate:    getString(cacheManager, "hit_rate", "0%"),
				Evictions:  getUint64(cacheManager, "evictions", 0),
				Expired:    getUint64(cacheManager, "expired", 0),
			}
		} else {
			// 降级使用旧统计
			cacheStats = CacheStats{
				Name:      "image_optimization",
				Type:      "image_optimization",
				Entries:   getInt(imgStats, "cache_items", 0),
				TotalSize: getInt64(imgStats, "cache_size_bytes", 0),
				Hits:      getUint64(imgStats, "cache_hits", 0),
				Misses:    getUint64(imgStats, "cache_misses", 0),
			}
			// 计算命中率
			total := cacheStats.Hits + cacheStats.Misses
			if total > 0 {
				hitRate := float64(cacheStats.Hits) / float64(total) * 100
				cacheStats.HitRate = formatFloat(hitRate) + "%"
			}
		}

		if cacheStats.MaxSize > 0 {
			cacheStats.UsageRate = float64(cacheStats.TotalSize) / float64(cacheStats.MaxSize) * 100
		}

		caches = append(caches, cacheStats)

		totalEntries += cacheStats.Entries
		totalSize += cacheStats.TotalSize
		totalHits += cacheStats.Hits
		totalMisses += cacheStats.Misses
	}

	// 计算总体命中率
	overallHitRate := "0%"
	totalRequests := totalHits + totalMisses
	if totalRequests > 0 {
		rate := float64(totalHits) / float64(totalRequests) * 100
		overallHitRate = formatFloat(rate) + "%"
	}

	response := CacheStatsResponse{
		Caches: caches,
		Total: TotalStats{
			TotalCaches:    len(caches),
			TotalEntries:   totalEntries,
			TotalSize:      totalSize,
			TotalSizeMB:    float64(totalSize) / 1024 / 1024,
			TotalHits:      totalHits,
			TotalMisses:    totalMisses,
			OverallHitRate: overallHitRate,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleCacheClear 清空指定缓存
// POST /sslcat-panel/api/cache/clear?type=compression|image
func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cacheType := r.URL.Query().Get("type")

	switch cacheType {
	case "compression":
		if s.compressionCache != nil {
			s.compressionCache.Clear()
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "success",
				"message": "Compression cache cleared",
			})
		} else {
			http.Error(w, "Compression cache not available", http.StatusNotFound)
		}
	case "image":
		if s.imageOptimizer != nil {
			s.imageOptimizer.ClearCache()
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "success",
				"message": "Image cache cleared",
			})
		} else {
			http.Error(w, "Image optimizer not available", http.StatusNotFound)
		}
	case "all":
		cleared := []string{}
		if s.compressionCache != nil {
			s.compressionCache.Clear()
			cleared = append(cleared, "compression")
		}
		if s.imageOptimizer != nil {
			s.imageOptimizer.ClearCache()
			cleared = append(cleared, "image")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"message": "All caches cleared",
			"cleared": cleared,
		})
	default:
		http.Error(w, "Invalid cache type. Use: compression, image, or all", http.StatusBadRequest)
	}
}

// 辅助函数
func getString(m map[string]interface{}, key, defaultValue string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultValue
}

func getInt(m map[string]interface{}, key string, defaultValue int) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case int:
			return val
		case int64:
			return int(val)
		case float64:
			return int(val)
		}
	}
	return defaultValue
}

func getInt64(m map[string]interface{}, key string, defaultValue int64) int64 {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case int64:
			return val
		case int:
			return int64(val)
		case float64:
			return int64(val)
		}
	}
	return defaultValue
}

func getUint64(m map[string]interface{}, key string, defaultValue uint64) uint64 {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case uint64:
			return val
		case int64:
			return uint64(val)
		case int:
			return uint64(val)
		case float64:
			return uint64(val)
		}
	}
	return defaultValue
}

func formatFloat(f float64) string {
	if f == float64(int(f)) {
		return fmt.Sprintf("%.0f", f)
	}
	return fmt.Sprintf("%.2f", f)
}
