package cache

import (
	"fmt"
	"testing"
	"time"
)

func TestBigCacheWrapper(t *testing.T) {
	// 创建测试配置
	config := &MemoryCacheConfig{
		Name:            "test",
		MaxEntries:      100,
		MaxSizeBytes:    10 * 1024 * 1024, // 10MB
		MaxItemSize:     1024 * 1024,      // 1MB
		DefaultTTL:      1 * time.Hour,
		CleanupInterval: 1 * time.Minute,
	}

	// 创建缓存实例
	cache := NewMemoryCache(config)
	defer cache.Close()

	// 测试基本功能
	t.Run("Set and Get", func(t *testing.T) {
		key := "test-key"
		data := []byte("test data")
		metadata := map[string]interface{}{
			"test": "value",
		}

		// 设置缓存
		err := cache.SetWithMetadata(key, data, metadata, 0)
		if err != nil {
			t.Fatalf("Failed to set cache: %v", err)
		}

		// 获取缓存
		item, ok := cache.Get(key)
		if !ok {
			t.Fatal("Failed to get cache item")
		}

		if string(item.Data) != string(data) {
			t.Errorf("Expected data %s, got %s", string(data), string(item.Data))
		}

		if item.Metadata["test"] != "value" {
			t.Errorf("Expected metadata test=value, got %v", item.Metadata["test"])
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		key := "expire-key"
		data := []byte("expire data")

		// 设置短期过期
		err := cache.Set(key, data, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("Failed to set cache: %v", err)
		}

		// 立即获取应该成功
		_, ok := cache.Get(key)
		if !ok {
			t.Fatal("Cache item should exist immediately")
		}

		// 等待过期
		time.Sleep(150 * time.Millisecond)

		// 再次获取应该失败
		_, ok = cache.Get(key)
		if ok {
			t.Fatal("Cache item should have expired")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		key := "delete-key"
		data := []byte("delete data")

		// 设置缓存
		err := cache.Set(key, data, 0)
		if err != nil {
			t.Fatalf("Failed to set cache: %v", err)
		}

		// 删除缓存
		deleted := cache.Delete(key)
		if !deleted {
			t.Fatal("Failed to delete cache item")
		}

		// 再次获取应该失败
		_, ok := cache.Get(key)
		if ok {
			t.Fatal("Cache item should have been deleted")
		}
	})

	t.Run("Stats", func(t *testing.T) {
		// 添加一些数据
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("stats-key-%d", i)
			data := []byte(fmt.Sprintf("stats data %d", i))
			cache.Set(key, data, 0)
		}

		// 获取统计信息
		stats := cache.Stats()

		if stats["entries"].(int) < 5 {
			t.Errorf("Expected at least 5 entries, got %d", stats["entries"])
		}

		if stats["hits"].(uint64) == 0 {
			t.Error("Expected hits > 0")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		// 添加数据
		cache.Set("clear-key", []byte("clear data"), 0)

		// 清空缓存
		cache.Clear()

		// 获取统计信息
		stats := cache.Stats()
		if stats["entries"].(int) != 0 {
			t.Errorf("Expected 0 entries after clear, got %d", stats["entries"])
		}
	})
}

func TestBigCachePerformance(t *testing.T) {
	config := &MemoryCacheConfig{
		Name:            "perf-test",
		MaxEntries:      1000,
		MaxSizeBytes:    50 * 1024 * 1024, // 50MB
		MaxItemSize:     1024 * 1024,      // 1MB
		DefaultTTL:      1 * time.Hour,
		CleanupInterval: 1 * time.Minute,
	}

	cache := NewMemoryCache(config)
	defer cache.Close()

	// 性能测试
	t.Run("Concurrent Access", func(t *testing.T) {
		const numGoroutines = 10
		const numOperations = 100

		done := make(chan bool, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(goroutineID int) {
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("perf-key-%d-%d", goroutineID, j)
					data := []byte(fmt.Sprintf("perf data %d-%d", goroutineID, j))

					// 设置
					cache.Set(key, data, 0)

					// 获取
					_, ok := cache.Get(key)
					if !ok {
						t.Errorf("Failed to get key %s", key)
					}
				}
				done <- true
			}(i)
		}

		// 等待所有 goroutine 完成
		for i := 0; i < numGoroutines; i++ {
			<-done
		}

		// 检查统计信息
		stats := cache.Stats()
		t.Logf("Performance test stats: %+v", stats)
	})
}
