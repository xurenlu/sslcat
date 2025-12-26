package web

import (
	"strings"
	"sync"
)

// headerMapPool 用于复用 map[string]string 对象，减少内存分配
var headerMapPool = &sync.Pool{
	New: func() interface{} {
		return make(map[string]string, 8) // 预分配容量为 8
	},
}

// sanitizeHeaderMap 规范化头部键值，移除空键并裁剪空白
// 性能优化：使用对象池优化临时 map 的创建，但最终返回新的 map 给调用方
func sanitizeHeaderMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	
	// 使用对象池获取临时 map 进行处理
	tempMap := headerMapPool.Get().(map[string]string)
	defer func() {
		// 清空 map 但保留容量，归还到对象池
		for k := range tempMap {
			delete(tempMap, k)
		}
		headerMapPool.Put(tempMap)
	}()
	
	// 在临时 map 中进行规范化处理
	for key, value := range in {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue == "" {
			continue
		}
		tempMap[trimmedKey] = trimmedValue
	}
	
	if len(tempMap) == 0 {
		return nil
	}
	
	// 创建新的 map 返回给调用方（调用方会持有这个 map，所以不能直接返回对象池中的 map）
	// 但我们可以根据 tempMap 的大小预分配容量，减少一次扩容
	result := make(map[string]string, len(tempMap))
	for k, v := range tempMap {
		result[k] = v
	}
	return result
}
