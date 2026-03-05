package statistics

import (
	"fmt"
	"sort"
	"sync"
)

// ValueLearner 基于分布学习 code/status 等字段的成功/失败值
// 算法：1) HTTP 2xx 中高频 = 成功，4xx/5xx 中高频 = 失败
//      2) 若 HTTP 无区分（全 2xx 或全 4xx），则多数派 = 成功（大多数 API 成功占多数）
type ValueLearner struct {
	mu sync.RWMutex

	// path -> field -> valueString -> {count2xx, count4xx5xx}
	samples map[string]map[string]map[string]*valueCounts

	minSamples   int   // 最少样本数才启用学习结果
	maxValues    int   // 每个 field 最多跟踪的值数量
	successRatio float64 // 2xx 占比超过此值则判为成功（默认 0.6）
}

type valueCounts struct {
	Count2xx    int
	Count4xx5xx int
}

func NewValueLearner() *ValueLearner {
	return &ValueLearner{
		samples:      make(map[string]map[string]map[string]*valueCounts),
		minSamples:   15,
		maxValues:   50,
		successRatio: 0.6,
	}
}

// Record 记录一次 (path, field, value) 与对应的 HTTP 状态码
func (vl *ValueLearner) Record(path, field, valueStr string, statusCode int) {
	if valueStr == "" && field != "error" && field != "errmsg" {
		return
	}

	vl.mu.Lock()
	defer vl.mu.Unlock()

	if vl.samples[path] == nil {
		vl.samples[path] = make(map[string]map[string]*valueCounts)
	}
	if vl.samples[path][field] == nil {
		vl.samples[path][field] = make(map[string]*valueCounts)
	}

	vc := vl.samples[path][field][valueStr]
	if vc == nil {
		vc = &valueCounts{}
		vl.samples[path][field][valueStr] = vc
	}

	if statusCode >= 200 && statusCode < 400 {
		vc.Count2xx++
	} else {
		vc.Count4xx5xx++
	}

	// 限制每个 field 的值数量，删除最少的
	if len(vl.samples[path][field]) > vl.maxValues {
		vl.pruneValues(path, field)
	}
}

func (vl *ValueLearner) pruneValues(path, field string) {
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, vc := range vl.samples[path][field] {
		list = append(list, kv{k, vc.Count2xx + vc.Count4xx5xx})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	keep := make(map[string]bool)
	for i := 0; i < vl.maxValues && i < len(list); i++ {
		keep[list[i].k] = true
	}
	for k := range vl.samples[path][field] {
		if !keep[k] {
			delete(vl.samples[path][field], k)
		}
	}
}

// GetLearnedSuccessValues 返回学习到的成功值列表，样本不足时返回 nil（使用内置）
func (vl *ValueLearner) GetLearnedSuccessValues(path, field string) []interface{} {
	vl.mu.RLock()
	defer vl.mu.RUnlock()

	if vl.samples[path] == nil || vl.samples[path][field] == nil {
		return nil
	}

	total := 0
	for _, vc := range vl.samples[path][field] {
		total += vc.Count2xx + vc.Count4xx5xx
	}
	if total < vl.minSamples {
		return nil
	}

	var successValues []interface{}

	// 策略1：HTTP 有区分时，2xx 占比高的值 = 成功
	for valueStr, vc := range vl.samples[path][field] {
		sum := vc.Count2xx + vc.Count4xx5xx
		if sum < 2 {
			continue
		}
		ratio2xx := float64(vc.Count2xx) / float64(sum)
		if vc.Count4xx5xx > 0 && ratio2xx >= vl.successRatio {
			successValues = append(successValues, parseValueToInterface(valueStr))
		}
	}

	// 策略2：若全为 2xx（无 HTTP 区分），用多数派：出现最多的值 = 成功
	if len(successValues) == 0 {
		type kv struct {
			val string
			cnt int
		}
		var list []kv
		for valueStr, vc := range vl.samples[path][field] {
			list = append(list, kv{valueStr, vc.Count2xx + vc.Count4xx5xx})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].cnt > list[j].cnt })
		if len(list) > 0 {
			successValues = append(successValues, parseValueToInterface(list[0].val))
		}
	}

	if len(successValues) == 0 {
		return nil
	}
	return successValues
}

// parseValueToInterface 将字符串形式的 JSON 值转回 interface{}
func parseValueToInterface(s string) interface{} {
	switch s {
	case "null", "":
		return nil
	case "true":
		return true
	case "false":
		return false
	default:
		// 尝试解析为数字
		var f float64
		if _, err := fmt.Sscanf(s, "%v", &f); err == nil {
			if float64(int(f)) == f {
				return int(f)
			}
			return f
		}
		return s
	}
}

// HasLearnedValues 是否已有该 path+field 的学习结果
func (vl *ValueLearner) HasLearnedValues(path, field string) bool {
	vl.mu.RLock()
	defer vl.mu.RUnlock()
	if vl.samples[path] == nil || vl.samples[path][field] == nil {
		return false
	}
	total := 0
	for _, vc := range vl.samples[path][field] {
		total += vc.Count2xx + vc.Count4xx5xx
	}
	return total >= vl.minSamples
}
