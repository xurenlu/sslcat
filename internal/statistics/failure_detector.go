package statistics

import (
	"encoding/json"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// FailureDetector 非 RESTful API 的失败率检测器
// 结合：1) error 类字段检测 2) 响应长度启发式 3) Isolation Forest 异常检测
type FailureDetector struct {
	mu sync.RWMutex

	// per-path 响应长度画像（用于短响应=失败启发式）
	pathLengthProfiles map[string]*lengthProfile

	// Isolation Forest 模型（per-path）
	pathIFModels map[string]*isolationForest

	// 配置
	maxProfileSize   int   // 每个 path 最多保留的样本数
	shortPercentile  int   // 低于此百分位视为"短响应"
	anomalyThreshold float64 // IF 异常分数阈值，高于此值视为失败
}

type lengthProfile struct {
	lengths []int
	sorted  bool
}

// 响应特征向量（用于 Isolation Forest）
type responseFeatures struct {
	BodyLength    float64 // 响应体字节数
	StatusCode    float64 // HTTP 状态码
	HasErrorField float64 // 1=有 error 类字段且非空
	ErrorLen      float64 // error 字段值长度
	HasSuccessFalse float64 // 1=success:false
	NumKeys       float64 // 顶层 key 数量
	Depth         float64 // JSON 最大嵌套深度
}

// NewFailureDetector 创建失败检测器
func NewFailureDetector() *FailureDetector {
	return &FailureDetector{
		pathLengthProfiles: make(map[string]*lengthProfile),
		pathIFModels:       make(map[string]*isolationForest),
		maxProfileSize:     500,
		shortPercentile:    15, // 低于 p15 的响应视为异常短
		anomalyThreshold:   0.65,
	}
}

// errorLikeFields 错误类字段名（非空值通常表示失败）
var errorLikeFields = []string{"error", "err", "errmsg", "err_msg", "message", "msg", "error_message"}

// successLikeValues 成功语义（error 字段若为此类值则不算失败）
var successLikeValues = map[string]bool{
	"ok": true, "success": true, "0": true, "null": true, "": true,
}

// DetectFailure 检测响应是否为业务失败
// 当 ResponseAnalyzer 无法通过模式匹配时，作为 fallback
func (fd *FailureDetector) DetectFailure(resp *http.Response, body []byte, apiPath string) *BusinessStatus {
	if len(body) == 0 {
		return nil
	}
	contentType := ""
	if resp != nil && resp.Header != nil {
		contentType = resp.Header.Get("Content-Type")
	}
	if !strings.Contains(contentType, "application/json") {
		return nil
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	features := fd.extractFeatures(data, body, resp)
	if features == nil {
		return nil
	}

	// 1) 强信号：error 类字段非空
	if status := fd.detectByErrorField(data); status != nil {
		fd.recordSample(apiPath, features, true)
		return status
	}

	// 2) 强信号：success: false
	if status := fd.detectBySuccessFalse(data); status != nil {
		fd.recordSample(apiPath, features, true)
		return status
	}

	// 3) 启发式：短响应 + 有 error 结构
	if fd.isShortResponse(apiPath, len(body)) && fd.hasErrorStructure(data) {
		fd.recordSample(apiPath, features, true)
		return &BusinessStatus{
			IsSuccess: false,
			Code:      -1,
			Message:   "short_response_with_error_structure",
			Source:    "failure_heuristic",
		}
	}

	// 4) Isolation Forest 异常检测
	if fd.isAnomaly(apiPath, features) {
		fd.recordSample(apiPath, features, true)
		return &BusinessStatus{
			IsSuccess: false,
			Code:      -1,
			Message:   "anomaly_detected",
			Source:    "isolation_forest",
		}
	}

	// 记录正常样本（用于更新画像）
	fd.recordSample(apiPath, features, false)
	return nil
}

func (fd *FailureDetector) extractFeatures(data interface{}, body []byte, resp *http.Response) *responseFeatures {
	statusCode := 200
	if resp != nil {
		statusCode = resp.StatusCode
	}

	hasError, errorLen := fd.checkErrorField(data)
	hasSuccessFalse := fd.checkSuccessFalse(data)
	numKeys, depth := countKeysAndDepth(data)

	return &responseFeatures{
		BodyLength:      float64(len(body)),
		StatusCode:      float64(statusCode),
		HasErrorField:   boolToFloat(hasError),
		ErrorLen:        float64(errorLen),
		HasSuccessFalse: boolToFloat(hasSuccessFalse),
		NumKeys:         float64(numKeys),
		Depth:           float64(depth),
	}
}

func (fd *FailureDetector) checkErrorField(data interface{}) (hasError bool, errorValueLen int) {
	m, ok := data.(map[string]interface{})
	if !ok {
		return false, 0
	}
	for _, key := range errorLikeFields {
		if v, exists := m[key]; exists && v != nil {
			s := strings.TrimSpace(stringifyValue(v))
			if s != "" && !successLikeValues[strings.ToLower(s)] {
				return true, len(s)
			}
		}
	}
	return false, 0
}

func (fd *FailureDetector) checkSuccessFalse(data interface{}) bool {
	m, ok := data.(map[string]interface{})
	if !ok {
		return false
	}
	if v, exists := m["success"]; exists {
		switch val := v.(type) {
		case bool:
			return !val
		case string:
			return strings.ToLower(val) == "false" || val == "0"
		}
	}
	return false
}

func (fd *FailureDetector) detectByErrorField(data interface{}) *BusinessStatus {
	hasError, errorLen := fd.checkErrorField(data)
	if !hasError || errorLen == 0 {
		return nil
	}
	return &BusinessStatus{
		IsSuccess: false,
		Code:      -1,
		Message:   "error_field_non_empty",
		Source:    "error_field",
	}
}

func (fd *FailureDetector) detectBySuccessFalse(data interface{}) *BusinessStatus {
	if !fd.checkSuccessFalse(data) {
		return nil
	}
	return &BusinessStatus{
		IsSuccess: false,
		Code:      0,
		Message:   "success_false",
		Source:    "success_field",
	}
}

func (fd *FailureDetector) hasErrorStructure(data interface{}) bool {
	// 仅当 error 类字段存在且值为非空（表示失败）时返回 true
	hasError, _ := fd.checkErrorField(data)
	return hasError
}

func (fd *FailureDetector) isShortResponse(apiPath string, length int) bool {
	fd.mu.RLock()
	profile := fd.pathLengthProfiles[apiPath]
	fd.mu.RUnlock()

	if profile == nil || len(profile.lengths) < 20 {
		// 样本不足，用启发式：< 200 字节的 JSON 多为错误响应
		return length < 200
	}

	fd.mu.Lock()
	if !profile.sorted {
		sorted := make([]int, len(profile.lengths))
		copy(sorted, profile.lengths)
		sort.Ints(sorted)
		profile.lengths = sorted
		profile.sorted = true
	}
	p15Idx := int(float64(len(profile.lengths)) * 0.15)
	if p15Idx < 0 {
		p15Idx = 0
	}
	p15 := profile.lengths[p15Idx]
	fd.mu.Unlock()

	return length < p15
}

func (fd *FailureDetector) isAnomaly(apiPath string, features *responseFeatures) bool {
	fd.mu.RLock()
	model := fd.pathIFModels[apiPath]
	fd.mu.RUnlock()

	if model == nil || model.sampleCount < 50 {
		return false
	}

	score := model.Score(features)
	return score > fd.anomalyThreshold
}

func (fd *FailureDetector) recordSample(apiPath string, features *responseFeatures, isFailure bool) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	// 更新长度画像
	if fd.pathLengthProfiles[apiPath] == nil {
		fd.pathLengthProfiles[apiPath] = &lengthProfile{lengths: make([]int, 0, fd.maxProfileSize)}
	}
	profile := fd.pathLengthProfiles[apiPath]
	profile.lengths = append(profile.lengths, int(features.BodyLength))
	profile.sorted = false
	if len(profile.lengths) > fd.maxProfileSize {
		profile.lengths = profile.lengths[1:]
	}

	// 仅用"正常"样本训练 IF（失败样本会拉偏分布）
	if !isFailure {
		if fd.pathIFModels[apiPath] == nil {
			fd.pathIFModels[apiPath] = newIsolationForest(100, 256)
		}
		fd.pathIFModels[apiPath].AddSample(features)
	}
}

func countKeysAndDepth(data interface{}) (keys int, depth int) {
	switch v := data.(type) {
	case map[string]interface{}:
		keys = len(v)
		maxChild := 0
		for _, child := range v {
			_, d := countKeysAndDepth(child)
			if d > maxChild {
				maxChild = d
			}
		}
		depth = 1 + maxChild
	case []interface{}:
		keys = len(v)
		if len(v) > 0 {
			_, d := countKeysAndDepth(v[0])
			depth = 1 + d
		}
	default:
		return 0, 0
	}
	return keys, depth
}

func stringifyValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case float64, int:
		return ""
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// --- Isolation Forest 简化实现 ---

type isolationForest struct {
	trees        []*iTree
	samples      [][]float64
	sampleCount  int
	maxSamples   int
	numTrees     int
	sampleSize   int
}

type iTree struct {
	left      *iTree
	right     *iTree
	feature   int
	splitVal  float64
	leafSize  int
	isLeaf    bool
}

func newIsolationForest(numTrees, sampleSize int) *isolationForest {
	return &isolationForest{
		trees:      make([]*iTree, 0, numTrees),
		samples:    make([][]float64, 0, 1024),
		maxSamples: 2000,
		numTrees:   numTrees,
		sampleSize: sampleSize,
	}
}

func (iforest *isolationForest) AddSample(f *responseFeatures) {
	vec := []float64{f.BodyLength, f.StatusCode, f.HasErrorField, f.ErrorLen, f.HasSuccessFalse, f.NumKeys, f.Depth}
	iforest.samples = append(iforest.samples, vec)
	iforest.sampleCount++
	if len(iforest.samples) > iforest.maxSamples {
		iforest.samples = iforest.samples[1:]
	}
	// 样本足够时建树
	if iforest.sampleCount >= iforest.sampleSize && len(iforest.trees) < iforest.numTrees {
		iforest.fitTree()
	}
}

func (iforest *isolationForest) fitTree() {
	n := len(iforest.samples)
	if n < 2 {
		return
	}
	indices := make([]int, n)
	for i := range indices {
		indices[i] = rand.Intn(n)
	}
	sub := make([][]float64, iforest.sampleSize)
	for i := 0; i < iforest.sampleSize && i < n; i++ {
		sub[i] = iforest.samples[indices[i]]
	}
	root := iforest.buildTree(sub, 0)
	iforest.trees = append(iforest.trees, root)
}

func (iforest *isolationForest) buildTree(samples [][]float64, depth int) *iTree {
	if len(samples) <= 1 || depth > 20 {
		return &iTree{leafSize: len(samples), isLeaf: true}
	}

	numFeatures := len(samples[0])
	feat := rand.Intn(numFeatures)

	minVal, maxVal := samples[0][feat], samples[0][feat]
	for _, s := range samples {
		if s[feat] < minVal {
			minVal = s[feat]
		}
		if s[feat] > maxVal {
			maxVal = s[feat]
		}
	}
	if minVal >= maxVal {
		return &iTree{leafSize: len(samples), isLeaf: true}
	}

	splitVal := minVal + rand.Float64()*(maxVal-minVal)
	var left, right [][]float64
	for _, s := range samples {
		if s[feat] < splitVal {
			left = append(left, s)
		} else {
			right = append(right, s)
		}
	}

	return &iTree{
		feature:  feat,
		splitVal: splitVal,
		left:     iforest.buildTree(left, depth+1),
		right:    iforest.buildTree(right, depth+1),
		isLeaf:   false,
	}
}

func (iforest *isolationForest) Score(f *responseFeatures) float64 {
	if len(iforest.trees) == 0 {
		return 0
	}
	vec := []float64{f.BodyLength, f.StatusCode, f.HasErrorField, f.ErrorLen, f.HasSuccessFalse, f.NumKeys, f.Depth}

	var totalPathLen float64
	for _, t := range iforest.trees {
		totalPathLen += float64(pathLength(t, vec))
	}
	avgPath := totalPathLen / float64(len(iforest.trees))
	n := float64(iforest.sampleSize)
	c := 2*math.Log(n-1) + 0.5772156649 - 2*(n-1)/n
	return math.Pow(2, -avgPath/c)
}

func pathLength(node *iTree, point []float64) int {
	if node.isLeaf {
		if node.leafSize <= 1 {
			return 1
		}
		return int(math.Ceil(math.Log2(float64(node.leafSize))))
	}
	if point[node.feature] < node.splitVal {
		return 1 + pathLength(node.left, point)
	}
	return 1 + pathLength(node.right, point)
}
