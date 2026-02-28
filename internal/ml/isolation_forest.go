package ml

import (
	"math"
	"math/rand"
	"sync"

	"github.com/sirupsen/logrus"
)

// IsolationForest 隔离森林异常检测器
// 基于论文: "Isolation Forest" by Liu, Ting, and Zhou
type IsolationForest struct {
	// 森林配置
	NTrees          int           // 树的数量
	MaxSamples      int           // 每棵树的最大样本数
	FeatureDim      int           // 特征维度
	MaxDepth        int           // 最大深度
	Contamination   float64       // 预期污染率（用于计算阈值）

	// 森林
	Trees           []*iTree
	TreesMutex      sync.RWMutex

	// 统计
	TotalSamples    int
	SamplesMutex    sync.Mutex

	// 配置
	SubSampling     float64 // 子采样率
	BootstrapSize    int     // Bootstrap 样本大小

	log *logrus.Entry
}

// iTree 隔离树
type iTree struct {
	Root     *iTreeNode
	MaxDepth int
	Depth    int
	Size     int
}

// iTreeNode 隔离树节点
type iTreeNode struct {
	Left      *iTreeNode
	Right     *iTreeNode
	SplitFeat int       // 分裂特征索引
	SplitVal  float64   // 分裂值
	IsLeaf    bool
	Size      int       // 该节点包含的样本数
	Depth     int       // 节点深度
}

// ForestConfig 森林配置
type ForestConfig struct {
	NTrees        int     // 树的数量，默认100
	MaxSamples    int     // 最大样本数，默认256
	Contamination float64 // 污染率，默认0.1
	MaxDepth      int     // 最大深度，默认自动计算
	SubSampling   float64 // 子采样率，默认1.0（不采样）
}

// DefaultForestConfig 默认配置
func DefaultForestConfig() *ForestConfig {
	return &ForestConfig{
		NTrees:        100,
		MaxSamples:    256,
		Contamination: 0.1,
		MaxDepth:      0, // 自动计算
		SubSampling:   1.0,
	}
}

// NewIsolationForest 创建隔离森林
func NewIsolationForest(featureDim int, config *ForestConfig) *IsolationForest {
	if config == nil {
		config = DefaultForestConfig()
	}

	// 自动计算最大深度
	maxDepth := config.MaxSamples
	if config.MaxDepth == 0 {
		maxDepth = int(math.Ceil(math.Log2(float64(config.MaxSamples))))
	}

	forest := &IsolationForest{
		NTrees:        config.NTrees,
		MaxSamples:    config.MaxSamples,
		FeatureDim:    featureDim,
		MaxDepth:      maxDepth,
		Contamination: config.Contamination,
		Trees:         make([]*iTree, 0, config.NTrees),
		SubSampling:   config.SubSampling,
		BootstrapSize: config.MaxSamples,
		log: logrus.WithFields(logrus.Fields{
			"component": "isolation_forest",
		}),
	}

	return forest
}

// Fit 训练模型
func (f *IsolationForest) Fit(samples [][]float64) error {
	if len(samples) == 0 {
		return nil
	}

	f.log.Infof("开始训练 Isolation Forest: %d 树, %d 特征, %d 样本", f.NTrees, f.FeatureDim, len(samples))

	// 子采样
	trainSamples := samples
	if f.SubSampling < 1.0 && f.SubSampling > 0 {
		sampleSize := int(float64(len(samples)) * f.SubSampling)
		trainSamples = make([][]float64, 0, sampleSize)
		indices := rand.Perm(len(samples))
		for i := 0; i < sampleSize && i < len(indices); i++ {
			trainSamples = append(trainSamples, samples[indices[i]])
		}
	}

	// 构建森林
	f.TreesMutex.Lock()
	defer f.TreesMutex.Unlock()

	f.Trees = make([]*iTree, f.NTrees)

	var wg sync.WaitGroup
	for i := 0; i < f.NTrees; i++ {
		wg.Add(1)
		go func(treeIndex int) {
			defer wg.Done()

			// Bootstrap采样
			bootstrapSamples := trainSamples
			if len(trainSamples) > f.BootstrapSize {
				bootstrapSamples = make([][]float64, f.BootstrapSize)
				indices := rand.Perm(len(trainSamples))
				for j := 0; j < f.BootstrapSize; j++ {
					bootstrapSamples[j] = trainSamples[indices[j]]
				}
			}

			tree := f.buildTree(bootstrapSamples, 0, f.MaxDepth)
			f.Trees[treeIndex] = tree
		}(i)
	}

	wg.Wait()

	f.SamplesMutex.Lock()
	f.TotalSamples = len(samples)
	f.SamplesMutex.Unlock()

	f.log.Info("Isolation Forest 训练完成")
	return nil
}

// buildTree 构建单棵树
func (f *IsolationForest) buildTree(samples [][]float64, depth int, maxDepth int) *iTree {
	if len(samples) <= 1 || depth >= maxDepth {
		return &iTree{
			Root: &iTreeNode{
				IsLeaf: true,
				Size:   len(samples),
				Depth:  depth,
			},
			MaxDepth: depth,
			Depth:    depth,
			Size:     len(samples),
		}
	}

	// 随机选择特征
	splitFeat := rand.Intn(f.FeatureDim)

	// 随机选择分裂值
	minVal := math.Inf(1)
	maxVal := math.Inf(-1)
	for _, sample := range samples {
		if splitFeat < len(sample) {
			val := sample[splitFeat]
			if val < minVal {
				minVal = val
			}
			if val > maxVal {
				maxVal = val
			}
		}
	}

	if minVal == maxVal || math.IsInf(minVal, 0) || math.IsInf(maxVal, 0) {
		return &iTree{
			Root: &iTreeNode{
				IsLeaf: true,
				Size:   len(samples),
				Depth:  depth,
			},
			MaxDepth: depth,
			Depth:    depth,
			Size:     len(samples),
		}
	}

	splitVal := minVal + rand.Float64()*(maxVal-minVal)

	// 分裂数据
	leftSamples := make([][]float64, 0)
	rightSamples := make([][]float64, 0)

	for _, sample := range samples {
		if splitFeat < len(sample) && sample[splitFeat] < splitVal {
			leftSamples = append(leftSamples, sample)
		} else {
			rightSamples = append(rightSamples, sample)
		}
	}

	// 递归构建
	node := &iTreeNode{
		SplitFeat: splitFeat,
		SplitVal:  splitVal,
		IsLeaf:    false,
		Size:      len(samples),
		Depth:     depth,
	}

	leftTree := f.buildTree(leftSamples, depth+1, maxDepth)
	rightTree := f.buildTree(rightSamples, depth+1, maxDepth)

	node.Left = leftTree.Root
	node.Right = rightTree.Root

	return &iTree{
		Root:     node,
		MaxDepth: maxDepth,
		Depth:    depth,
		Size:     len(samples),
	}
}

// Predict 预测异常分数
func (f *IsolationForest) Predict(sample []float64) float64 {
	if len(f.Trees) == 0 {
		return 0
	}

	// 计算路径长度
	pathLengths := make([]float64, len(f.Trees))
	f.TreesMutex.RLock()
	defer f.TreesMutex.RUnlock()

	for i, tree := range f.Trees {
		pathLengths[i] = f.pathLength(tree.Root, sample, 0)
	}

	// 平均路径长度
	avgPathLength := 0.0
	for _, pl := range pathLengths {
		avgPathLength += pl
	}
	avgPathLength /= float64(len(pathLengths))

	// 归一化
	c := f.expectedPathLength(float64(f.MaxSamples))
	if c > 0 {
		avgPathLength /= c
	}

	// 异常分数 (0-1，越高越异常)
	score := math.Pow(2, -avgPathLength)

	return score
}

// pathLength 计算路径长度
func (f *IsolationForest) pathLength(node *iTreeNode, sample []float64, depth int) float64 {
	if node.IsLeaf {
		// 加上调整项
		adjustment := 0.0
		if node.Size > 1 {
			adjustment = expectedPathLength(float64(node.Size))
		}
		return float64(depth) + adjustment
	}

	if node.SplitFeat < len(sample) && sample[node.SplitFeat] < node.SplitVal {
		return f.pathLength(node.Left, sample, depth+1)
	}
	return f.pathLength(node.Right, sample, depth+1)
}

// expectedPathLength 预期路径长度（不使用递归避免溢出）
func expectedPathLength(n float64) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}

	// H(n) = ln(n) + 0.5772156649 (Euler's constant)
	harmonic := math.Log(n) + 0.5772156649

	// c(n) = 2H(n-1) - (2(n-1)/n)
	c := 2*harmonic - (2*(n-1)/n)

	return c
}

// GetThreshold 获取异常阈值
func (f *IsolationForest) GetThreshold() float64 {
	c := f.expectedPathLength(float64(f.MaxSamples))
	threshold := math.Pow(2, -c)
	return threshold
}

// expectedPathLength 不递归版本
func (f *IsolationForest) expectedPathLength(n float64) float64 {
	if n <= 1 {
		return 0
	}

	h := math.Log(n) + 0.5772156649
	c := 2*h - (2*(n-1)/n)

	return c
}

// IsAnomaly 判断是否为异常
func (f *IsolationForest) IsAnomaly(sample []float64) bool {
	score := f.Predict(sample)
	return score >= f.Contamination
}

// GetAnomalyScore 获取异常分数和级别
func (f *IsolationForest) GetAnomalyScore(sample []float64) (score float64, level string) {
	score = f.Predict(sample)

	level = "normal"
	if score > 0.9 {
		level = "critical"
	} else if score > 0.7 {
		level = "high"
	} else if score > 0.5 {
		level = "medium"
	} else if score > f.Contamination {
		level = "low"
	}

	return score, level
}

// SaveModel 保存模型（简化版）
func (f *IsolationForest) SaveModel(path string) error {
	// TODO: 实现模型序列化
	return nil
}

// LoadModel 加载模型（简化版）
func (f *IsolationForest) LoadModel(path string) error {
	// TODO: 实现模型反序列化
	return nil
}

// UpdateModel 在线更新模型
func (f *IsolationForest) UpdateModel(newSamples [][]float64) error {
	if len(newSamples) == 0 {
		return nil
	}

	f.log.Infof("在线更新模型: %d 新样本", len(newSamples))

	// 重新训练（简化版，生产环境可以使用增量学习）
	return f.Fit(newSamples)
}

// GetStats 获取森林统计信息
func (f *IsolationForest) GetStats() map[string]interface{} {
	f.TreesMutex.RLock()
	f.SamplesMutex.Lock()
	defer f.TreesMutex.RUnlock()
	defer f.SamplesMutex.Unlock()

	avgDepth := 0.0
	if len(f.Trees) > 0 {
		for _, tree := range f.Trees {
			avgDepth += float64(tree.Depth)
		}
		avgDepth /= float64(len(f.Trees))
	}

	return map[string]interface{}{
		"n_trees":         f.NTrees,
		"max_samples":     f.MaxSamples,
		"feature_dim":     f.FeatureDim,
		"max_depth":       f.MaxDepth,
		"contamination":   f.Contamination,
		"total_samples":   f.TotalSamples,
		"avg_tree_depth":  avgDepth,
		"threshold":       f.GetThreshold(),
	}
}
