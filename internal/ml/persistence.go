package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ModelSnapshot 持久化到磁盘的森林快照
type ModelSnapshot struct {
	Version       int            `json:"version"`
	NTrees        int            `json:"n_trees"`
	MaxSamples    int            `json:"max_samples"`
	FeatureDim    int            `json:"feature_dim"`
	MaxDepth      int            `json:"max_depth"`
	Contamination float64        `json:"contamination"`
	SubSampling   float64        `json:"sub_sampling"`
	BootstrapSize int            `json:"bootstrap_size"`
	TotalSamples  int            `json:"total_samples"`
	Trees         []*treeSnap    `json:"trees"`
	SavedAt       time.Time      `json:"saved_at"`
}

type treeSnap struct {
	MaxDepth int        `json:"max_depth"`
	Depth    int        `json:"depth"`
	Size     int        `json:"size"`
	Root     *nodeSnap  `json:"root"`
}

type nodeSnap struct {
	SplitFeat int        `json:"split_feat"`
	SplitVal  float64    `json:"split_val"`
	IsLeaf    bool       `json:"is_leaf"`
	Size      int        `json:"size"`
	Depth     int        `json:"depth"`
	Left      *nodeSnap  `json:"left,omitempty"`
	Right     *nodeSnap  `json:"right,omitempty"`
}

func dumpNode(n *iTreeNode) *nodeSnap {
	if n == nil {
		return nil
	}
	return &nodeSnap{
		SplitFeat: n.SplitFeat,
		SplitVal:  n.SplitVal,
		IsLeaf:    n.IsLeaf,
		Size:      n.Size,
		Depth:     n.Depth,
		Left:      dumpNode(n.Left),
		Right:     dumpNode(n.Right),
	}
}

func loadNode(s *nodeSnap) *iTreeNode {
	if s == nil {
		return nil
	}
	return &iTreeNode{
		SplitFeat: s.SplitFeat,
		SplitVal:  s.SplitVal,
		IsLeaf:    s.IsLeaf,
		Size:      s.Size,
		Depth:     s.Depth,
		Left:      loadNode(s.Left),
		Right:     loadNode(s.Right),
	}
}

// Snapshot 把森林导出为可持久化结构
func (f *IsolationForest) Snapshot() *ModelSnapshot {
	f.TreesMutex.RLock()
	defer f.TreesMutex.RUnlock()

	trees := make([]*treeSnap, 0, len(f.Trees))
	for _, t := range f.Trees {
		if t == nil {
			continue
		}
		trees = append(trees, &treeSnap{
			MaxDepth: t.MaxDepth,
			Depth:    t.Depth,
			Size:     t.Size,
			Root:     dumpNode(t.Root),
		})
	}

	f.SamplesMutex.Lock()
	total := f.TotalSamples
	f.SamplesMutex.Unlock()

	return &ModelSnapshot{
		Version:       1,
		NTrees:        f.NTrees,
		MaxSamples:    f.MaxSamples,
		FeatureDim:    f.FeatureDim,
		MaxDepth:      f.MaxDepth,
		Contamination: f.Contamination,
		SubSampling:   f.SubSampling,
		BootstrapSize: f.BootstrapSize,
		TotalSamples:  total,
		Trees:         trees,
		SavedAt:       time.Now(),
	}
}

// RestoreFromSnapshot 从快照恢复森林
func RestoreFromSnapshot(snap *ModelSnapshot) *IsolationForest {
	if snap == nil {
		return nil
	}
	cfg := &ForestConfig{
		NTrees:        snap.NTrees,
		MaxSamples:    snap.MaxSamples,
		Contamination: snap.Contamination,
		MaxDepth:      snap.MaxDepth,
		SubSampling:   snap.SubSampling,
	}
	if cfg.SubSampling == 0 {
		cfg.SubSampling = 1.0
	}
	f := NewIsolationForest(snap.FeatureDim, cfg)
	f.BootstrapSize = snap.BootstrapSize
	f.MaxDepth = snap.MaxDepth
	f.TotalSamples = snap.TotalSamples

	trees := make([]*iTree, 0, len(snap.Trees))
	for _, ts := range snap.Trees {
		if ts == nil {
			continue
		}
		trees = append(trees, &iTree{
			MaxDepth: ts.MaxDepth,
			Depth:    ts.Depth,
			Size:     ts.Size,
			Root:     loadNode(ts.Root),
		})
	}
	f.TreesMutex.Lock()
	f.Trees = trees
	f.TreesMutex.Unlock()
	return f
}

// SaveModelJSON 把模型以 JSON 写入磁盘（带原子重命名）
func SaveModelJSON(f *IsolationForest, path string) error {
	if f == nil {
		return fmt.Errorf("nil forest")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}
	snap := f.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// LoadModelJSON 从磁盘读取模型
func LoadModelJSON(path string) (*IsolationForest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	snap := &ModelSnapshot{}
	if err := json.Unmarshal(data, snap); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if snap.FeatureDim == 0 {
		return nil, fmt.Errorf("invalid snapshot: feature_dim=0")
	}
	return RestoreFromSnapshot(snap), nil
}

// TrainingHistoryEntry 单次训练事件
type TrainingHistoryEntry struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	NTrees        int       `json:"n_trees"`
	MaxSamples    int       `json:"max_samples"`
	Contamination float64   `json:"contamination"`
	FeatureDim    int       `json:"feature_dim"`
	SampleCount   int       `json:"sample_count"`
	SampleSource  string    `json:"sample_source"` // "auto" | "manual"
	DurationMS    int64     `json:"duration_ms"`
	Threshold     float64   `json:"threshold"`
	AvgTreeDepth  float64   `json:"avg_tree_depth"`
	Triggered     string    `json:"triggered"` // "ui" | "api" | "scheduler"
	Notes         string    `json:"notes,omitempty"`
}

// TrainingHistoryStore 训练历史的持久化存储（JSON 文件，保留最近 N 条）
type TrainingHistoryStore struct {
	path    string
	maxKeep int
	mu      sync.Mutex
}

// NewTrainingHistoryStore 创建训练历史存储
func NewTrainingHistoryStore(path string, maxKeep int) *TrainingHistoryStore {
	if maxKeep <= 0 {
		maxKeep = 50
	}
	return &TrainingHistoryStore{path: path, maxKeep: maxKeep}
}

func (s *TrainingHistoryStore) load() ([]TrainingHistoryEntry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []TrainingHistoryEntry{}, nil
		}
		return nil, err
	}
	entries := []TrainingHistoryEntry{}
	if len(data) == 0 {
		return entries, nil
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *TrainingHistoryStore) save(entries []TrainingHistoryEntry) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Append 追加一次训练事件
func (s *TrainingHistoryStore) Append(entry TrainingHistoryEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}
	entries = append(entries, entry)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})
	if len(entries) > s.maxKeep {
		entries = entries[len(entries)-s.maxKeep:]
	}
	return s.save(entries)
}

// List 返回训练历史（按时间倒序）
func (s *TrainingHistoryStore) List(limit int) []TrainingHistoryEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return nil
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}

// Last 返回最后一次训练（若无则返回 nil）
func (s *TrainingHistoryStore) Last() *TrainingHistoryEntry {
	list := s.List(1)
	if len(list) == 0 {
		return nil
	}
	c := list[0]
	return &c
}
