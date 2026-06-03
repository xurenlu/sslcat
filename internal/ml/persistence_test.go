package ml

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeTrainingSamples 生成可重复的训练样本
func makeTrainingSamples(dim, n int, seed int64) [][]float64 {
	rng := rand.New(rand.NewSource(seed))
	out := make([][]float64, n)
	for i := 0; i < n; i++ {
		row := make([]float64, dim)
		for j := 0; j < dim; j++ {
			row[j] = rng.NormFloat64()
		}
		out[i] = row
	}
	return out
}

func TestSaveLoadModel_RoundTrip(t *testing.T) {
	dim := 12
	cfg := &ForestConfig{NTrees: 8, MaxSamples: 64, Contamination: 0.1, SubSampling: 1.0}
	forest := NewIsolationForest(dim, cfg)
	if err := forest.Fit(makeTrainingSamples(dim, 200, 42)); err != nil {
		t.Fatalf("fit failed: %v", err)
	}

	// 准备测试向量
	testVecs := makeTrainingSamples(dim, 5, 7)
	wantScores := make([]float64, len(testVecs))
	for i, v := range testVecs {
		wantScores[i] = forest.Predict(v)
	}

	// 写入
	dir := t.TempDir()
	path := filepath.Join(dir, "model.json")
	if err := SaveModelJSON(forest, path); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// 写入后磁盘上应该有 model.json，没有遗留 .tmp
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("model.json not present: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp file leaked: %v", err)
	}

	// 读回
	loaded, err := LoadModelJSON(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	// 元数据守恒
	if loaded.FeatureDim != forest.FeatureDim {
		t.Errorf("FeatureDim mismatch: got %d want %d", loaded.FeatureDim, forest.FeatureDim)
	}
	if loaded.NTrees != forest.NTrees {
		t.Errorf("NTrees mismatch: got %d want %d", loaded.NTrees, forest.NTrees)
	}
	if loaded.Contamination != forest.Contamination {
		t.Errorf("Contamination mismatch")
	}
	// 应该有树
	if len(loaded.Trees) != forest.NTrees {
		t.Errorf("Trees count mismatch: got %d want %d", len(loaded.Trees), forest.NTrees)
	}

	// 同一向量给出相同分数（关键回归点）
	for i, v := range testVecs {
		got := loaded.Predict(v)
		if got != wantScores[i] {
			t.Errorf("Predict mismatch on vec %d: got %.6f want %.6f", i, got, wantScores[i])
		}
	}
}

func TestLoadModelJSON_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadModelJSON(filepath.Join(dir, "does-not-exist.json"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected NotExist, got %v", err)
	}
}

func TestLoadModelJSON_BadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModelJSON(path); err == nil {
		t.Fatalf("expected unmarshal error")
	}
}

func TestSaveModelJSON_CreatesDirs(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c", "model.json")

	cfg := &ForestConfig{NTrees: 2, MaxSamples: 16, Contamination: 0.1, SubSampling: 1.0}
	forest := NewIsolationForest(4, cfg)
	_ = forest.Fit(makeTrainingSamples(4, 30, 1))

	if err := SaveModelJSON(forest, nested); err != nil {
		t.Fatalf("save with nested dir failed: %v", err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Fatalf("file not created at nested path: %v", err)
	}
}

func TestTrainingHistoryStore_AppendList(t *testing.T) {
	dir := t.TempDir()
	store := NewTrainingHistoryStore(filepath.Join(dir, "history.json"), 50)

	// 空 store
	if got := store.List(0); len(got) != 0 {
		t.Fatalf("expected empty list, got %d", len(got))
	}
	if store.Last() != nil {
		t.Fatalf("expected Last() nil on empty")
	}

	// 追加 3 条
	base := time.Now()
	for i := 0; i < 3; i++ {
		err := store.Append(TrainingHistoryEntry{
			ID:           "t" + string(rune('0'+i)),
			Timestamp:    base.Add(time.Duration(i) * time.Minute),
			NTrees:       100,
			SampleCount:  i * 10,
			SampleSource: "auto",
			Triggered:    "api",
		})
		if err != nil {
			t.Fatalf("append %d failed: %v", i, err)
		}
	}

	list := store.List(0)
	if len(list) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(list))
	}
	// 倒序：最新在前
	if list[0].SampleCount != 20 || list[2].SampleCount != 0 {
		t.Fatalf("expected newest first, got SampleCounts %d / %d", list[0].SampleCount, list[2].SampleCount)
	}

	// Last
	last := store.Last()
	if last == nil || last.SampleCount != 20 {
		t.Fatalf("Last() incorrect, got %+v", last)
	}

	// limit 截断
	if l := store.List(2); len(l) != 2 {
		t.Fatalf("List(2) returned %d entries", len(l))
	}
}

func TestTrainingHistoryStore_MaxKeepTruncation(t *testing.T) {
	dir := t.TempDir()
	store := NewTrainingHistoryStore(filepath.Join(dir, "history.json"), 5)

	base := time.Now()
	for i := 0; i < 12; i++ {
		err := store.Append(TrainingHistoryEntry{
			ID:          "t",
			Timestamp:   base.Add(time.Duration(i) * time.Second),
			SampleCount: i,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	list := store.List(0)
	if len(list) != 5 {
		t.Fatalf("expected truncated to 5, got %d", len(list))
	}
	// 保留最近 5 条，最新 SampleCount=11
	if list[0].SampleCount != 11 {
		t.Fatalf("expected newest=11, got %d", list[0].SampleCount)
	}
	// 最旧应是 7（12-5=7）
	if list[4].SampleCount != 7 {
		t.Fatalf("expected oldest kept=7, got %d", list[4].SampleCount)
	}
}

func TestTrainingHistoryStore_PersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")

	s1 := NewTrainingHistoryStore(path, 10)
	if err := s1.Append(TrainingHistoryEntry{ID: "a", Timestamp: time.Now(), SampleCount: 42}); err != nil {
		t.Fatal(err)
	}

	// 新实例读同一个文件
	s2 := NewTrainingHistoryStore(path, 10)
	list := s2.List(0)
	if len(list) != 1 || list[0].SampleCount != 42 {
		t.Fatalf("expected 1 entry with SampleCount=42, got %+v", list)
	}
}
