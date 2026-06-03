package ml

import (
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// trainedEngine 准备一个装载了真实模型的 InferenceEngine
func trainedEngine(t *testing.T, dim, samples int) *InferenceEngine {
	t.Helper()
	fe := NewFeatureExtractor()
	cfg := &ForestConfig{NTrees: 16, MaxSamples: 64, Contamination: 0.1, SubSampling: 1.0}
	forest := NewIsolationForest(dim, cfg)
	if err := forest.Fit(makeTrainingSamples(dim, samples, 11)); err != nil {
		t.Fatalf("fit failed: %v", err)
	}
	ie := NewInferenceEngineWithConfig(4, 100, 50*time.Millisecond, "drop")
	ie.SetModel(forest, fe)
	return ie
}

func TestInferenceEngine_PredictWithoutModel(t *testing.T) {
	ie := NewInferenceEngineWithConfig(4, 50, 50*time.Millisecond, "drop")
	r := httptest.NewRequest("GET", "/foo", nil)
	pred, err := ie.Predict(r, 200, time.Millisecond, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pred != nil {
		t.Fatalf("expected nil prediction without model, got %+v", pred)
	}
	// 未推理过，total_predictions 应为 0
	stats := ie.GetStats()
	if v := stats["total_predictions"].(int64); v != 0 {
		t.Fatalf("expected total_predictions=0, got %d", v)
	}
}

func TestInferenceEngine_PredictAccumulatesStats(t *testing.T) {
	// 回归点：之前 updateStats 是空函数，total_predictions 永远为 0
	dim := NewFeatureExtractor().GetFeatureDimension()
	ie := trainedEngine(t, dim, 100)

	for i := 0; i < 25; i++ {
		r := httptest.NewRequest("GET", fmt.Sprintf("/p/%d", i), nil)
		pred, err := ie.Predict(r, 200, time.Millisecond, "127.0.0.1")
		if err != nil {
			t.Fatalf("predict %d failed: %v", i, err)
		}
		if pred == nil {
			t.Fatalf("expected non-nil prediction at i=%d", i)
		}
	}

	stats := ie.GetStats()
	total := stats["total_predictions"].(int64)
	if total != 25 {
		t.Fatalf("expected total_predictions=25, got %d", total)
	}
}

func TestInferenceEngine_RecentPredictionsBuffer(t *testing.T) {
	dim := NewFeatureExtractor().GetFeatureDimension()
	ie := trainedEngine(t, dim, 80)

	// 默认 buffer 容量 200
	for i := 0; i < 30; i++ {
		r := httptest.NewRequest("GET", fmt.Sprintf("/r/%d", i), nil)
		_, _ = ie.Predict(r, 200, time.Millisecond, "127.0.0.1")
	}

	recent := ie.RecentPredictions(10)
	if len(recent) != 10 {
		t.Fatalf("expected 10 recent predictions, got %d", len(recent))
	}

	// 关键：recent buffer 中存的应是 light 版本（FeatureVector / Features 已清空）
	for i, p := range recent {
		if p.FeatureVector != nil {
			t.Errorf("recent[%d] still carries FeatureVector (%d floats)", i, len(p.FeatureVector))
		}
		if p.Features != nil {
			t.Errorf("recent[%d] still carries Features", i)
		}
		if p.Timestamp.IsZero() {
			t.Errorf("recent[%d] missing timestamp", i)
		}
	}
}

func TestInferenceEngine_RecentReturnsAllWhenLimitLarger(t *testing.T) {
	dim := NewFeatureExtractor().GetFeatureDimension()
	ie := trainedEngine(t, dim, 50)

	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("GET", fmt.Sprintf("/r/%d", i), nil)
		_, _ = ie.Predict(r, 200, time.Millisecond, "127.0.0.1")
	}
	got := ie.RecentPredictions(50)
	if len(got) != 5 {
		t.Fatalf("expected 5 (all available), got %d", len(got))
	}
}

func TestInferenceEngine_ConcurrentPredictStats(t *testing.T) {
	dim := NewFeatureExtractor().GetFeatureDimension()
	ie := trainedEngine(t, dim, 100)

	const workers = 8
	const perWorker = 50

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				r := httptest.NewRequest("GET", fmt.Sprintf("/w%d/i%d", wid, i), nil)
				_, _ = ie.Predict(r, 200, time.Millisecond, fmt.Sprintf("10.0.%d.1", wid))
			}
		}(w)
	}
	wg.Wait()

	stats := ie.GetStats()
	total := stats["total_predictions"].(int64)
	expected := int64(workers * perWorker)
	if total != expected {
		t.Fatalf("expected total_predictions=%d, got %d (race/atomic broken?)", expected, total)
	}

	// anomaly_count 应该 <= total
	anomaly := stats["anomaly_count"].(int64)
	if anomaly < 0 || anomaly > total {
		t.Fatalf("anomaly_count %d out of range [0,%d]", anomaly, total)
	}
}

func TestInferenceEngine_AnomalyCountTracksIsAnomaly(t *testing.T) {
	dim := NewFeatureExtractor().GetFeatureDimension()
	ie := trainedEngine(t, dim, 100)

	// 喂一批请求，记录每条 IsAnomaly，然后比对 anomaly_count
	expectedAnomalies := int64(0)
	for i := 0; i < 40; i++ {
		// 让 path 千奇百怪一点，制造异常的可能性
		path := fmt.Sprintf("/x?%s=%d", "qwertyuiopasdfghjklzxcvbnm", i*97)
		r := httptest.NewRequest("GET", path, nil)
		pred, _ := ie.Predict(r, 500, 5*time.Millisecond, "203.0.113.7")
		if pred != nil && pred.IsAnomaly {
			expectedAnomalies++
		}
	}
	stats := ie.GetStats()
	got := stats["anomaly_count"].(int64)
	if got != expectedAnomalies {
		t.Fatalf("anomaly_count drift: counted %d but engine reports %d", expectedAnomalies, got)
	}
}
