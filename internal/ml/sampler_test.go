package ml

import (
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRequestSampler_EmptyBuffer(t *testing.T) {
	fe := NewFeatureExtractor()
	s := NewRequestSampler(fe, 10)

	if got := s.Size(); got != 0 {
		t.Fatalf("expected empty Size=0, got %d", got)
	}
	if vecs := s.Vectors(); len(vecs) != 0 {
		t.Fatalf("expected empty Vectors, got %d", len(vecs))
	}
	if got := s.TotalObserved(); got != 0 {
		t.Fatalf("expected TotalObserved=0, got %d", got)
	}
}

func TestRequestSampler_PartialFill(t *testing.T) {
	fe := NewFeatureExtractor()
	s := NewRequestSampler(fe, 10)

	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", fmt.Sprintf("/path-%d", i), nil)
		s.Observe(r, 200, 10*time.Millisecond, "127.0.0.1")
	}

	if got := s.Size(); got != 3 {
		t.Fatalf("expected Size=3, got %d", got)
	}
	if got := s.TotalObserved(); got != 3 {
		t.Fatalf("expected TotalObserved=3, got %d", got)
	}
	vecs := s.Vectors()
	if len(vecs) != 3 {
		t.Fatalf("expected 3 vectors, got %d", len(vecs))
	}
	if len(vecs[0]) != fe.GetFeatureDimension() {
		t.Fatalf("expected feature dim %d, got %d", fe.GetFeatureDimension(), len(vecs[0]))
	}
}

func TestRequestSampler_RingOverwrite(t *testing.T) {
	fe := NewFeatureExtractor()
	capacity := 5
	s := NewRequestSampler(fe, capacity)

	for i := 0; i < 12; i++ {
		r := httptest.NewRequest("GET", fmt.Sprintf("/p-%d", i), nil)
		s.Observe(r, 200, time.Millisecond, "10.0.0.1")
	}

	if got := s.Size(); got != capacity {
		t.Fatalf("expected Size=%d (cap), got %d", capacity, got)
	}
	if got := s.TotalObserved(); got != 12 {
		t.Fatalf("expected TotalObserved=12, got %d", got)
	}
	vecs := s.Vectors()
	if len(vecs) != capacity {
		t.Fatalf("expected %d vectors (ring full), got %d", capacity, len(vecs))
	}
	dim := fe.GetFeatureDimension()
	for i, v := range vecs {
		if len(v) != dim {
			t.Fatalf("vector %d has dim %d, expected %d", i, len(v), dim)
		}
	}
}

func TestRequestSampler_ConcurrentObserve(t *testing.T) {
	fe := NewFeatureExtractor()
	s := NewRequestSampler(fe, 1000)

	const workers = 20
	const perWorker = 100
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				r := httptest.NewRequest("GET", fmt.Sprintf("/w%d/i%d", wid, i), nil)
				s.Observe(r, 200, time.Millisecond, "127.0.0.1")
			}
		}(w)
	}
	wg.Wait()

	if got := s.TotalObserved(); got != int64(workers*perWorker) {
		t.Fatalf("expected TotalObserved=%d, got %d", workers*perWorker, got)
	}
	expectedSize := workers * perWorker
	if expectedSize > 1000 {
		expectedSize = 1000
	}
	if got := s.Size(); got != expectedSize {
		t.Fatalf("expected Size=%d, got %d", expectedSize, got)
	}
}

func TestPredictionBuffer_Empty(t *testing.T) {
	b := NewPredictionBuffer(10)
	if got := b.Size(); got != 0 {
		t.Fatalf("expected empty Size=0, got %d", got)
	}
	if r := b.Recent(5); len(r) != 0 {
		t.Fatalf("expected empty Recent, got %d", len(r))
	}
}

func TestPredictionBuffer_RecentNewestFirst(t *testing.T) {
	b := NewPredictionBuffer(5)
	for i := 0; i < 3; i++ {
		b.Push(AnomalyPrediction{
			Score:     float64(i) / 10.0,
			Level:     "low",
			IsAnomaly: false,
			Timestamp: time.Unix(int64(1000+i), 0),
		})
	}
	got := b.Recent(0)
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	if got[0].Score != 0.2 {
		t.Fatalf("expected newest (0.2) first, got %.2f", got[0].Score)
	}
	if got[2].Score != 0.0 {
		t.Fatalf("expected oldest (0.0) last, got %.2f", got[2].Score)
	}
}

func TestPredictionBuffer_RingOverwrite(t *testing.T) {
	b := NewPredictionBuffer(3)
	for i := 0; i < 7; i++ {
		b.Push(AnomalyPrediction{Score: float64(i), Timestamp: time.Unix(int64(i), 0)})
	}
	got := b.Recent(10)
	if len(got) != 3 {
		t.Fatalf("expected ring cap 3, got %d", len(got))
	}
	expected := []float64{6, 5, 4}
	for i, want := range expected {
		if got[i].Score != want {
			t.Fatalf("Recent[%d]: expected %.0f, got %.0f", i, want, got[i].Score)
		}
	}
}

func TestPredictionBuffer_RecentRespectsLimit(t *testing.T) {
	b := NewPredictionBuffer(10)
	for i := 0; i < 8; i++ {
		b.Push(AnomalyPrediction{Score: float64(i)})
	}
	got := b.Recent(3)
	if len(got) != 3 {
		t.Fatalf("expected 3 entries due to limit, got %d", len(got))
	}
	if got[0].Score != 7 {
		t.Fatalf("expected newest=7, got %.0f", got[0].Score)
	}
}
