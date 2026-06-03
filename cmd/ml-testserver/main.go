// ml-testserver 是一个仅用于自动化回归测试的最小 HTTP 服务，对外暴露 ML 子系统的核心接口。
// 它不复用 internal/web/server.go 的庞大初始化逻辑，也不要求登录或首次设置，方便 Ruby 集成测试直接驱动。
// 仅供 tests/ml_regression.rb 调用，不应该在生产中启动。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/xurenlu/sslcat/internal/ml"
)

func listenWithAddr(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

type testServer struct {
	extractor *ml.FeatureExtractor
	sampler   *ml.RequestSampler
	engine    *ml.InferenceEngine
	history   *ml.TrainingHistoryStore
	forest    atomic.Pointer[ml.IsolationForest]
	modelPath string
}

func newTestServer(dataDir string) *testServer {
	ts := &testServer{
		extractor: ml.NewFeatureExtractor(),
		modelPath: filepath.Join(dataDir, "isolation_forest.json"),
	}
	ts.sampler = ml.NewRequestSampler(ts.extractor, 5000)
	ts.engine = ml.NewInferenceEngineWithConfig(4, 200, 50*time.Millisecond, "drop")
	ts.history = ml.NewTrainingHistoryStore(filepath.Join(dataDir, "training_history.json"), 50)

	// 加载持久化模型（如果存在）
	if loaded, err := ml.LoadModelJSON(ts.modelPath); err == nil && loaded != nil {
		ts.forest.Store(loaded)
		ts.engine.SetModel(loaded, ts.extractor)
	}
	return ts
}

func (ts *testServer) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// /observe?path=&status=&ip= —— 用于让 Ruby 测试制造一条真实请求样本喂给 sampler + engine
func (ts *testServer) handleObserve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}
	statusCode, _ := strconv.Atoi(r.URL.Query().Get("status"))
	if statusCode == 0 {
		statusCode = 200
	}
	remoteAddr := r.URL.Query().Get("ip")
	if remoteAddr == "" {
		remoteAddr = "127.0.0.1"
	}

	// 构造一个合成的请求
	target := httptest.NewRequest("GET", path, nil)
	target.Header.Set("User-Agent", "ml-testserver/1.0")
	ts.sampler.Observe(target, statusCode, time.Millisecond, remoteAddr)

	// 如果模型已加载，也喂给推理引擎
	if forest := ts.forest.Load(); forest != nil {
		_, _ = ts.engine.Predict(target, statusCode, time.Millisecond, remoteAddr)
	}

	ts.writeJSON(w, 200, map[string]any{
		"observed":          true,
		"collected_samples": ts.sampler.Size(),
		"total_observed":    ts.sampler.TotalObserved(),
	})
}

// /train —— 用 sampler 现有样本训练
func (ts *testServer) handleTrain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NTrees        int     `json:"n_trees"`
		MaxSamples    int     `json:"max_samples"`
		Contamination float64 `json:"contamination"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.NTrees == 0 {
		req.NTrees = 50
	}
	if req.MaxSamples == 0 {
		req.MaxSamples = 64
	}
	if req.Contamination == 0 {
		req.Contamination = 0.1
	}

	samples := ts.sampler.Vectors()
	if len(samples) == 0 {
		ts.writeJSON(w, 400, map[string]any{"error": "no samples"})
		return
	}
	dim := len(samples[0])

	start := time.Now()
	cfg := &ml.ForestConfig{NTrees: req.NTrees, MaxSamples: req.MaxSamples, Contamination: req.Contamination, SubSampling: 1.0}
	forest := ml.NewIsolationForest(dim, cfg)
	if err := forest.Fit(samples); err != nil {
		ts.writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	duration := time.Since(start)

	ts.forest.Store(forest)
	ts.engine.SetModel(forest, ts.extractor)

	if err := ml.SaveModelJSON(forest, ts.modelPath); err != nil {
		log.Printf("save model failed: %v", err)
	}

	stats := forest.GetStats()
	entry := ml.TrainingHistoryEntry{
		ID:            fmt.Sprintf("train_%d", time.Now().UnixNano()),
		Timestamp:     time.Now(),
		NTrees:        cfg.NTrees,
		MaxSamples:    cfg.MaxSamples,
		Contamination: cfg.Contamination,
		FeatureDim:    dim,
		SampleCount:   len(samples),
		SampleSource:  "auto",
		DurationMS:    duration.Milliseconds(),
		Triggered:     "test",
	}
	if v, ok := stats["threshold"].(float64); ok {
		entry.Threshold = v
	}
	if v, ok := stats["avg_tree_depth"].(float64); ok {
		entry.AvgTreeDepth = v
	}
	_ = ts.history.Append(entry)

	ts.writeJSON(w, 200, map[string]any{
		"success":       true,
		"total_samples": len(samples),
		"feature_dim":   dim,
		"n_trees":       cfg.NTrees,
		"duration_ms":   duration.Milliseconds(),
	})
}

func (ts *testServer) handleStats(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"model_loaded":           ts.forest.Load() != nil,
		"collected_samples":      ts.sampler.Size(),
		"total_observed":         ts.sampler.TotalObserved(),
		"training_history_count": len(ts.history.List(0)),
	}
	if forest := ts.forest.Load(); forest != nil {
		fs := forest.GetStats()
		for k, v := range fs {
			resp[k] = v
		}
	}
	engineStats := ts.engine.GetStats()
	resp["total_predictions"] = engineStats["total_predictions"]
	resp["anomaly_count"] = engineStats["anomaly_count"]
	if last := ts.history.Last(); last != nil {
		resp["last_training"] = last.Timestamp.Format(time.RFC3339)
	}
	ts.writeJSON(w, 200, resp)
}

func (ts *testServer) handleRecent(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	preds := ts.engine.RecentPredictions(limit)
	ts.writeJSON(w, 200, map[string]any{"predictions": preds, "count": len(preds)})
}

func (ts *testServer) handleHistory(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	entries := ts.history.List(limit)
	ts.writeJSON(w, 200, map[string]any{"entries": entries, "count": len(entries)})
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address; default random port")
	dataDir := flag.String("data", "./data/ml-test", "data dir for model + history")
	flag.Parse()

	ts := newTestServer(*dataDir)

	mux := http.NewServeMux()
	mux.HandleFunc("/observe", ts.handleObserve)
	mux.HandleFunc("/train", ts.handleTrain)
	mux.HandleFunc("/stats", ts.handleStats)
	mux.HandleFunc("/predictions/recent", ts.handleRecent)
	mux.HandleFunc("/training/history", ts.handleHistory)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	srv := &http.Server{Addr: *addr, Handler: mux}
	ln, err := listenWithAddr(*addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// 立刻把端口写到 stdout，方便测试脚本读取
	fmt.Println("LISTENING", ln.Addr().String())
	log.Printf("ml-testserver listening on %s, data=%s", ln.Addr().String(), *dataDir)
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
