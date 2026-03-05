package statistics

import (
	"net/http"
	"testing"
)

// TestValueLearner_LearnFromDistribution 测试基于分布学习成功/失败值
func TestValueLearner_LearnFromDistribution(t *testing.T) {
	vl := NewValueLearner()
	path, field := "/api/inverted", "code"

	// 模拟「反直觉」API：code=1 成功，code=0 失败，且多数请求成功
	// 用 HTTP 状态区分：2xx 时 code=1，4xx 时 code=0
	for i := 0; i < 12; i++ {
		vl.Record(path, field, "1", 200)
	}
	for i := 0; i < 5; i++ {
		vl.Record(path, field, "0", 403)
	}

	// 学习后应得到：1=成功
	got := vl.GetLearnedSuccessValues(path, field)
	if len(got) == 0 {
		t.Fatal("GetLearnedSuccessValues() = empty, want learned success values")
	}
	// 1 应在成功列表中
	found := false
	for _, v := range got {
		if v == 1 || v == "1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetLearnedSuccessValues() = %v, want 1 in success list", got)
	}
}

// TestValueLearner_MajorityWhenAll2xx 全 2xx 时用多数派
func TestValueLearner_MajorityWhenAll2xx(t *testing.T) {
	vl := NewValueLearner()
	path, field := "/api/majority", "code"

	// 全 2xx，code=999 出现 12 次，code=-1 出现 3 次
	for i := 0; i < 12; i++ {
		vl.Record(path, field, "999", 200)
	}
	for i := 0; i < 3; i++ {
		vl.Record(path, field, "-1", 200)
	}

	got := vl.GetLearnedSuccessValues(path, field)
	if len(got) == 0 {
		t.Fatal("GetLearnedSuccessValues() = empty, want learned (majority = 999)")
	}
	found := false
	for _, v := range got {
		if v == 999 || v == "999" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetLearnedSuccessValues() = %v, want 999 (majority) in success list", got)
	}
}

// TestValueLearner_IntegrationWithAnalyzer 集成测试：学习后覆盖内置
func TestValueLearner_IntegrationWithAnalyzer(t *testing.T) {
	analyzer := NewResponseAnalyzer()

	// 某 API 用 code=100 表示成功，code=-1 表示失败
	// 先喂 15+ 次成功（code=100, 2xx）和失败（code=-1, 500）
	for i := 0; i < 10; i++ {
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}}
		analyzer.AnalyzeResponse(resp, []byte(`{"code": 100, "data": {}}`), "", "/api/custom")
	}
	for i := 0; i < 8; i++ {
		resp := &http.Response{StatusCode: 500, Header: http.Header{"Content-Type": []string{"application/json"}}}
		analyzer.AnalyzeResponse(resp, []byte(`{"code": -1, "error": "internal"}`), "", "/api/custom")
	}

	// 现在 code=100 应被学习为成功
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}}
	status, _ := analyzer.AnalyzeResponse(resp, []byte(`{"code": 100}`), "", "/api/custom")
	if status == nil {
		t.Fatal("AnalyzeResponse() = nil, want success for code=100")
	}
	if !status.IsSuccess {
		t.Errorf("AnalyzeResponse() IsSuccess = false, want true (learned 100=success)")
	}
}
