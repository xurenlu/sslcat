package statistics

import (
	"net/http"
	"testing"
)

func TestFailureDetector_DetectByErrorField(t *testing.T) {
	fd := NewFailureDetector()

	tests := []struct {
		name       string
		body       string
		wantFailure bool
	}{
		{
			name:        "error field non-empty",
			body:        `{"error": "something went wrong"}`,
			wantFailure: true,
		},
		{
			name:        "errmsg non-empty",
			body:        `{"errmsg": "invalid request"}`,
			wantFailure: true,
		},
		{
			name:        "error null - no failure",
			body:        `{"error": null, "data": {"id": 1}}`,
			wantFailure: false,
		},
		{
			name:        "error empty string - no failure",
			body:        `{"error": "", "data": {"id": 1}}`,
			wantFailure: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
			}
			got := fd.DetectFailure(resp, []byte(tt.body), "/api/test")
			if tt.wantFailure && got == nil {
				t.Errorf("DetectFailure() = nil, want failure")
			}
			if !tt.wantFailure && got != nil && got.IsSuccess == false {
				t.Errorf("DetectFailure() = failure, want success/nil")
			}
		})
	}
}

func TestFailureDetector_DetectBySuccessFalse(t *testing.T) {
	fd := NewFailureDetector()

	body := `{"success": false, "message": "failed"}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	got := fd.DetectFailure(resp, []byte(body), "/api/test")
	if got == nil {
		t.Errorf("DetectFailure() = nil, want failure for success:false")
	}
	if got != nil && got.IsSuccess {
		t.Errorf("DetectFailure() IsSuccess = true, want false")
	}
}

func TestFailureDetector_ShortResponseHeuristic(t *testing.T) {
	fd := NewFailureDetector()

	// 先喂一些"正常"长响应，建立画像
	longBody := `{"data": {"items": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]}}`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	for i := 0; i < 30; i++ {
		fd.DetectFailure(resp, []byte(longBody), "/api/items")
	}

	// 短响应 + error 结构
	shortBody := `{"error": "not found"}` // ~22 bytes
	got := fd.DetectFailure(resp, []byte(shortBody), "/api/items")
	// 样本不足 20 时用 200 字节阈值，22 < 200 且 has error -> 应判失败
	if got == nil {
		t.Errorf("DetectFailure() = nil for short error response, want failure")
	}
}

func TestCountKeysAndDepth(t *testing.T) {
	tests := []struct {
		name      string
		data      interface{}
		wantKeys  int
		wantDepth int
	}{
		{
			name:      "flat map",
			data:      map[string]interface{}{"a": 1, "b": 2},
			wantKeys:  2,
			wantDepth: 1,
		},
		{
			name: "nested map",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"inner": 1,
				},
			},
			wantKeys:  1,
			wantDepth: 2, // root -> data -> primitive
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, depth := countKeysAndDepth(tt.data)
			if keys != tt.wantKeys || depth != tt.wantDepth {
				t.Errorf("countKeysAndDepth() = (%d, %d), want (%d, %d)", keys, depth, tt.wantKeys, tt.wantDepth)
			}
		})
	}
}
