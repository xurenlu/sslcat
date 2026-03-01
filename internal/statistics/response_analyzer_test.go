package statistics

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestIsAPIRequest 测试 API 请求识别
func TestIsAPIRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *http.Request
		want    bool
	}{
		{
			name: "JSON Content-Type",
			request: &http.Request{
				Header: http.Header{"Content-Type": []string{"application/json"}},
				URL:    &url.URL{Path: "/test"},
			},
			want: true,
		},
		{
			name: "API path prefix",
			request: &http.Request{
				Header: http.Header{},
				URL:    &url.URL{Path: "/api/users"},
			},
			want: true,
		},
		{
			name: "v1 path prefix",
			request: &http.Request{
				Header: http.Header{},
				URL:    &url.URL{Path: "/v1/data"},
			},
			want: true,
		},
		{
			name: "Static resource",
			request: &http.Request{
				Header: http.Header{},
				URL:    &url.URL{Path: "/index.html"},
			},
			want: false,
		},
		{
			name: "JSON extension",
			request: &http.Request{
				Header: http.Header{},
				URL:    &url.URL{Path: "/data.json"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAPIRequest(tt.request); got != tt.want {
				t.Errorf("IsAPIRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestResponseAnalyzer_AnalyzeResponse 测试响应分析器
func TestResponseAnalyzer_AnalyzeResponse(t *testing.T) {
	analyzer := NewResponseAnalyzer()

	tests := []struct {
		name       string
		body       string
		apiPath    string
		wantStatus *BusinessStatus
	}{
		{
			name: "Status field success (status=0)",
			body: `{"status": 0, "data": "success"}`,
			apiPath: "/api/test",
			wantStatus: &BusinessStatus{
				IsSuccess: true,
				Code:      0,
				Message:   "0",
				Source:    "status",
			},
		},
		{
			name: "Status field failure (status=-1)",
			body: `{"status": -1, "msg": "error"}`,
			apiPath: "/api/test",
			wantStatus: &BusinessStatus{
				IsSuccess: false,
				Code:      -1,
				Message:   "-1",
				Source:    "status",
			},
		},
		{
			name: "Code field success (code=0)",
			body: `{"code": 0, "message": "ok"}`,
			apiPath: "/api/test",
			wantStatus: &BusinessStatus{
				IsSuccess: true,
				Code:      0,
				Message:   "0",
				Source:    "code",
			},
		},
		{
			name: "Errcode field success (errcode=0)",
			body: `{"errcode": 0, "errmsg": "success"}`,
			apiPath: "/api/test",
			wantStatus: &BusinessStatus{
				IsSuccess: true,
				Code:      0,
				Message:   "0",
				Source:    "errcode",
			},
		},
		{
			name: "Success field true",
			body: `{"success": true, "data": {}}`,
			apiPath: "/api/test",
			wantStatus: &BusinessStatus{
				IsSuccess: true,
				Code:      1,
				Message:   "true",
				Source:    "success",
			},
		},
		{
			name: "Nested status field",
			body: `{"data": {"status": 0, "result": "ok"}}`,
			apiPath: "/api/test",
			wantStatus: &BusinessStatus{
				IsSuccess: true,
				Code:      0,
				Message:   "0",
				Source:    "data.status",
			},
		},
		{
			name: "Status string success",
			body: `{"status": "success", "data": {}}`,
			apiPath: "/api/test",
			wantStatus: &BusinessStatus{
				IsSuccess: true,
				Code:      0,
				Message:   "success",
				Source:    "status",
			},
		},
		{
			name: "Non-JSON response",
			body: "plain text response",
			apiPath: "/api/test",
			wantStatus: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建 HTTP 响应
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       nil,
			}

			body := []byte(tt.body)
			if tt.body != "plain text response" {
				resp.Header.Set("Content-Type", "application/json")
			}

			// 分析响应
			gotStatus, err := analyzer.AnalyzeResponse(resp, body, tt.apiPath)

			// 检查错误
			if err != nil && tt.wantStatus != nil {
				t.Errorf("AnalyzeResponse() error = %v", err)
				return
			}

			// 比较结果
			if tt.wantStatus == nil {
				if gotStatus != nil {
					t.Errorf("AnalyzeResponse() = %v, want nil", gotStatus)
				}
				return
			}

			if gotStatus == nil {
				t.Errorf("AnalyzeResponse() = nil, want %v", tt.wantStatus)
				return
			}

			if gotStatus.IsSuccess != tt.wantStatus.IsSuccess {
				t.Errorf("AnalyzeResponse() IsSuccess = %v, want %v", gotStatus.IsSuccess, tt.wantStatus.IsSuccess)
			}
			if gotStatus.Code != tt.wantStatus.Code {
				t.Errorf("AnalyzeResponse() Code = %v, want %v", gotStatus.Code, tt.wantStatus.Code)
			}
			if gotStatus.Source != tt.wantStatus.Source {
				t.Errorf("AnalyzeResponse() Source = %v, want %v", gotStatus.Source, tt.wantStatus.Source)
			}
		})
	}
}

// TestResponseAnalyzer_LearnPattern 测试模式学习
func TestResponseAnalyzer_LearnPattern(t *testing.T) {
	analyzer := NewResponseAnalyzer()

	apiPath := "/api/learn"

	// 模拟多次相同结构的响应
	for i := 0; i < 10; i++ {
		body := []byte(`{"custom_status": 0, "result": "ok"}`)
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}
		analyzer.AnalyzeResponse(resp, body, apiPath)
	}

	// 检查是否学习到了模式
	patterns := analyzer.GetLearnedPatterns(apiPath)
	if len(patterns) > 0 {
		t.Logf("Learned %d patterns for %s", len(patterns), apiPath)
		for i, p := range patterns {
			t.Logf("Pattern %d: FieldPath=%s, SuccessValues=%v", i, p.FieldPath, p.SuccessValues)
		}
	}
}

// TestCopyResponseBody 测试响应体复制
func TestCopyResponseBody(t *testing.T) {
	originalBody := `{"test": "data"}`

	resp := &http.Response{
		Body: http.NoBody,
	}

	// 测试 NoBody
	body, err := CopyResponseBody(resp)
	if err != nil {
		t.Errorf("CopyResponseBody() error = %v", err)
	}
	if body != nil {
		t.Errorf("CopyResponseBody() = %v, want nil for NoBody", body)
	}

	// 测试正常响应体
	resp.Body = http.NoBody
	bodyStr := strings.NewReader(originalBody)
	resp.Body = &readCloser{Reader: bodyStr}

	body, err = CopyResponseBody(resp)
	if err != nil {
		t.Errorf("CopyResponseBody() error = %v", err)
	}
	if string(body) != originalBody {
		t.Errorf("CopyResponseBody() = %v, want %v", string(body), originalBody)
	}

	// 验证 Body 可以重新读取
	newBody := make([]byte, len(originalBody))
	n, _ := resp.Body.Read(newBody)
	if n != len(originalBody) {
		t.Errorf("Body re-read failed, got %d bytes", n)
	}
}

// readCloser 用于测试的 io.ReadCloser 实现
type readCloser struct {
	*strings.Reader
}

func (rc *readCloser) Close() error {
	return nil
}

// TestExtractFieldValue 测试字段提取
func TestExtractFieldValue(t *testing.T) {
	analyzer := NewResponseAnalyzer()

	tests := []struct {
		name      string
		data      interface{}
		fieldPath string
		want      interface{}
	}{
		{
			name:      "Simple field",
			data:      map[string]interface{}{"status": 0},
			fieldPath: "status",
			want:      0,
		},
		{
			name: "Nested field",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"status": 1,
				},
			},
			fieldPath: "data.status",
			want:      1,
		},
		{
			name:      "Missing field",
			data:      map[string]interface{}{"other": "value"},
			fieldPath: "status",
			want:      nil,
		},
		{
			name: "Deep nested field",
			data: map[string]interface{}{
				"response": map[string]interface{}{
					"data": map[string]interface{}{
						"code": 200,
					},
				},
			},
			fieldPath: "response.data.code",
			want:      200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.extractFieldValue(tt.data, tt.fieldPath)
			if !compareValues(got, tt.want) {
				t.Errorf("extractFieldValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

// 辅助函数：比较值
func compareValues(a, b interface{}) bool {
	switch va := a.(type) {
	case int:
		if vb, ok := b.(int); ok {
			return va == vb
		}
		if vb, ok := b.(float64); ok {
			return float64(va) == vb
		}
	case float64:
		if vb, ok := b.(int); ok {
			return va == float64(vb)
		}
		if vb, ok := b.(float64); ok {
			return va == vb
		}
	case string:
		if vb, ok := b.(string); ok {
			return va == vb
		}
	case nil:
		return b == nil
	}
	return false
}

// TestBusinessStatusJSON 测试 BusinessStatus JSON 序列化
func TestBusinessStatusJSON(t *testing.T) {
	status := &BusinessStatus{
		IsSuccess: true,
		Code:      0,
		Message:   "success",
		Source:    "status",
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Errorf("Marshal error = %v", err)
	}

	var decoded BusinessStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Errorf("Unmarshal error = %v", err)
	}

	if decoded.IsSuccess != status.IsSuccess ||
		decoded.Code != status.Code ||
		decoded.Message != status.Message ||
		decoded.Source != status.Source {
		t.Errorf("JSON round-trip failed, got %+v, want %+v", decoded, status)
	}
}
