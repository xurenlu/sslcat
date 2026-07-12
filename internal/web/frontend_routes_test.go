package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xurenlu/sslcat/internal/assets"
)

func TestHandleFrontendLogo(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/sslcat-panel/logo.png", nil)

	server.handleFrontendLogo(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "image/png" {
		t.Fatalf("content type = %q, want image/png", contentType)
	}
	if len(recorder.Body.Bytes()) != len(assets.LogoPNG) {
		t.Fatalf("logo bytes = %d, want %d", len(recorder.Body.Bytes()), len(assets.LogoPNG))
	}
}
