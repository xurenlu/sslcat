package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadLimitedRequestBodyRejectsOversize(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader("abcdef"))
	rec := httptest.NewRecorder()

	if _, err := s.readLimitedRequestBody(rec, req, 3); err == nil {
		t.Fatal("expected oversized body to be rejected")
	}
}

func TestReadLimitedRequestBodyAllowsWithinLimit(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader("abc"))
	rec := httptest.NewRecorder()

	got, err := s.readLimitedRequestBody(rec, req, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Fatalf("body = %q, want abc", string(got))
	}
}
