package waf

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadRequestBodyPrefixRestoresFullBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("abcdef"))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	prefix, err := readRequestBodyPrefix(req, 3)
	if err != nil {
		t.Fatalf("readRequestBodyPrefix() error = %v", err)
	}
	if string(prefix) != "abc" {
		t.Fatalf("prefix = %q, want abc", string(prefix))
	}

	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll(restored body) error = %v", err)
	}
	if string(restored) != "abcdef" {
		t.Fatalf("restored body = %q, want abcdef", string(restored))
	}
}

func TestReadRequestBodyPrefixUsesDefaultLimit(t *testing.T) {
	body := strings.Repeat("x", int(maxWAFBodyScanBytes)+8)
	req, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	prefix, err := readRequestBodyPrefix(req, 0)
	if err != nil {
		t.Fatalf("readRequestBodyPrefix() error = %v", err)
	}
	if int64(len(prefix)) != maxWAFBodyScanBytes {
		t.Fatalf("prefix len = %d, want %d", len(prefix), maxWAFBodyScanBytes)
	}

	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll(restored body) error = %v", err)
	}
	if len(restored) != len(body) {
		t.Fatalf("restored body len = %d, want %d", len(restored), len(body))
	}
}
