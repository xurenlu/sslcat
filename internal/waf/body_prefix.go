package waf

import (
	"bytes"
	"io"
	"net/http"
)

const maxWAFBodyScanBytes int64 = 1 << 20

type replayReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *replayReadCloser) Close() error {
	return r.closer.Close()
}

func readRequestBodyPrefix(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = maxWAFBodyScanBytes
	}

	originalBody := r.Body
	prefix, err := io.ReadAll(io.LimitReader(originalBody, limit))
	r.Body = &replayReadCloser{
		reader: io.MultiReader(bytes.NewReader(prefix), originalBody),
		closer: originalBody,
	}
	if err != nil {
		return nil, err
	}

	return prefix, nil
}
