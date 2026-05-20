package web

import (
	"fmt"
	"io"
	"net/http"
)

const defaultJSONBodyLimit int64 = 1 << 20

func (s *Server) readLimitedRequestBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = defaultJSONBodyLimit
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("request body too large or unreadable: %w", err)
	}
	return data, nil
}
