package web

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReadRecentJSONLinesReturnsTailOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	var data []byte
	for i := 0; i < 20; i++ {
		data = append(data, []byte(fmt.Sprintf(`{"idx":%d}`+"\n", i))...)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	rows, err := readRecentJSONLines(path, 5, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("got %d rows, want 5", len(rows))
	}
	if got := int(rows[0]["idx"].(float64)); got != 15 {
		t.Fatalf("first tail row idx = %d, want 15", got)
	}
	if got := int(rows[4]["idx"].(float64)); got != 19 {
		t.Fatalf("last tail row idx = %d, want 19", got)
	}
}

func TestReadTailLinesHonorsMaxBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.log")
	var data []byte
	for i := 0; i < 100; i++ {
		data = append(data, []byte(fmt.Sprintf("line-%03d\n", i))...)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	lines, err := readTailLines(path, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) >= 50 {
		t.Fatalf("maxBytes should limit returned line count, got %d", len(lines))
	}
	if lines[len(lines)-1] != "line-099" {
		t.Fatalf("tail should include last line, got %q", lines[len(lines)-1])
	}
}
