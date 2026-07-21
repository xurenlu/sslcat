package logger

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestRotatorCloseDrainsQueuedWrites(t *testing.T) {
	path := t.TempDir() + "/audit.log"
	rotator, err := NewRotator(path, 1024*1024, 2)
	if err != nil {
		t.Fatalf("NewRotator() error = %v", err)
	}

	const lines = 500
	for i := 0; i < lines; i++ {
		if _, err := rotator.Write([]byte("queued log line\n")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := rotator.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got := strings.Count(string(data), "queued log line"); got != lines {
		t.Fatalf("drained lines = %d, want %d", got, lines)
	}
	if _, err := rotator.Write([]byte("after close\n")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write() after Close error = %v, want io.ErrClosedPipe", err)
	}
}

func TestRotatorConcurrentWriteAndClose(t *testing.T) {
	path := t.TempDir() + "/concurrent.log"
	rotator, err := NewRotator(path, 1024*1024, 2)
	if err != nil {
		t.Fatalf("NewRotator() error = %v", err)
	}

	var writers sync.WaitGroup
	for i := 0; i < 8; i++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for j := 0; j < 200; j++ {
				_, _ = rotator.Write([]byte("concurrent log line\n"))
			}
		}()
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- rotator.Close()
	}()
	writers.Wait()
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := rotator.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
