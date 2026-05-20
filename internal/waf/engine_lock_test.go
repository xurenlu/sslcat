package waf

import (
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

type blockingRequestBody struct {
	readStarted chan struct{}
	unblock     chan struct{}
	once        sync.Once
}

func newBlockingRequestBody() *blockingRequestBody {
	return &blockingRequestBody{
		readStarted: make(chan struct{}),
		unblock:     make(chan struct{}),
	}
}

func (b *blockingRequestBody) Read(_ []byte) (int, error) {
	b.once.Do(func() {
		close(b.readStarted)
	})
	<-b.unblock
	return 0, io.EOF
}

func (b *blockingRequestBody) Close() error {
	return nil
}

func (b *blockingRequestBody) release() {
	close(b.unblock)
}

func TestCheckRequestDoesNotHoldRuleLockWhileReadingBody(t *testing.T) {
	engine := NewEngine(nil, nil, true)
	body := newBlockingRequestBody()

	req, err := http.NewRequest(http.MethodPost, "https://example.com/upload", body)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = engine.CheckRequest(req)
		close(done)
	}()

	select {
	case <-body.readStarted:
	case <-time.After(time.Second):
		t.Fatal("CheckRequest did not start reading request body")
	}

	addDone := make(chan error, 1)
	go func() {
		addDone <- engine.AddRule(&Rule{
			ID:          "lock_probe",
			Name:        "Lock Probe",
			Type:        RuleTypeCustom,
			Pattern:     `lock-probe-never-matches`,
			Action:      ActionLog,
			Enabled:     true,
			Description: "verifies rule writes are not blocked by body reads",
			CreatedAt:   time.Now(),
		})
	}()

	select {
	case err := <-addDone:
		if err != nil {
			t.Fatalf("AddRule() error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("AddRule blocked while CheckRequest was reading request body")
	}

	body.release()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("CheckRequest did not finish after releasing request body")
	}
}
