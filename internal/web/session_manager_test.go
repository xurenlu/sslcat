package web

import (
	"sync"
	"testing"
	"time"
)

type noopSessionLogger struct{}

func (noopSessionLogger) Infof(format string, args ...interface{})  {}
func (noopSessionLogger) Warnf(format string, args ...interface{})  {}
func (noopSessionLogger) Errorf(format string, args ...interface{}) {}
func (noopSessionLogger) Debugf(format string, args ...interface{}) {}

type callbackSessionStorage struct {
	mu     sync.RWMutex
	data   map[string]*Session
	onSet  func()
	onOnce sync.Once
}

func (s *callbackSessionStorage) Set(key string, session *Session) error {
	if s.onSet != nil {
		s.onOnce.Do(s.onSet)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = session
	return nil
}

func (s *callbackSessionStorage) Get(key string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.data[key]
	if !ok {
		return nil, errSessionNotFound
	}
	return session, nil
}

func (s *callbackSessionStorage) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *callbackSessionStorage) GetAll() (map[string]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]*Session, len(s.data))
	for k, v := range s.data {
		result[k] = v
	}
	return result, nil
}

func (s *callbackSessionStorage) Close() error { return nil }

var errSessionNotFound = &sessionStorageError{message: "session not found"}

type sessionStorageError struct {
	message string
}

func (e *sessionStorageError) Error() string { return e.message }

func TestCreateSessionNoDeadlockWithReentrantStorage(t *testing.T) {
	storage := &callbackSessionStorage{data: make(map[string]*Session)}
	sm := NewSessionManagerWithStorage(storage, noopSessionLogger{})
	storage.onSet = func() {
		_ = sm.GetSessionStats()
	}

	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		defer close(done)
		_, err := sm.CreateSession("alice", "admin", "127.0.0.1", "test-agent")
		if err != nil {
			errCh <- err
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("CreateSession deadlocked when storage callback re-entered session manager")
	}

	select {
	case err := <-errCh:
		t.Fatalf("CreateSession returned error: %v", err)
	default:
	}
}
