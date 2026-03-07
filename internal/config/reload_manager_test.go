package config

import (
	"sync"
	"testing"
	"time"
)

type testReloadableComponent struct {
	name     string
	validate func(*Config) error
	reload   func(*Config) error
}

func (c *testReloadableComponent) GetName() string { return c.name }

func (c *testReloadableComponent) Validate(cfg *Config) error {
	if c.validate != nil {
		return c.validate(cfg)
	}
	return nil
}

func (c *testReloadableComponent) Reload(cfg *Config) error {
	if c.reload != nil {
		return c.reload(cfg)
	}
	return nil
}

func TestReloadAllNoDeadlockWhenComponentReentersManager(t *testing.T) {
	rm := NewReloadManager()
	var once sync.Once

	component := &testReloadableComponent{
		name: "component-a",
		validate: func(cfg *Config) error {
			once.Do(func() {
				rm.RegisterComponent(&testReloadableComponent{name: "component-b"})
			})
			return nil
		},
	}
	rm.RegisterComponent(component)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = rm.ReloadAll(&Config{}, &Config{})
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReloadAll deadlocked when component callback re-entered manager")
	}
}
