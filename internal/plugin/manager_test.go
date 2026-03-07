package plugin

import (
	"context"
	"sync"
	"testing"
	"time"
)

type testPlugin struct {
	info   *PluginInfo
	stopFn func(context.Context) error
}

func (p *testPlugin) GetInfo() *PluginInfo                             { return p.info }
func (p *testPlugin) Initialize(config map[string]interface{}) error   { return nil }
func (p *testPlugin) Start(ctx context.Context) error                  { return nil }
func (p *testPlugin) Stop(ctx context.Context) error                   { if p.stopFn != nil { return p.stopFn(ctx) }; return nil }
func (p *testPlugin) IsEnabled() bool                                  { return true }
func (p *testPlugin) SetEnabled(enabled bool)                          {}
func (p *testPlugin) GetConfig() map[string]interface{}                { return map[string]interface{}{} }
func (p *testPlugin) UpdateConfig(config map[string]interface{}) error { return nil }
func (p *testPlugin) GetHealth() *PluginHealth                         { return &PluginHealth{Status: "healthy"} }

func TestStopNoDeadlockWhenPluginReentersManager(t *testing.T) {
	m := NewManager(nil)

	var once sync.Once
	p := &testPlugin{
		info: &PluginInfo{ID: "plugin-1", Name: "plugin-1", Version: "test"},
		stopFn: func(ctx context.Context) error {
			once.Do(func() {
				_, _ = m.GetPlugin("plugin-1")
			})
			return nil
		},
	}

	m.plugins[p.info.ID] = p

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.Stop(context.Background())
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("plugin manager Stop deadlocked when plugin.Stop re-entered manager")
	}
}
