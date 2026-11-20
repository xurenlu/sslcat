package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadEffectivePreservesStartupFieldsAndAppliesHotChanges(t *testing.T) {
	oldCfg := getDefaultConfig()
	requested := *oldCfg
	requested.AdminPrefix = "/next-panel"
	requested.Server.Port = 18081
	requested.Server.Debug = !oldCfg.Server.Debug
	var applied *Config
	rm := NewReloadManager()
	rm.RegisterComponent(&testReloadableComponent{
		name: "observer",
		reload: func(cfg *Config) error {
			applied = cfg
			return nil
		},
	})
	active, err := rm.ReloadEffective(oldCfg, &requested)
	if err != nil {
		t.Fatal(err)
	}
	if active != applied || active.AdminPrefix != oldCfg.AdminPrefix || active.Server.Port != oldCfg.Server.Port {
		t.Fatal("startup fields leaked into active component configuration")
	}
	if active.Server.Debug != requested.Server.Debug {
		t.Fatal("hot change was not applied")
	}
	if requested.AdminPrefix != "/next-panel" || requested.Server.Port != 18081 {
		t.Fatal("requested configuration was mutated")
	}
	if rm.GetStats()["restart_required"] != true {
		t.Fatal("pending startup changes were not reported")
	}
}

func TestConfigWatcherApplyKeepsDefaultsAndActiveStartupConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sslcat.conf")
	if err := os.WriteFile(path, []byte(`{"admin_prefix":"/active"}`), 0600); err != nil {
		t.Fatal(err)
	}
	oldCfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	watcher, err := NewConfigWatcher(path, oldCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Stop()
	rm := NewReloadManager()
	watcher.OnConfigApply(rm.ReloadEffective)
	var published *Config
	watcher.OnReloadSuccess(func(cfg *Config) { published = cfg })
	requested := []byte(`{"admin_prefix":"/pending","server":{"debug":true}}`)
	if err := os.WriteFile(path, requested, 0600); err != nil {
		t.Fatal(err)
	}
	if err := watcher.ForceReload(); err != nil {
		t.Fatal(err)
	}
	active := watcher.GetConfig()
	if active != published || active.AdminPrefix != "/active" || !active.Server.Debug {
		t.Fatal("watcher published requested startup fields or lost hot changes")
	}
	if active.Server.Port != oldCfg.Server.Port || active.Server.Host != oldCfg.Server.Host {
		t.Fatal("omitted fields lost loader defaults")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != string(requested) {
		t.Fatal("pending disk configuration was overwritten")
	}
	hash, err := calculateConfigHash(path)
	if err != nil || watcher.GetLastHash() != hash {
		t.Fatal("watcher did not commit the accepted disk hash")
	}
}
