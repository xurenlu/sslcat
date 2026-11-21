package config

import (
	"errors"
	"reflect"
	"testing"
)

func TestReloadAllRollsBackAttemptedComponents(t *testing.T) {
	oldCfg := getDefaultConfig()
	newCfg := *oldCfg
	newCfg.Server.Debug = !oldCfg.Server.Debug
	rm := NewReloadManager()
	failure := errors.New("apply failure")
	var order []string
	active := map[string]*Config{}
	for _, name := range []string{"first", "second", "untouched"} {
		rm.RegisterComponent(&testReloadableComponent{
			name: name,
			reload: func(cfg *Config) error {
				active[name] = cfg
				phase := "new"
				if cfg == oldCfg {
					phase = "old"
				}
				order = append(order, name+":"+phase)
				if name == "second" && cfg == &newCfg {
					return failure
				}
				return nil
			},
		})
	}
	if err := rm.ReloadAll(oldCfg, &newCfg); !errors.Is(err, failure) {
		t.Fatalf("expected original apply failure, got %v", err)
	}
	want := []string{"first:new", "second:new", "second:old", "first:old"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("reload/rollback order %v, want %v", order, want)
	}
	if active["first"] != oldCfg || active["second"] != oldCfg || active["untouched"] != nil {
		t.Fatal("attempted components were not restored or later component was applied")
	}
	stats := rm.GetStats()
	if stats["success_count"] != int64(0) || stats["error_count"] != int64(1) {
		t.Fatalf("incorrect failure statistics: %v", stats)
	}
}

func TestReloadAllReportsRollbackFailure(t *testing.T) {
	oldCfg := getDefaultConfig()
	newCfg := *oldCfg
	newCfg.Server.Debug = !oldCfg.Server.Debug
	applyFailure := errors.New("apply failure")
	rollbackFailure := errors.New("rollback failure")
	rm := NewReloadManager()
	rm.RegisterComponent(&testReloadableComponent{
		name: "partial",
		reload: func(cfg *Config) error {
			if cfg == oldCfg {
				return rollbackFailure
			}
			return applyFailure
		},
	})
	err := rm.ReloadAll(oldCfg, &newCfg)
	if !errors.Is(err, applyFailure) || !errors.Is(err, rollbackFailure) {
		t.Fatalf("expected both apply and rollback errors, got %v", err)
	}
}

func TestReloadAllKeepsRestartRequirementUntilProcessRestart(t *testing.T) {
	oldCfg := getDefaultConfig()
	newCfg := *oldCfg
	newCfg.Server.Port = 18081
	rm := NewReloadManager()
	rm.RegisterComponent(&testReloadableComponent{name: "component"})
	if err := rm.ReloadAll(oldCfg, &newCfg); err != nil {
		t.Fatal(err)
	}
	stats := rm.GetStats()
	if stats["restart_required"] != true || !reflect.DeepEqual(stats["restart_fields"], []string{"Server.Port"}) {
		t.Fatalf("missing restart requirement: %v", stats)
	}
	fields := stats["restart_fields"].([]string)
	fields[0] = "caller mutation"
	if err := rm.ReloadAll(&newCfg, &newCfg); err != nil {
		t.Fatal(err)
	}
	if got := rm.GetStats()["restart_fields"]; !reflect.DeepEqual(got, []string{"Server.Port"}) {
		t.Fatalf("restart requirement was cleared or externally mutated: %v", got)
	}
}

func TestDetectChangesStartupFieldsRequireRestart(t *testing.T) {
	oldCfg := getDefaultConfig()
	newCfg := *oldCfg
	newCfg.Server.Host = "127.0.0.1"
	newCfg.Server.Debug = !oldCfg.Server.Debug
	detector := NewChangeDetector()
	detector.DetectChanges(oldCfg, &newCfg)
	if detector.GetMaxChangeLevel() != HardReload {
		t.Fatal("soft change hid startup-only host change")
	}
}
