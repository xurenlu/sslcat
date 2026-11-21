package config

import (
	"fmt"
	"reflect"
	"strings"
)

func runtimeReloadConfig(oldConfig, requested *Config, changes []ConfigChange) (*Config, error) {
	var active *Config
	for _, change := range changes {
		if change.Level != HardReload {
			continue
		}
		if active == nil {
			copy := *requested
			active = &copy
		}
		dst := reflect.ValueOf(active).Elem()
		src := reflect.ValueOf(oldConfig).Elem()
		for _, field := range strings.Split(change.Field, ".") {
			if dst.Kind() != reflect.Struct || src.Kind() != reflect.Struct {
				return nil, fmt.Errorf("unsupported restart field: %s", change.Field)
			}
			dst = dst.FieldByName(field)
			src = src.FieldByName(field)
			if !dst.IsValid() || !src.IsValid() {
				return nil, fmt.Errorf("unknown restart field: %s", change.Field)
			}
		}
		if !dst.CanSet() {
			return nil, fmt.Errorf("restart field cannot be restored: %s", change.Field)
		}
		dst.Set(src)
	}
	if active == nil {
		return requested, nil
	}
	return active, nil
}
