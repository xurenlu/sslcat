package web

import (
	"strings"
	"testing"
)

func TestBuildPHPAdminValue(t *testing.T) {
	tests := []struct {
		name    string
		vars    map[string]string
		want    string
		wantErr bool
	}{
		{
			name: "empty",
			vars: nil,
			want: "",
		},
		{
			name: "single directive",
			vars: map[string]string{"session.upload_progress.enabled": "0"},
			want: "session.upload_progress.enabled=0",
		},
		{
			name: "sorted and lowercased keys",
			vars: map[string]string{
				"Memory_Limit":                    "-1",
				"session.upload_progress.enabled": "0",
			},
			want: "memory_limit=-1\nsession.upload_progress.enabled=0",
		},
		{
			name: "empty value skipped",
			vars: map[string]string{"memory_limit": "   "},
			want: "",
		},
		{
			name:    "directive not in whitelist",
			vars:    map[string]string{"auto_prepend_file": "/tmp/x.php"},
			wantErr: true,
		},
		{
			name:    "newline injection in value",
			vars:    map[string]string{"memory_limit": "-1\nauto_prepend_file=/tmp/x.php"},
			wantErr: true,
		},
		{
			name:    "trailing newline",
			vars:    map[string]string{"memory_limit": "128M\n"},
			wantErr: true,
		},
		{
			name:    "carriage return",
			vars:    map[string]string{"memory_limit": "\r128M"},
			wantErr: true,
		},
		{
			name:    "NUL",
			vars:    map[string]string{"memory_limit": "128M\x00"},
			wantErr: true,
		},
		{
			name:    "duplicate normalized keys",
			vars:    map[string]string{"Memory_Limit": "128M", " memory_limit ": "256M"},
			wantErr: true,
		},
		{
			name:    "empty directive name",
			vars:    map[string]string{"  ": "1"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildPHPAdminValue(tt.vars)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got value %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildPHPAdminValueRejectsInjectedDirectives(t *testing.T) {
	// 换行必须被拒绝，否则单条 php_admin_value 会被拆成多条指令。
	_, err := buildPHPAdminValue(map[string]string{
		"memory_limit": "-1\r\nauto_prepend_file=/tmp/payload.php",
	})
	if err == nil {
		t.Fatal("expected newline injection to be rejected")
	}
	if !strings.Contains(err.Error(), "memory_limit") {
		t.Fatalf("error should name the offending directive, got: %v", err)
	}
}

func TestSanitizePHPAdminIni(t *testing.T) {
	got := sanitizePHPAdminIni(map[string]string{
		" Memory_Limit ":                  " -1 ",
		"session.upload_progress.enabled": "0",
		"log_errors":                      "",
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 entries after sanitizing, got %d: %v", len(got), got)
	}
	if got["memory_limit"] != "-1" {
		t.Fatalf("expected memory_limit=-1, got %v", got)
	}
	if got["session.upload_progress.enabled"] != "0" {
		t.Fatalf("expected upload_progress=0, got %v", got)
	}

	if sanitizePHPAdminIni(nil) != nil {
		t.Fatal("nil input should stay nil")
	}
	if sanitizePHPAdminIni(map[string]string{"log_errors": " "}) != nil {
		t.Fatal("all-empty input should collapse to nil")
	}
}
