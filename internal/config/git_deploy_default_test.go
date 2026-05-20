package config

import "testing"

func TestDefaultConfigEnablesGitDeploy(t *testing.T) {
	cfg := getDefaultConfig()
	if !cfg.Runners.Git.Enabled {
		t.Fatalf("default runners.git.enabled should be true")
	}
	if cfg.Runners.Git.ReposDir == "" {
		t.Fatalf("default runners.git.repos_dir should not be empty")
	}
}
