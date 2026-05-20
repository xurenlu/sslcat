package runner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

func newTestGitServer(t *testing.T) (*GitServer, *GitApp) {
	t.Helper()

	tempDir := t.TempDir()
	app := &GitApp{
		Name:        "demo",
		GitPath:     filepath.Join(tempDir, "demo", "git"),
		RepoDir:     filepath.Join(tempDir, "demo", "git", "repo"),
		BareRepo:    filepath.Join(tempDir, "demo", "git", "repo.git"),
		LogsDir:     filepath.Join(tempDir, "demo", "logs"),
		Domain:      "demo.localhost",
		AllowedKeys: []string{"ssh-key-fingerprint"},
		DeployConfig: &AppDeployConfig{
			SSL: SSLConfig{Enabled: false},
		},
	}

	cfg := &config.Config{
		AdminPrefix: "/admin",
		ConfigFile:  filepath.Join(tempDir, "sslcat.conf"),
		Server: config.ServerConfig{
			Port: 8080,
		},
		SSL: config.SSLConfig{
			DisableSelfSigned: true,
		},
		Admin: config.AdminConfig{
			Username: "admin",
		},
		Runners: config.RunnerConfig{
			Git: config.GitServerConfig{
				Enabled:  true,
				ReposDir: tempDir,
			},
		},
	}

	gs := &GitServer{
		config:       cfg,
		apps:         map[string]*GitApp{app.Name: app},
		logger:       logrus.New(),
		serverConfig: &GitServerConfig{Port: 22},
	}

	return gs, app
}

func TestGeneratedGitHooksAreValidBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	gs, app := newTestGitServer(t)
	hooks := map[string]string{
		"pre-receive":  gs.generatePreReceiveHook(app),
		"update":       gs.generateUpdateHook(app),
		"post-receive": gs.generatePostReceiveHook(app),
		"receive-pack": gs.generateReceivePackWrapper(app),
	}

	for name, content := range hooks {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(content), 0755); err != nil {
			t.Fatalf("write hook %s: %v", name, err)
		}

		cmd := exec.Command("bash", "-n", path)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hook %s is not valid bash: %v\n%s", name, err, output)
		}
	}
}

func TestReconcileRunnerContainersKeepsRunningContainer(t *testing.T) {
	gs, app := newTestGitServer(t)
	app.Port = 0
	app.Status = "failed"
	app.ContainerStatus = "missing"
	app.DeployConfig.ContainerName = "sslcat-demo-running"
	app.DeployConfig.ContainerID = "container-123"
	app.DeployConfig.Port = 18081
	app.DeployConfig.InternalPort = 9000

	calls := 0
	originalInspect := dockerInspectContainerStatus
	dockerInspectContainerStatus = func(containerRef string) (string, error) {
		calls++
		if containerRef != "sslcat-demo-running" {
			t.Fatalf("unexpected container ref: %s", containerRef)
		}
		return "running", nil
	}
	t.Cleanup(func() {
		dockerInspectContainerStatus = originalInspect
	})

	if err := gs.reconcileRunnerContainers(); err != nil {
		t.Fatalf("reconcile containers: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected one docker inspect call, got %d", calls)
	}
	if app.Status != "running" {
		t.Fatalf("expected app status running, got %q", app.Status)
	}
	if app.ContainerStatus != "active" {
		t.Fatalf("expected container status active, got %q", app.ContainerStatus)
	}
	if app.Port != 18081 {
		t.Fatalf("expected app port restored from deploy config, got %d", app.Port)
	}
	if len(gs.config.Proxy.Rules) != 1 {
		t.Fatalf("expected one recovered proxy rule, got %d", len(gs.config.Proxy.Rules))
	}
	rule := gs.config.Proxy.Rules[0]
	if rule.Domain != "demo.localhost" || rule.Port != 18081 || !rule.ManagedByGitDeploy {
		t.Fatalf("unexpected recovered proxy rule: %#v", rule)
	}
}

func TestReconcileRunnerContainersMarksMissingWithoutRestarting(t *testing.T) {
	gs, app := newTestGitServer(t)
	app.Status = "running"
	app.ContainerStatus = "active"
	app.DeployConfig.ContainerName = "sslcat-demo-missing"
	app.DeployConfig.ContainerID = "container-404"
	app.DeployConfig.Port = 18082

	calls := 0
	originalInspect := dockerInspectContainerStatus
	dockerInspectContainerStatus = func(containerRef string) (string, error) {
		calls++
		return "", fmt.Errorf("container %s not found", containerRef)
	}
	t.Cleanup(func() {
		dockerInspectContainerStatus = originalInspect
	})

	if err := gs.reconcileRunnerContainers(); err != nil {
		t.Fatalf("reconcile containers: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected one docker inspect call, got %d", calls)
	}
	if app.Status != "failed" {
		t.Fatalf("expected missing container to mark app failed, got %q", app.Status)
	}
	if app.ContainerStatus != "missing" {
		t.Fatalf("expected container status missing, got %q", app.ContainerStatus)
	}
	if app.DeployConfig.ContainerName != "sslcat-demo-missing" || app.DeployConfig.ContainerID != "container-404" {
		t.Fatalf("container identity should be preserved for diagnostics: %#v", app.DeployConfig)
	}
}

func TestInitGitRepoAndSetupHooks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	gs, app := newTestGitServer(t)
	if err := os.MkdirAll(app.LogsDir, 0755); err != nil {
		t.Fatalf("create logs dir: %v", err)
	}

	if err := gs.initGitRepo(app); err != nil {
		t.Fatalf("init git repo: %v", err)
	}
	if err := gs.setupGitHooks(app); err != nil {
		t.Fatalf("setup git hooks: %v", err)
	}

	for _, name := range []string{"pre-receive", "update", "post-receive", "receive-pack"} {
		path := filepath.Join(app.BareRepo, "hooks", name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected hook %s to exist: %v", name, err)
		}
		if info.Mode().Perm()&0100 == 0 {
			t.Fatalf("expected hook %s to be executable, mode=%s", name, info.Mode())
		}

		cmd := exec.Command("bash", "-n", path)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hook %s is not valid bash: %v\n%s", name, err, output)
		}
	}
}

func TestPostReceiveHookRendersShellPercentOperators(t *testing.T) {
	gs, app := newTestGitServer(t)
	content := gs.generatePostReceiveHook(app)

	if strings.Contains(content, "%%") {
		t.Fatalf("generated post-receive hook still contains Go fmt percent escapes")
	}
	if !strings.Contains(content, "$((IDLE_ELAPSED % 2))") {
		t.Fatalf("generated post-receive hook is missing shell modulo expression")
	}
	if !strings.Contains(content, `printf "${COLOR_RESET} %3ds"`) {
		t.Fatalf("generated post-receive hook is missing progress printf format")
	}
	if !strings.Contains(content, `ADMIN_PORT="8080"`) {
		t.Fatalf("generated post-receive hook is missing admin port")
	}
	if !strings.Contains(content, `ADMIN_PREFIX="/admin"`) {
		t.Fatalf("generated post-receive hook is missing admin prefix")
	}
	if !strings.Contains(content, `API_URL="http://127.0.0.1:$ADMIN_PORT$ADMIN_PREFIX/api/git-server/apps/$APP_NAME/deploy"`) {
		t.Fatalf("generated post-receive hook uses unexpected deploy API URL")
	}
}

func TestInternalDeployTriggersBypassAppKeyBinding(t *testing.T) {
	gs, _ := newTestGitServer(t)

	for _, key := range []string{"system", "web-trigger", "git-hook"} {
		if !gs.CheckPushPermission("demo", key) {
			t.Fatalf("internal key %q should be allowed to trigger deployment", key)
		}
	}
	if gs.CheckPushPermission("demo", "other-key") {
		t.Fatalf("unbound external key should not be allowed")
	}
}

func TestDockerRunArgsIncludeRunnerSpec(t *testing.T) {
	spec := RunnerSpec{
		SourceType:   RunnerSourceDockerImage,
		RuntimeType:  RunnerRuntimeDockerImage,
		InternalPort: 9000,
		EnvVars: map[string]string{
			"APP_ENV": "production",
			"PORT":    "should-not-override-internal-port",
		},
		DockerImage: &DockerImageRunConfig{
			Image:         "registry.example.com/demo/api:1.2.3",
			Entrypoint:    "/app/entrypoint",
			Command:       []string{"serve", "--config", "/app/config.yml"},
			RestartPolicy: "always",
			EnvVars: map[string]string{
				"LOG_LEVEL": "info",
			},
			Volumes: []DockerVolumeMount{
				{Source: "/srv/demo/data", Target: "/app/data"},
				{Source: "/srv/demo/config.yml", Target: "/app/config.yml", ReadOnly: true},
			},
		},
	}

	got := spec.DockerRunArgs("sslcat-demo-123", 18080, "fallback:latest", 8080)
	want := []string{
		"run", "-d",
		"--name", "sslcat-demo-123",
		"-p", "18080:9000",
		"-e", "PORT=9000",
		"--restart", "always",
		"-e", "APP_ENV=production",
		"-e", "LOG_LEVEL=info",
		"-v", "/srv/demo/data:/app/data",
		"-v", "/srv/demo/config.yml:/app/config.yml:ro",
		"--entrypoint", "/app/entrypoint",
		"registry.example.com/demo/api:1.2.3",
		"serve", "--config", "/app/config.yml",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected docker args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestArtifactRunnerSpecFallsBackToDefaultDockerPort(t *testing.T) {
	spec := RunnerSpec{
		SourceType:  RunnerSourceDirectory,
		RuntimeType: RunnerRuntimeDockerImage,
		Artifact: &ArtifactRunConfig{
			Kind:         RunnerSourceDirectory,
			Path:         "/srv/uploads/demo",
			StartCommand: "./server",
			EnvVars: map[string]string{
				"APP_ENV": "staging",
			},
		},
	}

	got := spec.DockerRunArgs("sslcat-upload-123", 18081, "sslcat-upload-demo:latest", 7000)
	want := []string{
		"run", "-d",
		"--name", "sslcat-upload-123",
		"-p", "18081:7000",
		"-e", "PORT=7000",
		"--restart", "unless-stopped",
		"-e", "APP_ENV=staging",
		"sslcat-upload-demo:latest",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected artifact docker args:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestUpdateAppRuntimePersistsDirectImageSpec(t *testing.T) {
	gs, app := newTestGitServer(t)
	spec := RunnerSpec{
		SourceType:   RunnerSourceDockerImage,
		RuntimeType:  RunnerRuntimeDockerImage,
		InternalPort: 9090,
		EnvVars: map[string]string{
			"APP_ENV": "production",
		},
		DockerImage: &DockerImageRunConfig{
			Image: "registry.example.com/demo/api:1.2.3",
			Volumes: []DockerVolumeMount{
				{Source: "/srv/demo/data", Target: "/app/data"},
			},
		},
	}

	if err := gs.UpdateAppRuntime(app.Name, spec); err != nil {
		t.Fatalf("update runtime: %v", err)
	}

	if app.SourceType != RunnerSourceDockerImage {
		t.Fatalf("unexpected source type: %s", app.SourceType)
	}
	if app.DockerImage != "registry.example.com/demo/api:1.2.3" {
		t.Fatalf("unexpected docker image: %s", app.DockerImage)
	}
	if !app.PendingRestart {
		t.Fatalf("runtime update should mark app pending restart")
	}
	if app.DeployConfig == nil || app.DeployConfig.Runtime == nil {
		t.Fatalf("runtime spec should be stored in deploy config")
	}
	if app.DeployConfig.InternalPort != 9090 {
		t.Fatalf("unexpected internal port: %d", app.DeployConfig.InternalPort)
	}
	if got := app.EnvVars["APP_ENV"]; got != "production" {
		t.Fatalf("runtime env should be merged into app env, got %q", got)
	}
}
