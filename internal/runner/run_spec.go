package runner

import (
	"fmt"
	"sort"
)

// RunnerSourceType 描述应用从哪里来。运行入口可以不同，但最终应归一到同一套运行规格。
type RunnerSourceType string

const (
	RunnerSourceGit         RunnerSourceType = "git"
	RunnerSourceArtifact    RunnerSourceType = "artifact"
	RunnerSourceBinary      RunnerSourceType = "binary"
	RunnerSourceDirectory   RunnerSourceType = "directory"
	RunnerSourceDockerImage RunnerSourceType = "docker_image"
	RunnerSourceTemplate    RunnerSourceType = "template"
)

// RunnerRuntimeType 描述应用最终如何运行。
type RunnerRuntimeType string

const (
	RunnerRuntimeAuto        RunnerRuntimeType = "auto"
	RunnerRuntimeProcess     RunnerRuntimeType = "process"
	RunnerRuntimeDockerImage RunnerRuntimeType = "docker_image"
	RunnerRuntimeCompose     RunnerRuntimeType = "compose"
)

// RunnerSpec 是 Git、上传产物、Docker 镜像、模板部署共享的运行规格。
type RunnerSpec struct {
	SourceType      RunnerSourceType      `json:"source_type,omitempty"`
	RuntimeType     RunnerRuntimeType     `json:"runtime_type,omitempty"`
	Artifact        *ArtifactRunConfig    `json:"artifact,omitempty"`
	DockerImage     *DockerImageRunConfig `json:"docker_image,omitempty"`
	EnvVars         map[string]string     `json:"env_vars,omitempty"`
	StartCommand    string                `json:"start_command,omitempty"`
	WorkDir         string                `json:"work_dir,omitempty"`
	InternalPort    int                   `json:"internal_port,omitempty"`
	HealthCheckPath string                `json:"health_check_path,omitempty"`
}

// ArtifactRunConfig 描述上传目录、压缩包或二进制产物的运行方式。
type ArtifactRunConfig struct {
	Kind         RunnerSourceType  `json:"kind,omitempty"`
	Path         string            `json:"path,omitempty"`
	WorkDir      string            `json:"work_dir,omitempty"`
	StartCommand string            `json:"start_command,omitempty"`
	InternalPort int               `json:"internal_port,omitempty"`
	EnvVars      map[string]string `json:"env_vars,omitempty"`
}

// DockerImageRunConfig 描述直接运行镜像所需的配置。
type DockerImageRunConfig struct {
	Image         string              `json:"image,omitempty"`
	PullPolicy    string              `json:"pull_policy,omitempty"`
	Entrypoint    string              `json:"entrypoint,omitempty"`
	Command       []string            `json:"command,omitempty"`
	EnvVars       map[string]string   `json:"env_vars,omitempty"`
	Volumes       []DockerVolumeMount `json:"volumes,omitempty"`
	InternalPort  int                 `json:"internal_port,omitempty"`
	RestartPolicy string              `json:"restart_policy,omitempty"`
}

// DockerVolumeMount 描述 docker run 的一个挂载。
type DockerVolumeMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// DockerRunArgs 生成不经 shell 拼接的 docker run 参数。
func (spec RunnerSpec) DockerRunArgs(containerName string, hostPort int, imageName string, fallbackInternalPort int) []string {
	internalPort := spec.InternalPort
	if internalPort <= 0 && spec.DockerImage != nil {
		internalPort = spec.DockerImage.InternalPort
	}
	if internalPort <= 0 {
		internalPort = fallbackInternalPort
	}
	if internalPort <= 0 {
		internalPort = 8080
	}

	if spec.DockerImage != nil && spec.DockerImage.Image != "" {
		imageName = spec.DockerImage.Image
	}

	restartPolicy := "unless-stopped"
	if spec.DockerImage != nil && spec.DockerImage.RestartPolicy != "" {
		restartPolicy = spec.DockerImage.RestartPolicy
	}

	args := []string{
		"run", "-d",
		"--name", containerName,
		"-p", fmt.Sprintf("%d:%d", hostPort, internalPort),
		"-e", fmt.Sprintf("PORT=%d", internalPort),
		"--restart", restartPolicy,
	}

	envVars := mergeEnvVars(spec.EnvVars, nil)
	if spec.Artifact != nil {
		envVars = mergeEnvVars(envVars, spec.Artifact.EnvVars)
	}
	if spec.DockerImage != nil {
		envVars = mergeEnvVars(envVars, spec.DockerImage.EnvVars)
	}
	for _, key := range sortedMapKeys(envVars) {
		if key == "PORT" {
			continue
		}
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, envVars[key]))
	}

	if spec.DockerImage != nil {
		for _, volume := range spec.DockerImage.Volumes {
			if volume.Source == "" || volume.Target == "" {
				continue
			}
			mount := fmt.Sprintf("%s:%s", volume.Source, volume.Target)
			if volume.ReadOnly {
				mount += ":ro"
			}
			args = append(args, "-v", mount)
		}
		if spec.DockerImage.Entrypoint != "" {
			args = append(args, "--entrypoint", spec.DockerImage.Entrypoint)
		}
	}

	args = append(args, imageName)
	if spec.DockerImage != nil && len(spec.DockerImage.Command) > 0 {
		args = append(args, spec.DockerImage.Command...)
	}

	return args
}

func appRuntimeSpec(app *GitApp, internalPort int) RunnerSpec {
	runtimeSpec := app.Runtime
	if runtimeSpec.SourceType == "" {
		runtimeSpec.SourceType = app.SourceType
	}
	if runtimeSpec.RuntimeType == "" {
		runtimeSpec.RuntimeType = RunnerRuntimeDockerImage
	}
	runtimeSpec.InternalPort = internalPort
	runtimeSpec.EnvVars = mergeEnvVars(runtimeSpec.EnvVars, app.EnvVars)
	if app.DeployConfig == nil {
		return runtimeSpec
	}

	runtimeSpec.EnvVars = mergeEnvVars(runtimeSpec.EnvVars, app.DeployConfig.EnvVars)
	if app.DeployConfig.DockerImage != nil {
		runtimeSpec.DockerImage = app.DeployConfig.DockerImage
	}
	if app.DeployConfig.Artifact != nil {
		runtimeSpec.Artifact = app.DeployConfig.Artifact
	}
	if app.DeployConfig.Runtime != nil {
		runtimeSpec = *app.DeployConfig.Runtime
		runtimeSpec.InternalPort = internalPort
		runtimeSpec.EnvVars = mergeEnvVars(runtimeSpec.EnvVars, app.EnvVars)
		runtimeSpec.EnvVars = mergeEnvVars(runtimeSpec.EnvVars, app.DeployConfig.EnvVars)
	}
	return runtimeSpec
}

// UpdateAppRuntime 更新应用统一运行规格。
func (gs *GitServer) UpdateAppRuntime(appName string, spec RunnerSpec) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	app, exists := gs.apps[appName]
	if !exists {
		return fmt.Errorf("应用 %s 不存在", appName)
	}

	if spec.SourceType == "" {
		spec.SourceType = RunnerSourceGit
	}
	if spec.RuntimeType == "" {
		spec.RuntimeType = RunnerRuntimeAuto
	}

	app.SourceType = spec.SourceType
	app.Runtime = spec
	app.PendingRestart = true
	if spec.StartCommand != "" {
		app.StartCommand = spec.StartCommand
	}
	if spec.EnvVars != nil {
		app.EnvVars = mergeEnvVars(app.EnvVars, spec.EnvVars)
	}
	if app.DeployConfig == nil {
		app.DeployConfig = &AppDeployConfig{}
	}
	if spec.InternalPort > 0 {
		app.DeployConfig.InternalPort = spec.InternalPort
	}
	app.DeployConfig.Runtime = &spec
	app.DeployConfig.Artifact = spec.Artifact
	app.DeployConfig.DockerImage = spec.DockerImage
	app.DeployConfig.EnvVars = mergeEnvVars(app.DeployConfig.EnvVars, spec.EnvVars)
	if spec.DockerImage != nil && spec.DockerImage.Image != "" {
		app.DockerImage = spec.DockerImage.Image
		app.DeployConfig.ImageName = spec.DockerImage.Image
	}

	if err := gs.saveApps(); err != nil {
		return fmt.Errorf("保存应用信息失败: %w", err)
	}

	gs.logger.Infof("应用 %s Runner 运行规格已更新，需要重新部署以应用更改", appName)
	return nil
}

func mergeEnvVars(base map[string]string, override map[string]string) map[string]string {
	merged := make(map[string]string)
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range override {
		merged[key] = value
	}
	return merged
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
