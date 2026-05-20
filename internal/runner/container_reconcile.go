package runner

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type dockerInspectStatusFunc func(containerRef string) (string, error)

var dockerInspectContainerStatus dockerInspectStatusFunc = defaultDockerInspectContainerStatus

func defaultDockerInspectContainerStatus(containerRef string) (string, error) {
	output, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerRef).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker inspect %s failed: %w: %s", containerRef, err, strings.TrimSpace(string(output)))
	}

	return strings.TrimSpace(string(output)), nil
}

func isDockerUnavailable(err error) bool {
	var pathErr *exec.Error
	return errors.As(err, &pathErr) && pathErr.Err == exec.ErrNotFound
}

// reconcileRunnerContainers syncs sslcat's persisted app state with Docker's current
// container state. It intentionally never starts, stops, restarts, or removes containers.
func (gs *GitServer) reconcileRunnerContainers() error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	changed := false
	reconciled := 0

	for _, app := range gs.apps {
		if app == nil || app.DeployConfig == nil {
			continue
		}

		containerRef := strings.TrimSpace(app.DeployConfig.ContainerName)
		if containerRef == "" {
			containerRef = strings.TrimSpace(app.DeployConfig.ContainerID)
		}
		if containerRef == "" {
			continue
		}

		status, err := dockerInspectContainerStatus(containerRef)
		if err != nil {
			if isDockerUnavailable(err) {
				gs.logger.Warnf("Docker 不可用，跳过 Runner 容器对账: %v", err)
				return nil
			}

			if app.Status != "failed" || app.ContainerStatus != "missing" {
				app.Status = "failed"
				app.ContainerStatus = "missing"
				changed = true
			}
			reconciled++
			gs.logger.Warnf("Runner 容器对账发现应用 %s 的容器不可访问: %s (%v)", app.Name, containerRef, err)
			continue
		}

		normalized := normalizeDockerContainerStatus(status)
		nextAppStatus, nextContainerStatus := appStatusForDockerContainerStatus(normalized)
		if app.Status != nextAppStatus || app.ContainerStatus != nextContainerStatus {
			app.Status = nextAppStatus
			app.ContainerStatus = nextContainerStatus
			changed = true
		}

		if normalized == "running" {
			if app.DeployConfig.Port > 0 && app.Port != app.DeployConfig.Port {
				app.Port = app.DeployConfig.Port
				changed = true
			}
			if app.Port > 0 {
				if err := gs.addProxyRuleForApp(app); err != nil {
					gs.logger.Warnf("Runner 容器对账恢复应用 %s 代理规则失败: %v", app.Name, err)
				}
			}
		}

		reconciled++
	}

	if changed {
		if err := gs.saveApps(); err != nil {
			return err
		}
	}

	if reconciled > 0 {
		gs.logger.Infof("Runner 容器对账完成: %d 个应用", reconciled)
	}

	return nil
}

func normalizeDockerContainerStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

func appStatusForDockerContainerStatus(status string) (string, string) {
	switch status {
	case "running":
		return "running", "active"
	case "restarting":
		return "deploying", "restarting"
	case "paused":
		return "failed", "paused"
	case "created":
		return "failed", "created"
	case "exited":
		return "failed", "exited"
	case "dead":
		return "failed", "dead"
	default:
		if status == "" {
			status = "unknown"
		}
		return "failed", status
	}
}
