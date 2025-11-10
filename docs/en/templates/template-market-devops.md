# Template Marketplace - DevOps Category

This document provides detailed information about all templates in the DevOps category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## CI/CD Tools

### Jenkins ✅ Tested and Passed

**Function**: Open-source CI/CD platform, powerful, supports continuous integration and continuous deployment.

**Docker Image**: `jenkins/jenkins:lts`

**Configuration Options**:
- `JENKINS_VERSION`: Jenkins version (default: lts, optional: latest, lts-jdk17)
- `JENKINS_PORT`: Jenkins web service port (default: 8080)
- `JENKINS_AGENT_PORT`: Jenkins Agent communication port (default: 50000)

**Test Status**: ✅ Tested and Passed

**Description**: Jenkins is one of the most popular open-source CI/CD platforms, supporting a rich plugin ecosystem. First startup requires checking container logs to get the initial administrator password.

**Startup Time**: Approximately 2 minutes (first startup requires initialization)

---

### GitHub Actions Runner ✅ Tested and Passed

**Function**: GitHub Actions Runner, can run GitHub Actions workflows on self-hosted servers.

**Docker Image**: `myoung34/github-runner:latest`

**Configuration Options**:
- `GITHUB_RUNNER_VERSION`: GitHub Runner version (default: latest)
- `GITHUB_RUNNER_PORT`: Runner service port (default: 8080)
- `GITHUB_TOKEN`: GitHub Personal Access Token (required)
- `GITHUB_REPO`: GitHub repository (format: owner/repo)

**Test Status**: ✅ Tested and Passed

**Description**: GitHub Actions Runner allows running GitHub Actions workflows on self-hosted servers, suitable for workflows that require special environments or resources.

---

### Woodpecker CI ✅ Tested and Passed

**Function**: Woodpecker CI lightweight CI/CD platform, fork of Drone CI.

**Docker Image**: `woodpeckerci/woodpecker-server:latest`

**Configuration Options**:
- `WOODPECKER_VERSION`: Woodpecker CI version (default: latest)
- `WOODPECKER_PORT`: Woodpecker CI web service port (default: 8000)

**Test Status**: ✅ Tested and Passed

**Description**: Woodpecker CI is an open-source fork of Drone CI, providing a lightweight CI/CD solution.

---

### Drone ⏳ Not Tested

**Function**: Drone CI/CD platform, container-based workflows.

**Docker Image**: `drone/drone:latest`

**Configuration Options**:
- `DRONE_VERSION`: Drone version (default: latest)
- `DRONE_PORT`: Drone web service port (default: 3000)

**Test Status**: ⏳ Not Tested (port conflict issue fixed, port changed from 80 to 3000)

**Description**: Drone is a container-based CI/CD platform with simple configuration and excellent performance.

---

### GitLab ✅ Tested and Passed

**Function**: GitLab complete DevOps platform, includes Git repository, CI/CD, project management, and other features.

**Docker Image**: `gitlab/gitlab-ce:latest`

**Configuration Options**:
- `GITLAB_VERSION`: GitLab version (default: latest)
- `GITLAB_PORT`: GitLab web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: GitLab is a complete DevOps platform with very rich features. First startup requires a longer time (10-15 minutes) for initialization.

**Resource Requirements**: Recommend at least 4GB RAM

---

## Monitoring Tools

### Grafana ✅ Tested and Passed

**Function**: Grafana open-source data visualization and monitoring platform, supports multiple data sources, can create beautiful dashboards and charts.

**Docker Image**: `grafana/grafana:latest`

**Configuration Options**:
- `GRAFANA_VERSION`: Grafana version (default: latest, optional: 10, 9)
- `GRAFANA_PORT`: Grafana web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: Grafana is one of the most popular monitoring visualization tools, supporting multiple data sources such as Prometheus, InfluxDB, Elasticsearch, etc. Automatically generates administrator password.

**Default Account**: admin / {auto-generated password}

---

### Prometheus ✅ Tested and Passed

**Function**: Prometheus open-source monitoring and alerting system, powerful, suitable for cloud-native applications.

**Docker Image**: `prom/prometheus:latest`

**Configuration Options**:
- `PROMETHEUS_VERSION`: Prometheus version (default: latest, optional: v2.48, v2.47)
- `PROMETHEUS_PORT`: Prometheus Web UI port (default: 9090)

**Test Status**: ✅ Tested and Passed

**Description**: Prometheus is the standard tool for cloud-native monitoring, supports PromQL query language, can be used with Grafana.

---

### Netdata ✅ Tested and Passed

**Function**: Netdata real-time system monitoring tool, provides detailed system metrics.

**Docker Image**: `netdata/netdata:latest`

**Configuration Options**:
- `NETDATA_VERSION`: Netdata version (default: latest)
- `NETDATA_PORT`: Netdata web service port (default: 19999)

**Test Status**: ✅ Tested and Passed

**Description**: Netdata provides real-time system monitoring with a beautiful interface, ready to use without configuration.

---

### Uptime Kuma ✅ Tested and Passed

**Function**: Uptime Kuma website monitoring tool, supports multiple monitoring types and notification methods.

**Docker Image**: `louislam/uptime-kuma:latest`

**Configuration Options**:
- `UPTIME_KUMA_VERSION`: Uptime Kuma version (default: latest)
- `UPTIME_KUMA_PORT`: Uptime Kuma web service port (default: 3001)

**Test Status**: ✅ Tested and Passed

**Description**: Uptime Kuma is a fully-featured website monitoring tool that supports multiple monitoring types such as HTTP, TCP, Ping, etc.

---

### Glances ⏳ Not Tested

**Function**: Glances system monitoring tool, provides command-line and web interface.

**Docker Image**: `nicolargo/glances:latest`

**Configuration Options**:
- `GLANCES_VERSION`: Glances version (default: latest)
- `GLANCES_PORT`: Glances web service port (default: 61208)

**Test Status**: ⏳ Not Tested

**Description**: Glances is a cross-platform system monitoring tool that provides a concise command-line and web interface.

---

## Log Management

### Graylog ✅ Tested and Passed

**Function**: Graylog log management platform, supports log collection, search, and analysis.

**Docker Image**: `graylog/graylog:latest`

**Configuration Options**:
- `GRAYLOG_VERSION`: Graylog version (default: latest)
- `GRAYLOG_PORT`: Graylog web service port (default: 9000)

**Test Status**: ✅ Tested and Passed

**Description**: Graylog is a powerful log management platform that supports multiple log input sources and search functionality.

---

### Loki ✅ Tested and Passed

**Function**: Loki log aggregation system, designed for the Prometheus ecosystem.

**Docker Image**: `grafana/loki:latest`

**Configuration Options**:
- `LOKI_VERSION`: Loki version (default: latest)
- `LOKI_PORT`: Loki API service port (default: 3100)

**Test Status**: ✅ Tested and Passed

**Description**: Loki is a log aggregation system developed by Grafana, used together with Prometheus to provide a unified monitoring and logging solution.

---

### Seq ✅ Tested and Passed

**Function**: Seq structured log server, provides powerful log search and analysis functionality.

**Docker Image**: `datalust/seq:latest`

**Configuration Options**:
- `SEQ_VERSION`: Seq version (default: latest)
- `SEQ_PORT`: Seq web service port (default: 5341)

**Test Status**: ✅ Tested and Passed

**Description**: Seq is a structured log server that provides powerful search, filtering, and analysis functionality.

---

## Container Management

### Portainer ✅ Tested and Passed

**Function**: Portainer Docker container management tool, provides web interface to manage Docker containers and images.

**Docker Image**: `portainer/portainer-ce:latest`

**Configuration Options**:
- `PORTAINER_VERSION`: Portainer version (default: latest)
- `PORTAINER_PORT`: Portainer web service port (default: 9000)

**Test Status**: ✅ Tested and Passed

**Description**: Portainer is one of the most popular Docker management tools, providing an intuitive web interface to manage Docker environments.

---

### Portainer CE ✅ Tested and Passed

**Function**: Portainer CE community edition, Docker container management tool.

**Docker Image**: `portainer/portainer-ce:latest`

**Configuration Options**:
- `PORTAINER_CE_VERSION`: Portainer CE version (default: latest)
- `PORTAINER_CE_PORT`: Portainer CE web service port (default: 9000)

**Test Status**: ✅ Tested and Passed

**Description**: Portainer CE is the community edition of Portainer, with the same functionality as Portainer.

---

### Dozzle ✅ Tested and Passed

**Function**: Dozzle Docker log viewer, view container logs in real-time.

**Docker Image**: `amir20/dozzle:latest`

**Configuration Options**:
- `DOZZLE_VERSION`: Dozzle version (default: latest)
- `DOZZLE_PORT`: Dozzle web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Dozzle is a lightweight Docker log viewer that provides real-time log viewing functionality.

---

## Code Quality

### SonarQube ✅ Tested and Passed

**Function**: SonarQube code quality analysis tool, supports multiple programming languages.

**Docker Image**: `sonarqube:latest`

**Configuration Options**:
- `SONARQUBE_VERSION`: SonarQube version (default: latest)
- `SONARQUBE_PORT`: SonarQube web service port (default: 9000)

**Test Status**: ✅ Tested and Passed

**Description**: SonarQube is a powerful code quality analysis tool that supports multiple programming languages and code standard checks.

**Resource Requirements**: Recommend at least 2GB RAM

---

## Repository Management

### Harbor ✅ Tested and Passed

**Function**: Harbor enterprise container image registry, provides image management, security scanning, and other features.

**Docker Image**: `goharbor/harbor-core:latest`

**Configuration Options**:
- `HARBOR_VERSION`: Harbor version (default: latest)
- `HARBOR_PORT`: Harbor web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: Harbor is an enterprise container image registry that provides image management, security scanning, access control, and other features.

**Resource Requirements**: Recommend at least 4GB RAM

---

### Nexus Repository ✅ Tested and Passed

**Function**: Nexus Repository package management repository, supports multiple formats such as Maven, npm, Docker, etc.

**Docker Image**: `sonatype/nexus3:latest`

**Configuration Options**:
- `NEXUS_VERSION`: Nexus version (default: latest)
- `NEXUS_PORT`: Nexus web service port (default: 8081)

**Test Status**: ✅ Tested and Passed

**Description**: Nexus Repository is a powerful package management repository that supports multiple package formats and proxy functionality.

**Resource Requirements**: Recommend at least 2GB RAM

---

## Summary

The DevOps category contains **12 templates**, of which:
- ✅ **Tested and Passed**: 11 templates
- ⏳ **Not Tested**: 1 template (Drone, port conflict fixed)

Most DevOps tools have been tested and verified, and can be used stably. For CI/CD tools, Jenkins, GitHub Actions Runner, and Woodpecker CI have all been tested and passed. For monitoring tools, Grafana, Prometheus, Netdata, and Uptime Kuma have all been tested and passed.

---

*Last updated: 2025-11-11*
