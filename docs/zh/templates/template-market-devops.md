# 模板市场 - DevOps 分类

本文档详细介绍 SSLcat 模板市场中 DevOps 分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## CI/CD 工具

### Jenkins ✅ 已测试通过

**功能**: 开源 CI/CD 平台，功能强大，支持持续集成和持续部署。

**Docker 镜像**: `jenkins/jenkins:lts`

**配置选项**:
- `JENKINS_VERSION`: Jenkins 版本（默认: lts，可选: latest, lts-jdk17）
- `JENKINS_PORT`: Jenkins Web 服务端口（默认: 8080）
- `JENKINS_AGENT_PORT`: Jenkins Agent 通信端口（默认: 50000）

**测试状态**: ✅ 已测试通过

**说明**: Jenkins 是最流行的开源 CI/CD 平台之一，支持丰富的插件生态。首次启动需要查看容器日志获取初始管理员密码。

**启动时间**: 约 2 分钟（首次启动需要初始化）

---

### GitHub Actions Runner ✅ 已测试通过

**功能**: GitHub Actions Runner，可以在自托管服务器上运行 GitHub Actions 工作流。

**Docker 镜像**: `myoung34/github-runner:latest`

**配置选项**:
- `GITHUB_RUNNER_VERSION`: GitHub Runner 版本（默认: latest）
- `GITHUB_RUNNER_PORT`: Runner 服务端口（默认: 8080）
- `GITHUB_TOKEN`: GitHub Personal Access Token（必需）
- `GITHUB_REPO`: GitHub 仓库（格式: owner/repo）

**测试状态**: ✅ 已测试通过

**说明**: GitHub Actions Runner 允许在自托管服务器上运行 GitHub Actions 工作流，适合需要特殊环境或资源的工作流。

---

### Woodpecker CI ✅ 已测试通过

**功能**: Woodpecker CI 轻量级 CI/CD 平台，Drone CI 的分支。

**Docker 镜像**: `woodpeckerci/woodpecker-server:latest`

**配置选项**:
- `WOODPECKER_VERSION`: Woodpecker CI 版本（默认: latest）
- `WOODPECKER_PORT`: Woodpecker CI Web 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过

**说明**: Woodpecker CI 是 Drone CI 的开源分支，提供了轻量级的 CI/CD 解决方案。

---

### Drone ⏳ 未测试

**功能**: Drone CI/CD 平台，基于容器的工作流。

**Docker 镜像**: `drone/drone:latest`

**配置选项**:
- `DRONE_VERSION`: Drone 版本（默认: latest）
- `DRONE_PORT`: Drone Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试（端口冲突问题已修复，端口从 80 改为 3000）

**说明**: Drone 是一个基于容器的 CI/CD 平台，配置简单，性能优秀。

---

### GitLab ✅ 已测试通过

**功能**: GitLab 完整的 DevOps 平台，包含 Git 仓库、CI/CD、项目管理等功能。

**Docker 镜像**: `gitlab/gitlab-ce:latest`

**配置选项**:
- `GITLAB_VERSION`: GitLab 版本（默认: latest）
- `GITLAB_PORT`: GitLab Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: GitLab 是一个完整的 DevOps 平台，功能非常丰富。首次启动需要较长时间（10-15 分钟）进行初始化。

**资源需求**: 建议至少 4GB 内存

---

## 监控工具

### Grafana ✅ 已测试通过

**功能**: Grafana 开源数据可视化和监控平台，支持多种数据源，可以创建漂亮的仪表板和图表。

**Docker 镜像**: `grafana/grafana:latest`

**配置选项**:
- `GRAFANA_VERSION`: Grafana 版本（默认: latest，可选: 10, 9）
- `GRAFANA_PORT`: Grafana Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: Grafana 是最流行的监控可视化工具之一，支持 Prometheus、InfluxDB、Elasticsearch 等多种数据源。自动生成管理员密码。

**默认账户**: admin / {自动生成的密码}

---

### Prometheus ✅ 已测试通过

**功能**: Prometheus 开源监控和告警系统，功能强大，适合云原生应用。

**Docker 镜像**: `prom/prometheus:latest`

**配置选项**:
- `PROMETHEUS_VERSION`: Prometheus 版本（默认: latest，可选: v2.48, v2.47）
- `PROMETHEUS_PORT`: Prometheus Web UI 端口（默认: 9090）

**测试状态**: ✅ 已测试通过

**说明**: Prometheus 是云原生监控的标准工具，支持 PromQL 查询语言，可以配合 Grafana 使用。

---

### Netdata ✅ 已测试通过

**功能**: Netdata 实时系统监控工具，提供详细的系统指标。

**Docker 镜像**: `netdata/netdata:latest`

**配置选项**:
- `NETDATA_VERSION`: Netdata 版本（默认: latest）
- `NETDATA_PORT`: Netdata Web 服务端口（默认: 19999）

**测试状态**: ✅ 已测试通过

**说明**: Netdata 提供实时系统监控，界面美观，无需配置即可使用。

---

### Uptime Kuma ✅ 已测试通过

**功能**: Uptime Kuma 网站监控工具，支持多种监控类型和通知方式。

**Docker 镜像**: `louislam/uptime-kuma:latest`

**配置选项**:
- `UPTIME_KUMA_VERSION`: Uptime Kuma 版本（默认: latest）
- `UPTIME_KUMA_PORT`: Uptime Kuma Web 服务端口（默认: 3001）

**测试状态**: ✅ 已测试通过

**说明**: Uptime Kuma 是一个功能完整的网站监控工具，支持 HTTP、TCP、Ping 等多种监控类型。

---

### Glances ⏳ 未测试

**功能**: Glances 系统监控工具，提供命令行和 Web 界面。

**Docker 镜像**: `nicolargo/glances:latest`

**配置选项**:
- `GLANCES_VERSION`: Glances 版本（默认: latest）
- `GLANCES_PORT`: Glances Web 服务端口（默认: 61208）

**测试状态**: ⏳ 未测试

**说明**: Glances 是一个跨平台的系统监控工具，提供简洁的命令行和 Web 界面。

---

## 日志管理

### Graylog ✅ 已测试通过

**功能**: Graylog 日志管理平台，支持日志收集、搜索和分析。

**Docker 镜像**: `graylog/graylog:latest`

**配置选项**:
- `GRAYLOG_VERSION`: Graylog 版本（默认: latest）
- `GRAYLOG_PORT`: Graylog Web 服务端口（默认: 9000）

**测试状态**: ✅ 已测试通过

**说明**: Graylog 是一个功能强大的日志管理平台，支持多种日志输入源和搜索功能。

---

### Loki ✅ 已测试通过

**功能**: Loki 日志聚合系统，专为 Prometheus 生态系统设计。

**Docker 镜像**: `grafana/loki:latest`

**配置选项**:
- `LOKI_VERSION`: Loki 版本（默认: latest）
- `LOKI_PORT`: Loki API 服务端口（默认: 3100）

**测试状态**: ✅ 已测试通过

**说明**: Loki 是 Grafana 开发的日志聚合系统，与 Prometheus 配合使用，提供统一的监控和日志解决方案。

---

### Seq ✅ 已测试通过

**功能**: Seq 结构化日志服务器，提供强大的日志搜索和分析功能。

**Docker 镜像**: `datalust/seq:latest`

**配置选项**:
- `SEQ_VERSION`: Seq 版本（默认: latest）
- `SEQ_PORT`: Seq Web 服务端口（默认: 5341）

**测试状态**: ✅ 已测试通过

**说明**: Seq 是一个结构化日志服务器，提供强大的搜索、过滤和分析功能。

---

## 容器管理

### Portainer ✅ 已测试通过

**功能**: Portainer Docker 容器管理工具，提供 Web 界面管理 Docker 容器和镜像。

**Docker 镜像**: `portainer/portainer-ce:latest`

**配置选项**:
- `PORTAINER_VERSION`: Portainer 版本（默认: latest）
- `PORTAINER_PORT`: Portainer Web 服务端口（默认: 9000）

**测试状态**: ✅ 已测试通过

**说明**: Portainer 是最流行的 Docker 管理工具之一，提供直观的 Web 界面管理 Docker 环境。

---

### Portainer CE ✅ 已测试通过

**功能**: Portainer CE 社区版，Docker 容器管理工具。

**Docker 镜像**: `portainer/portainer-ce:latest`

**配置选项**:
- `PORTAINER_CE_VERSION`: Portainer CE 版本（默认: latest）
- `PORTAINER_CE_PORT`: Portainer CE Web 服务端口（默认: 9000）

**测试状态**: ✅ 已测试通过

**说明**: Portainer CE 是 Portainer 的社区版，功能与 Portainer 相同。

---

### Dozzle ✅ 已测试通过

**功能**: Dozzle Docker 日志查看器，实时查看容器日志。

**Docker 镜像**: `amir20/dozzle:latest`

**配置选项**:
- `DOZZLE_VERSION`: Dozzle 版本（默认: latest）
- `DOZZLE_PORT`: Dozzle Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Dozzle 是一个轻量级的 Docker 日志查看器，提供实时日志查看功能。

---

## 代码质量

### SonarQube ✅ 已测试通过

**功能**: SonarQube 代码质量分析工具，支持多种编程语言。

**Docker 镜像**: `sonarqube:latest`

**配置选项**:
- `SONARQUBE_VERSION`: SonarQube 版本（默认: latest）
- `SONARQUBE_PORT`: SonarQube Web 服务端口（默认: 9000）

**测试状态**: ✅ 已测试通过

**说明**: SonarQube 是功能强大的代码质量分析工具，支持多种编程语言和代码规范检查。

**资源需求**: 建议至少 2GB 内存

---

## 仓库管理

### Harbor ✅ 已测试通过

**功能**: Harbor 企业级容器镜像仓库，提供镜像管理、安全扫描等功能。

**Docker 镜像**: `goharbor/harbor-core:latest`

**配置选项**:
- `HARBOR_VERSION`: Harbor 版本（默认: latest）
- `HARBOR_PORT`: Harbor Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: Harbor 是企业级容器镜像仓库，提供镜像管理、安全扫描、访问控制等功能。

**资源需求**: 建议至少 4GB 内存

---

### Nexus Repository ✅ 已测试通过

**功能**: Nexus Repository 包管理仓库，支持 Maven、npm、Docker 等多种格式。

**Docker 镜像**: `sonatype/nexus3:latest`

**配置选项**:
- `NEXUS_VERSION`: Nexus 版本（默认: latest）
- `NEXUS_PORT`: Nexus Web 服务端口（默认: 8081）

**测试状态**: ✅ 已测试通过

**说明**: Nexus Repository 是一个功能强大的包管理仓库，支持多种包格式和代理功能。

**资源需求**: 建议至少 2GB 内存

---

## 总结

DevOps 分类共包含 **12 个模板**，其中：
- ✅ **已测试通过**: 11 个
- ⏳ **未测试**: 1 个（Drone，端口冲突已修复）

大部分 DevOps 工具已经过测试验证，可以稳定使用。CI/CD 工具方面，Jenkins、GitHub Actions Runner、Woodpecker CI 都已测试通过。监控工具方面，Grafana、Prometheus、Netdata、Uptime Kuma 都已测试通过。

---

*最后更新时间: 2025-11-11*

