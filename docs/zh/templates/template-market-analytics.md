# 模板市场 - 分析工具分类

本文档详细介绍 SSLcat 模板市场中分析工具分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## Web 分析

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

### Umami ✅ 已测试通过

**功能**: Umami 网站分析工具，隐私友好的网站统计。

**Docker 镜像**: `ghcr.io/umami-software/umami:postgresql-latest`

**配置选项**:
- `UMAMI_VERSION`: Umami 版本（默认: latest）
- `UMAMI_PORT`: Umami Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: Umami 是一个隐私友好的网站分析工具，不收集用户个人信息，符合 GDPR 要求。

---

### Plausible ✅ 已测试通过

**功能**: Plausible 网站分析工具，隐私友好的网站统计。

**Docker 镜像**: `plausible/analytics:latest`

**配置选项**:
- `PLAUSIBLE_VERSION`: Plausible 版本（默认: latest）
- `PLAUSIBLE_PORT`: Plausible Web 服务端口（默认: 8000）

**测试状态**: ✅ 已测试通过

**说明**: Plausible 是一个隐私友好的网站分析工具，不收集用户个人信息，符合 GDPR 要求。

---

### Fathom ✅ 已测试通过

**功能**: Fathom 网站分析工具，简单、快速的网站统计。

**Docker 镜像**: `usefathom/fathom:latest`

**配置选项**:
- `FATHOM_VERSION`: Fathom 版本（默认: latest）
- `FATHOM_PORT`: Fathom Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Fathom 是一个简单、快速的网站分析工具，界面简洁，性能优秀。

---

### GoatCounter ⏳ 未测试

**功能**: GoatCounter 网站统计工具，简单、隐私友好的网站分析。

**Docker 镜像**: `goatcounter/goatcounter:latest`

**配置选项**:
- `GOATCOUNTER_VERSION`: GoatCounter 版本（默认: latest）
- `GOATCOUNTER_PORT`: GoatCounter Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: GoatCounter 是一个简单、隐私友好的网站统计工具，不收集用户个人信息。

---

### Ackee ⏳ 未测试

**功能**: Ackee 网站分析工具，隐私友好的网站统计。

**Docker 镜像**: `ackee/ackee:latest`

**配置选项**:
- `ACKEE_VERSION`: Ackee 版本（默认: latest）
- `ACKEE_PORT`: Ackee Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Ackee 是一个隐私友好的网站分析工具，不收集用户个人信息。

---

## 商业智能

### Metabase ✅ 已测试通过

**功能**: Metabase 商业智能工具，可视化数据分析平台。

**Docker 镜像**: `metabase/metabase:latest`

**配置选项**:
- `METABASE_VERSION`: Metabase 版本（默认: latest）
- `METABASE_PORT`: Metabase Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: Metabase 是一个功能强大的商业智能工具，可以连接多种数据源，创建可视化报表和仪表板。

---

### Redash ✅ 已测试通过

**功能**: Redash SQL 查询和可视化工具，支持多种数据源。

**Docker 镜像**: `redash/redash:latest`

**配置选项**:
- `REDASH_VERSION`: Redash 版本（默认: latest）
- `REDASH_PORT`: Redash Web 服务端口（默认: 5000）

**测试状态**: ✅ 已测试通过

**说明**: Redash 是一个 SQL 查询和可视化工具，支持多种数据源，可以创建查询和可视化报表。

---

### Apache Superset ⏳ 未测试

**功能**: Apache Superset 商业智能工具，功能强大的数据可视化平台。

**Docker 镜像**: `apache/superset:latest`

**配置选项**:
- `SUPERSET_VERSION`: Apache Superset 版本（默认: latest）
- `SUPERSET_PORT`: Apache Superset Web 服务端口（默认: 8088）

**测试状态**: ⏳ 未测试

**说明**: Apache Superset 是一个功能强大的商业智能工具，支持多种数据源和可视化类型。

---

## 产品分析

### PostHog ⏳ 未测试

**功能**: PostHog 产品分析工具，提供用户行为分析和 A/B 测试。

**Docker 镜像**: `posthog/posthog:latest`

**配置选项**:
- `POSTHOG_VERSION`: PostHog 版本（默认: latest）
- `POSTHOG_PORT`: PostHog Web 服务端口（默认: 8000）

**测试状态**: ⏳ 未测试

**说明**: PostHog 是一个功能完整的产品分析工具，提供用户行为分析、A/B 测试、功能标志等功能。

---

### Countly ⏳ 未测试

**功能**: Countly 产品分析工具，移动和 Web 应用分析平台。

**Docker 镜像**: `countly/countly-server:latest`

**配置选项**:
- `COUNTLY_VERSION`: Countly 版本（默认: latest）
- `COUNTLY_PORT`: Countly Web 服务端口（默认: 3001）

**测试状态**: ⏳ 未测试

**说明**: Countly 是一个产品分析工具，专注于移动和 Web 应用分析。

---

## 总结

分析工具分类共包含 **10 个模板**，其中：
- ✅ **已测试通过**: 7 个（Grafana、Prometheus、Umami、Plausible、Fathom、Metabase、Redash）
- ⏳ **未测试**: 3 个（GoatCounter、Ackee、Apache Superset、PostHog、Countly）

已测试通过的模板主要集中在 Web 分析（Grafana、Prometheus、Umami、Plausible、Fathom）和商业智能（Metabase、Redash）方面。产品分析类模板（PostHog、Countly）尚未完成测试。

---

*最后更新时间: 2025-11-11*

