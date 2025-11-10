# Template Marketplace - Analytics Tools Category

This document provides detailed information about all templates in the Analytics Tools category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## Web Analytics

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

### Umami ✅ Tested and Passed

**Function**: Umami website analytics tool, privacy-friendly website statistics.

**Docker Image**: `ghcr.io/umami-software/umami:postgresql-latest`

**Configuration Options**:
- `UMAMI_VERSION`: Umami version (default: latest)
- `UMAMI_PORT`: Umami web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: Umami is a privacy-friendly website analytics tool that does not collect user personal information and complies with GDPR requirements.

---

### Plausible ✅ Tested and Passed

**Function**: Plausible website analytics tool, privacy-friendly website statistics.

**Docker Image**: `plausible/analytics:latest`

**Configuration Options**:
- `PLAUSIBLE_VERSION`: Plausible version (default: latest)
- `PLAUSIBLE_PORT`: Plausible web service port (default: 8000)

**Test Status**: ✅ Tested and Passed

**Description**: Plausible is a privacy-friendly website analytics tool that does not collect user personal information and complies with GDPR requirements.

---

### Fathom ✅ Tested and Passed

**Function**: Fathom website analytics tool, simple and fast website statistics.

**Docker Image**: `usefathom/fathom:latest`

**Configuration Options**:
- `FATHOM_VERSION`: Fathom version (default: latest)
- `FATHOM_PORT`: Fathom web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Fathom is a simple and fast website analytics tool with a clean interface and excellent performance.

---

### GoatCounter ⏳ Not Tested

**Function**: GoatCounter website statistics tool, simple and privacy-friendly website analytics.

**Docker Image**: `goatcounter/goatcounter:latest`

**Configuration Options**:
- `GOATCOUNTER_VERSION`: GoatCounter version (default: latest)
- `GOATCOUNTER_PORT`: GoatCounter web service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: GoatCounter is a simple and privacy-friendly website statistics tool that does not collect user personal information.

---

### Ackee ⏳ Not Tested

**Function**: Ackee website analytics tool, privacy-friendly website statistics.

**Docker Image**: `ackee/ackee:latest`

**Configuration Options**:
- `ACKEE_VERSION`: Ackee version (default: latest)
- `ACKEE_PORT`: Ackee web service port (default: 3000)

**Test Status**: ⏳ Not Tested

**Description**: Ackee is a privacy-friendly website analytics tool that does not collect user personal information.

---

## Business Intelligence

### Metabase ✅ Tested and Passed

**Function**: Metabase business intelligence tool, visual data analytics platform.

**Docker Image**: `metabase/metabase:latest`

**Configuration Options**:
- `METABASE_VERSION`: Metabase version (default: latest)
- `METABASE_PORT`: Metabase web service port (default: 3000)

**Test Status**: ✅ Tested and Passed

**Description**: Metabase is a powerful business intelligence tool that can connect to multiple data sources and create visual reports and dashboards.

---

### Redash ✅ Tested and Passed

**Function**: Redash SQL query and visualization tool, supports multiple data sources.

**Docker Image**: `redash/redash:latest`

**Configuration Options**:
- `REDASH_VERSION`: Redash version (default: latest)
- `REDASH_PORT`: Redash web service port (default: 5000)

**Test Status**: ✅ Tested and Passed

**Description**: Redash is a SQL query and visualization tool that supports multiple data sources and can create queries and visual reports.

---

### Apache Superset ⏳ Not Tested

**Function**: Apache Superset business intelligence tool, powerful data visualization platform.

**Docker Image**: `apache/superset:latest`

**Configuration Options**:
- `SUPERSET_VERSION`: Apache Superset version (default: latest)
- `SUPERSET_PORT`: Apache Superset web service port (default: 8088)

**Test Status**: ⏳ Not Tested

**Description**: Apache Superset is a powerful business intelligence tool that supports multiple data sources and visualization types.

---

## Product Analytics

### PostHog ⏳ Not Tested

**Function**: PostHog product analytics tool, provides user behavior analysis and A/B testing.

**Docker Image**: `posthog/posthog:latest`

**Configuration Options**:
- `POSTHOG_VERSION`: PostHog version (default: latest)
- `POSTHOG_PORT`: PostHog web service port (default: 8000)

**Test Status**: ⏳ Not Tested

**Description**: PostHog is a fully-featured product analytics tool that provides user behavior analysis, A/B testing, feature flags, etc.

---

### Countly ⏳ Not Tested

**Function**: Countly product analytics tool, mobile and web application analytics platform.

**Docker Image**: `countly/countly-server:latest`

**Configuration Options**:
- `COUNTLY_VERSION`: Countly version (default: latest)
- `COUNTLY_PORT`: Countly web service port (default: 3001)

**Test Status**: ⏳ Not Tested

**Description**: Countly is a product analytics tool focused on mobile and web application analytics.

---

## Summary

The Analytics Tools category contains **10 templates**, of which:
- ✅ **Tested and Passed**: 7 templates (Grafana, Prometheus, Umami, Plausible, Fathom, Metabase, Redash)
- ⏳ **Not Tested**: 3 templates (GoatCounter, Ackee, Apache Superset, PostHog, Countly)

Tested templates are mainly concentrated in web analytics (Grafana, Prometheus, Umami, Plausible, Fathom) and business intelligence (Metabase, Redash). Product analytics templates (PostHog, Countly) have not completed testing.

---

*Last updated: 2025-11-11*
