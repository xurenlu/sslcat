# 模板市场 - RSS 阅读器分类

本文档详细介绍 SSLcat 模板市场中 RSS 阅读器分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## RSS 阅读器

### FreshRSS ✅ 已测试通过

**功能**: FreshRSS RSS 阅读器，功能强大的 RSS 聚合和阅读工具。

**Docker 镜像**: `linuxserver/freshrss:latest`

**配置选项**:
- `FRESHRSS_VERSION`: FreshRSS 版本（默认: latest）
- `FRESHRSS_PORT`: FreshRSS Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: FreshRSS 是一个功能强大的 RSS 阅读器，支持多用户、标签、过滤等功能。

---

### Tiny Tiny RSS ⏳ 未测试

**功能**: Tiny Tiny RSS RSS 阅读器，功能完整的 RSS 聚合工具。

**Docker 镜像**: `linuxserver/tt-rss:latest`

**配置选项**:
- `TTRSS_VERSION`: Tiny Tiny RSS 版本（默认: latest）
- `TTRSS_PORT`: Tiny Tiny RSS Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Tiny Tiny RSS 是一个功能完整的 RSS 阅读器，支持多用户、插件、API 等功能。

---

### Miniflux ⏳ 未测试

**功能**: Miniflux RSS 阅读器，极简主义的 RSS 阅读器。

**Docker 镜像**: `miniflux/miniflux:latest`

**配置选项**:
- `MINIFLUX_VERSION`: Miniflux 版本（默认: latest）
- `MINIFLUX_PORT`: Miniflux Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Miniflux 是一个极简主义的 RSS 阅读器，界面简洁，性能优秀。

---

### Stringer ⏳ 未测试

**功能**: Stringer RSS 阅读器，自托管的 RSS 阅读器。

**Docker 镜像**: `stringer/stringer:latest`

**配置选项**:
- `STRINGER_VERSION`: Stringer 版本（默认: latest）
- `STRINGER_PORT`: Stringer Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Stringer 是一个自托管的 RSS 阅读器，功能简洁，易于使用。

---

### Selfoss ⏳ 未测试

**功能**: Selfoss RSS 阅读器，多源 RSS 聚合工具。

**Docker 镜像**: `selfoss/selfoss:latest`

**配置选项**:
- `SELFOSS_VERSION`: Selfoss 版本（默认: latest）
- `SELFOSS_PORT`: Selfoss Web 服务端口（默认: 8888）

**测试状态**: ⏳ 未测试

**说明**: Selfoss 是一个多源 RSS 聚合工具，支持 RSS、Twitter、Facebook 等多种源。

---

## 总结

RSS 阅读器分类共包含 **5 个模板**，其中：
- ✅ **已测试通过**: 1 个（FreshRSS）
- ⏳ **未测试**: 4 个（Tiny Tiny RSS、Miniflux、Stringer、Selfoss）

FreshRSS 已测试通过，可以稳定使用。其他 RSS 阅读器模板尚未完成测试。

---

*最后更新时间: 2025-11-11*

