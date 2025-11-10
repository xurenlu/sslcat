# 模板市场 - 论坛平台分类

本文档详细介绍 SSLcat 模板市场中论坛平台分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 论坛平台

### Discourse ✅ 已测试通过

**功能**: Discourse 现代化论坛平台，功能强大的社区论坛系统。

**Docker 镜像**: `discourse/discourse:latest`

**配置选项**:
- `DISCOURSE_VERSION`: Discourse 版本（默认: latest）
- `DISCOURSE_PORT`: Discourse Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: Discourse 是最流行的现代化论坛平台之一，界面美观，功能完整，适合构建社区论坛。

---

### Flarum ⏳ 未测试

**功能**: Flarum 现代化论坛平台，简洁美观的论坛系统。

**Docker 镜像**: `flarum/flarum:latest`

**配置选项**:
- `FLARUM_VERSION`: Flarum 版本（默认: latest）
- `FLARUM_PORT`: Flarum Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Flarum 是一个现代化的论坛平台，界面简洁美观，功能完整。

---

### NodeBB ⏳ 未测试

**功能**: NodeBB 现代化论坛平台，基于 Node.js 的论坛系统。

**Docker 镜像**: `nodebb/nodebb:latest`

**配置选项**:
- `NODEBB_VERSION`: NodeBB 版本（默认: latest）
- `NODEBB_PORT`: NodeBB Web 服务端口（默认: 4567）

**测试状态**: ⏳ 未测试

**说明**: NodeBB 是一个基于 Node.js 的现代化论坛平台，性能优秀，功能完整。

---

### Talkyard ⏳ 未测试

**功能**: Talkyard 论坛平台，Stack Overflow 风格的问答论坛。

**Docker 镜像**: `talkyard/talkyard:latest`

**配置选项**:
- `TALKYARD_VERSION`: Talkyard 版本（默认: latest）
- `TALKYARD_PORT`: Talkyard Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Talkyard 是一个 Stack Overflow 风格的问答论坛，适合技术社区使用。

---

### Answer ⏳ 未测试

**功能**: Answer 问答平台，现代化的问答社区系统。

**Docker 镜像**: `answerdev/answer:latest`

**配置选项**:
- `ANSWER_VERSION`: Answer 版本（默认: latest）
- `ANSWER_PORT`: Answer Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Answer 是一个现代化的问答社区系统，界面美观，功能完整。

---

## 总结

论坛平台分类共包含 **5 个模板**，其中：
- ✅ **已测试通过**: 1 个（Discourse）
- ⏳ **未测试**: 4 个（Flarum、NodeBB、Talkyard、Answer）

Discourse 已测试通过，可以稳定使用。其他论坛平台模板尚未完成测试。

---

*最后更新时间: 2025-11-11*

