# 模板市场 - 客服系统分类

本文档详细介绍 SSLcat 模板市场中客服系统分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 客服系统

### Chatwoot ✅ 已测试通过

**功能**: Chatwoot 客服系统，现代化的多渠道客服平台。

**Docker 镜像**: `chatwoot/chatwoot:latest`

**配置选项**:
- `CHATWOOT_VERSION`: Chatwoot 版本（默认: latest）
- `CHATWOOT_PORT`: Chatwoot Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: Chatwoot 是一个现代化的客服系统，支持多渠道（网站、Facebook、Twitter、WhatsApp 等），界面美观，功能完整。

---

### Zammad ⏳ 未测试

**功能**: Zammad 客服平台，功能强大的客服和工单系统。

**Docker 镜像**: `zammad/zammad:latest`

**配置选项**:
- `ZAMMAD_VERSION`: Zammad 版本（默认: latest）
- `ZAMMAD_PORT`: Zammad Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Zammad 是一个功能强大的客服平台，支持多渠道、工单管理、知识库等功能。

---

### FreeScout ⏳ 未测试

**功能**: FreeScout 客服系统，Help Scout 的开源替代方案。

**Docker 镜像**: `freescout/freescout:latest`

**配置选项**:
- `FREESCOUT_VERSION`: FreeScout 版本（默认: latest）
- `FREESCOUT_PORT`: FreeScout Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: FreeScout 是 Help Scout 的开源替代方案，提供类似的客服功能。

---

### osTicket ⏳ 未测试

**功能**: osTicket 工单系统，开源工单管理平台。

**Docker 镜像**: `osticket/osticket:latest`

**配置选项**:
- `OSTICKET_VERSION`: osTicket 版本（默认: latest）
- `OSTICKET_PORT`: osTicket Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: osTicket 是一个开源的工单系统，适合中小型企业使用。

---

## 总结

客服系统分类共包含 **4 个模板**，其中：
- ✅ **已测试通过**: 1 个（Chatwoot）
- ⏳ **未测试**: 3 个（Zammad、FreeScout、osTicket）

Chatwoot 已测试通过，可以稳定使用。其他客服系统模板尚未完成测试。

---

*最后更新时间: 2025-11-11*

