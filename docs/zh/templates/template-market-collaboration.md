# 模板市场 - 协作工具分类

本文档详细介绍 SSLcat 模板市场中协作工具分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 团队协作

### Mattermost ✅ 已测试通过

**功能**: Slack 的开源替代品，团队协作和实时聊天平台，支持频道、私聊、文件分享等。

**Docker 镜像**: `mattermost/mattermost-team-edition:latest`（主服务）、`postgres:15`（数据库）

**配置选项**:
- `MATTERMOST_VERSION`: Mattermost 版本（默认: latest，可选: 9.0, 8.1）
- `POSTGRES_VERSION`: PostgreSQL 版本（默认: 15，可选: 16, 14）
- `MATTERMOST_PORT`: Mattermost Web 服务端口（默认: 8065）

**测试状态**: ✅ 已测试通过

**说明**: Mattermost 是最流行的 Slack 开源替代品之一，功能完整，支持频道、私聊、文件分享、集成等功能。

**访问地址**: `http://{{PRIMARY_DOMAIN}}:8065`

**默认账户**: admin / admin

---

### Element ✅ 已测试通过

**功能**: Element 去中心化聊天应用，基于 Matrix 协议。

**Docker 镜像**: `vectorim/element-web:latest`

**配置选项**:
- `ELEMENT_VERSION`: Element 版本（默认: latest）
- `ELEMENT_PORT`: Element Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: Element 是一个去中心化的聊天应用，基于 Matrix 协议，支持端到端加密。

---

### Jitsi Meet ⏳ 未测试

**功能**: Jitsi Meet 视频会议平台，开源视频会议解决方案。

**Docker 镜像**: `jitsi/web:latest`

**配置选项**:
- `JITSI_VERSION`: Jitsi Meet 版本（默认: latest）
- `JITSI_PORT`: Jitsi Meet Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Jitsi Meet 是一个开源的视频会议平台，支持多人视频会议、屏幕共享等功能。

---

### Rocket.Chat ⏳ 未测试

**功能**: Rocket.Chat 团队协作平台，Slack 的开源替代方案。

**Docker 镜像**: `rocketchat/rocket.chat:latest`

**配置选项**:
- `ROCKETCHAT_VERSION`: Rocket.Chat 版本（默认: latest）
- `ROCKETCHAT_PORT`: Rocket.Chat Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Rocket.Chat 是一个功能完整的团队协作平台，支持频道、私聊、视频会议等功能。

---

## 文档协作

### BookStack ✅ 已测试通过

**功能**: BookStack 知识库平台，适合团队文档协作。

**Docker 镜像**: `linuxserver/bookstack:latest`

**配置选项**:
- `BOOKSTACK_VERSION`: BookStack 版本（默认: latest）
- `BOOKSTACK_PORT`: BookStack Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: BookStack 是一个知识库平台，提供书籍、章节、页面的层次结构，适合团队文档协作。

---

### Wiki.js ✅ 已测试通过

**功能**: Wiki.js 现代化 Wiki 系统，功能强大的知识库平台。

**Docker 镜像**: `ghcr.io/requarks/wiki:latest`

**配置选项**:
- `WIKIJS_VERSION`: Wiki.js 版本（默认: latest）
- `WIKIJS_PORT`: Wiki.js Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: Wiki.js 是一个现代化的 Wiki 系统，支持 Markdown、可视化编辑、权限管理等功能。

---

### HedgeDoc ✅ 已测试通过

**功能**: HedgeDoc 协作文档编辑器，支持 Markdown 和实时协作。

**Docker 镜像**: `quay.io/hedgedoc/hedgedoc:latest`

**配置选项**:
- `HEDGEDOC_VERSION`: HedgeDoc 版本（默认: latest）
- `HEDGEDOC_PORT`: HedgeDoc Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: HedgeDoc 是一个协作文档编辑器，支持 Markdown、实时协作、演示模式等功能。

---

### Outline ✅ 已测试通过

**功能**: Outline 知识库平台，现代化的团队知识管理工具。

**Docker 镜像**: `outlinewiki/outline:latest`

**配置选项**:
- `OUTLINE_VERSION`: Outline 版本（默认: latest）
- `OUTLINE_PORT`: Outline Web 服务端口（默认: 3000）

**测试状态**: ✅ 已测试通过

**说明**: Outline 是一个现代化的知识库平台，界面美观，功能完整，适合团队知识管理。

---

## 在线办公

### OnlyOffice ⏳ 未测试

**功能**: OnlyOffice 在线办公套件，支持文档、表格、演示文稿编辑。

**Docker 镜像**: `onlyoffice/documentserver:latest`

**配置选项**:
- `ONLYOFFICE_VERSION`: OnlyOffice 版本（默认: latest）
- `ONLYOFFICE_PORT`: OnlyOffice Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: OnlyOffice 是一个功能完整的在线办公套件，支持文档、表格、演示文稿的在线编辑。

---

### Collabora Online ⏳ 未测试

**功能**: Collabora Online 在线办公套件，LibreOffice 的在线版本。

**Docker 镜像**: `collabora/code:latest`

**配置选项**:
- `COLLABORA_VERSION`: Collabora Online 版本（默认: latest）
- `COLLABORA_PORT`: Collabora Online Web 服务端口（默认: 9980）

**测试状态**: ⏳ 未测试

**说明**: Collabora Online 是 LibreOffice 的在线版本，支持文档、表格、演示文稿的在线编辑。

---

### Excalidraw ⏳ 未测试

**功能**: Excalidraw 在线绘图工具，手绘风格的图表绘制。

**Docker 镜像**: `excalidraw/excalidraw:latest`

**配置选项**:
- `EXCALIDRAW_VERSION`: Excalidraw 版本（默认: latest）
- `EXCALIDRAW_PORT`: Excalidraw Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Excalidraw 是一个在线绘图工具，提供手绘风格的图表绘制功能，适合绘制流程图、架构图等。

---

## 其他协作工具

### 会议管理系统 ⏳ 未测试

**功能**: 会议管理系统，管理会议预约和资源。

**Docker 镜像**: `meeting/management:latest`

**配置选项**:
- `MEETING_VERSION`: 会议管理系统版本（默认: latest）
- `MEETING_PORT`: 会议管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 会议管理系统提供了会议预约、会议室管理、资源分配等功能。

---

### Home Assistant ✅ 已测试通过

**功能**: Home Assistant 智能家居平台，统一管理智能设备。

**Docker 镜像**: `homeassistant/home-assistant:latest`

**配置选项**:
- `HOMEASSISTANT_VERSION`: Home Assistant 版本（默认: latest）
- `HOMEASSISTANT_PORT`: Home Assistant Web 服务端口（默认: 8123）

**测试状态**: ✅ 已测试通过

**说明**: Home Assistant 是最流行的开源智能家居平台，支持多种智能设备协议和集成。

---

### Domoticz ✅ 已测试通过

**功能**: Domoticz 智能家居平台，轻量级的智能家居控制系统。

**Docker 镜像**: `domoticz/domoticz:latest`

**配置选项**:
- `DOMOTICZ_VERSION`: Domoticz 版本（默认: latest）
- `DOMOTICZ_PORT`: Domoticz Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Domoticz 是一个轻量级的智能家居控制系统，支持多种智能设备协议。

---

### Tandoor Recipes ⏳ 未测试

**功能**: Tandoor Recipes 食谱管理应用，支持导入、分享和管理食谱。

**Docker 镜像**: `vabene1111/recipes:latest`

**配置选项**:
- `TANDOOR_VERSION`: Tandoor Recipes 版本（默认: latest，可选: 1.6, 1.5）
- `TANDOOR_PORT`: Tandoor Recipes Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Tandoor Recipes 是一个开源食谱管理应用，支持导入、分享和管理食谱。

---

### ntfy ⏳ 未测试

**功能**: ntfy 推送通知服务，简单的推送通知服务器。

**Docker 镜像**: `binwiederhier/ntfy:latest`

**配置选项**:
- `NTFY_VERSION`: ntfy 版本（默认: latest）
- `NTFY_PORT`: ntfy Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: ntfy 是一个简单的推送通知服务器，可以通过 HTTP 发送推送通知。

---

## 总结

协作工具分类共包含 **14 个模板**，其中：
- ✅ **已测试通过**: 7 个（Mattermost、Element、BookStack、Wiki.js、HedgeDoc、Outline、Home Assistant、Domoticz）
- ⏳ **未测试**: 7 个（Jitsi Meet、Rocket.Chat、OnlyOffice、Collabora Online、Excalidraw、会议管理系统、Tandoor Recipes、ntfy）

已测试通过的模板主要集中在团队协作（Mattermost、Element）和文档协作（BookStack、Wiki.js、HedgeDoc、Outline）方面。在线办公类模板（OnlyOffice、Collabora Online）尚未完成测试。

---

*最后更新时间: 2025-11-11*

