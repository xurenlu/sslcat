# SSLcat 模板市场使用指南

## 概述

SSLcat 模板市场是一个强大的应用部署平台，提供 **362+ 个**企业级应用模板，覆盖从 AI 应用到企业工具、从数据库到媒体服务的全场景需求。通过模板市场，您可以一键部署各种应用，无需手动配置 Docker Compose、域名、SSL 证书等复杂设置。

## 核心特性

### 🚀 一键部署
- **零配置部署**: 选择模板，填写必要参数，一键完成部署
- **自动域名配置**: 自动配置域名和子域名
- **自动 SSL 证书**: 自动申请和配置 Let's Encrypt SSL 证书
- **自动健康检查**: 内置健康检查机制，确保服务正常运行

### 📦 丰富的模板库
- **362+ 个模板**: 覆盖 21 个主分类、130+ 个子分类
- **137 个测试通过**: 所有模板经过自动化测试验证
- **持续更新**: 定期添加新模板，优化现有模板

### 🔧 灵活的配置
- **版本选择**: 支持选择应用版本
- **端口配置**: 自定义端口映射
- **环境变量**: 灵活的环境变量配置
- **资源限制**: CPU、内存、GPU 资源配置

### 🔐 安全可靠
- **自动凭证生成**: 自动生成安全的数据库密码、API Token
- **数据持久化**: 自动配置数据卷，确保数据安全
- **权限控制**: 基于角色的访问控制

## 模板分类

### AI 应用（76个）

#### 大模型聊天（8个）
- **Ollama** - 本地大模型运行环境
- **Open WebUI** - AI 聊天界面
- **LibreChat** - ChatGPT 替代品
- **Chatbot UI** - AI 聊天界面
- **ChatGLM** - 中文大模型
- **Baichuan** - 百川大模型
- **Qwen** - 通义千问
- **Yi** - 零一万物大模型

#### 图片生成（8个）
- **Stable Diffusion WebUI** - 强大的 AI 图片生成工具
- **ComfyUI** - 节点式 AI 工作流
- **Replicate Stable Diffusion** - Replicate 上的 Stable Diffusion
- **Replicate SDXL** - SDXL 模型
- **Replicate ControlNet** - ControlNet 模型
- **DALL-E Mini** - DALL-E Mini 图片生成
- **Midjourney Alternative** - Midjourney 替代方案
- **Waifu Diffusion** - 动漫风格图片生成

#### 代码生成（4个）
- **CodeGeeX** - AI 代码生成
- **Codeium** - AI 代码助手
- **Tabby** - AI 代码补全
- **Continue** - AI 代码编辑器

#### 语音/视频生成（4个）
- **Pika** - AI 视频生成
- **RunwayML** - AI 视频编辑
- **Stable Video Diffusion** - 视频生成模型
- **Replicate Stable Video** - Replicate 视频生成

#### OCR/文字识别（3个）
- **EasyOCR** - 多语言 OCR
- **PaddleOCR** - 中文 OCR
- **TrOCR** - Transformer OCR（⚠️ 镜像不存在）

#### TTS/语音合成（3个）
- **Coqui TTS** - 文字转语音
- **Piper TTS** - 轻量级 TTS
- **Bark** - 文本到音频生成

#### 其他 AI 工具
- **AnythingLLM** - 私有化 ChatGPT
- **LocalAI** - OpenAI 兼容 API
- **LangChain** - AI 应用框架
- **LlamaIndex** - RAG 框架
- **Text Generation WebUI** - 本地 LLM 界面
- **TorchServe** - PyTorch 模型服务
- **Replicate Proxy** - Replicate 模型代理
- 以及更多...

### 企业工具（156个）

#### HR/人事管理（13个）
- 考勤管理系统
- 打卡系统
- 工时管理系统
- 薪酬管理系统
- 员工目录
- 宿舍管理系统
- 班车管理系统
- 排班管理系统
- 培训管理系统
- **Moodle** - 在线学习平台
- **Open edX** - 在线学习平台
- 知识考试系统
- **Kimai** - 时间追踪

#### 项目管理（11个）
- 项目组合管理（PPM）
- 项目成本管理系统
- 资源管理系统
- 项目风险管理系统
- **Leantime** - 项目管理工具
- **Plane** - 项目管理平台
- **Taiga** - 敏捷项目管理
- **Vikunja** - 任务管理
- **Kanboard** - 看板管理
- **OpenProject** - 项目管理
- **Linear Alternative** - Linear 替代方案

#### ERP/供应链（7个）
- 小型ERP系统
- 库存管理系统
- 仓库管理系统
- 供应商管理系统
- 供应商自助服务平台
- 采购门户
- 合同管理系统

#### 文档管理（6个）
- 文档版本控制系统
- 印章管理系统
- 档案管理系统
- 文档合规系统
- **Paperless-ngx** - 无纸化文档管理
- **Mayan EDMS** - 企业文档管理系统

#### 合规审计（4个）
- 合规管理系统
- 审计管理系统
- 风险管理系统
- 文档合规系统

#### 协作工具（6个）
- 会议管理系统
- **Mattermost** - 团队协作平台
- **Element** - 去中心化聊天
- **Jitsi Meet** - 视频会议
- **Excalidraw** - 在线绘图
- **OnlyOffice** - 在线办公套件

### 数据库（21个）

#### 关系型数据库
- **MySQL** - 最流行的关系型数据库
- **PostgreSQL** - 强大的开源数据库
- **MariaDB** - MySQL 分支
- **TimescaleDB** - 时序数据库

#### NoSQL 数据库
- **MongoDB** - 文档数据库
- **Redis** - 内存数据库
- **Cassandra** - 分布式数据库
- **CouchDB** - 文档数据库
- **ClickHouse** - 分析数据库
- **InfluxDB** - 时序数据库

#### 向量数据库（5个）
- **Milvus** - 向量数据库
- **Qdrant** - 向量搜索引擎
- **Weaviate** - 向量数据库
- **Chroma** - 向量数据库
- **Pinecone Alternative** - Pinecone 替代方案

#### 数据库管理工具
- **phpMyAdmin** - MySQL 管理
- **Adminer** - 数据库管理
- **pgAdmin** - PostgreSQL 管理
- **mongo-express** - MongoDB 管理

### 媒体服务（19个）

#### 视频服务
- **Jellyfin** - 媒体服务器
- **Plex** - 媒体服务器
- **Emby** - 媒体服务器
- **Owncast** - 直播平台
- **PeerTube** - 视频平台

#### 音乐服务
- **Airsonic** - 音乐服务器
- **Navidrome** - 音乐服务器
- **Lidarr** - 音乐管理
- **Radarr** - 电影管理
- **Readarr** - 电子书管理
- **Sonarr** - 电视剧管理
- **Prowlarr** - 索引管理

#### 图片服务
- **Immich** - 照片库
- **PhotoPrism** - 照片管理
- **Lychee** - 相册
- **Piwigo** - 照片库
- **Pixelfed** - 图片社交

#### 其他
- **Komga** - 漫画管理
- **Calibre Web** - 电子书管理

### DevOps（12个）

#### CI/CD 工具
- **Jenkins** - 持续集成
- **Drone** - CI/CD 平台
- **GitHub Actions Runner** - GitHub Actions Runner
- **Woodpecker CI** - CI/CD 平台

#### 监控工具
- **Grafana** - 监控面板
- **Prometheus** - 监控系统
- **Netdata** - 实时监控
- **Glances** - 系统监控
- **Uptime Kuma** - 网站监控

#### 日志管理
- **Graylog** - 日志管理
- **Loki** - 日志聚合
- **Seq** - 结构化日志

#### 其他
- **Portainer** - 容器管理
- **Dozzle** - Docker 日志查看器

### CMS（12个）

- **WordPress** - 最流行的 CMS
- **Ghost** - 博客平台
- **Strapi** - 无头 CMS
- **Drupal** - 企业级 CMS
- **Wagtail** - Django CMS
- **Hexo** - 静态博客
- **Hugo** - 静态网站生成器
- **Nuxt.js** - Vue.js 框架
- **Gatsby** - React 静态网站
- **Docusaurus** - 文档网站
- **Plume** - 博客平台
- **Keystone** - Node.js CMS

### 其他分类

#### 分析工具（10个）
- **Matomo** - Web 分析
- **Umami** - 网站分析
- **PostHog** - 产品分析
- **Metabase** - 商业智能
- **Plausible** - 隐私友好的分析
- **Fathom** - 网站分析
- **GoatCounter** - 网站统计
- **Ackee** - 网站分析
- **Countly** - 产品分析
- **Redash** - SQL 查询和可视化

#### CRM（5个）
- **SuiteCRM** - CRM 系统
- **EspoCRM** - CRM 系统
- **Dolibarr** - ERP/CRM
- **Odoo** - ERP/CRM
- **ERPNext** - ERP 系统

#### 客服系统（4个）
- **Chatwoot** - 客服系统
- **Zammad** - 客服平台
- **FreeScout** - 客服系统
- **osTicket** - 工单系统

#### 电商平台（4个）
- **WooCommerce** - WordPress 电商插件
- **Magento** - 电商平台
- **OpenCart** - 电商系统
- **PrestaShop** - 电商平台
- **Shopware** - 电商平台

#### 安全工具（3个）
- **Authelia** - 身份认证
- **Keycloak** - 身份和访问管理
- **Vaultwarden** - 密码管理器
- **JumpServer** - 堡垒机

#### RSS 阅读器（5个）
- **FreshRSS** - RSS 阅读器
- **Tiny Tiny RSS** - RSS 阅读器
- **Miniflux** - RSS 阅读器
- **Stringer** - RSS 阅读器
- **Selfoss** - RSS 阅读器

#### 论坛平台（5个）
- **Discourse** - 论坛平台
- **Flarum** - 论坛平台
- **NodeBB** - 论坛平台
- **Talkyard** - 论坛平台
- **Answer** - 问答平台

## 使用方法

### Web UI 使用

1. **访问模板市场**
   - 登录 SSLcat 管理面板
   - 导航到"模板市场"页面

2. **浏览模板**
   - 使用分类筛选：AI、数据库、DevOps 等
   - 使用标签筛选：gpu、web、api 等
   - 使用关键词搜索：输入应用名称或功能

3. **查看模板详情**
   - 点击模板卡片查看详细信息
   - 查看模板描述、配置选项、资源需求
   - 查看是否需要 GPU 支持

4. **部署模板**
   - 点击"部署"按钮
   - 填写必要的配置参数：
     - 应用名称
     - 域名（可选，自动生成）
     - 版本选择
     - 端口配置
     - 环境变量
   - 确认部署

5. **查看部署状态**
   - 在"应用列表"中查看部署状态
   - 查看部署日志
   - 等待部署完成

### API 使用

#### 获取模板列表

```bash
# 获取所有模板
GET /api/git-server/templates

# 按分类筛选
GET /api/git-server/templates?category=ai

# 按标签筛选
GET /api/git-server/templates?tag=gpu

# 关键词搜索
GET /api/git-server/templates?keyword=wordpress

# 显示所有模板（包括未测试的）
GET /api/git-server/templates?showAll=true
```

#### 获取模板详情

```bash
GET /api/git-server/templates/{template_id}
```

响应示例：
```json
{
  "meta": {
    "id": "wordpress",
    "name": "WordPress",
    "category": "cms",
    "description": "最流行的内容管理系统",
    "variables": [
      {
        "name": "WORDPRESS_VERSION",
        "type": "select",
        "default": "latest",
        "options": ["latest", "6.4", "6.3"]
      }
    ],
    "services": [...],
    "gpu_required": false
  },
  "readme": "# WordPress\n\n...",
  "assets": []
}
```

#### 部署模板

```bash
POST /api/git-server/templates/deploy
Content-Type: application/json

{
  "name": "my-wordpress",
  "template_id": "wordpress",
  "domain": "blog.example.com",
  "domains": ["blog.example.com", "www.blog.example.com"],
  "auto_ssl": true,
  "parameters": {
    "WORDPRESS_VERSION": "latest",
    "WORDPRESS_PORT": "8080"
  }
}
```

## 模板状态说明

### 测试通过（137个）
这些模板已经过自动化测试验证，可以稳定使用。API 默认只返回这些模板。

### 未测试（225+个）
这些模板尚未完成测试，可能存在配置问题。可以通过 `?showAll=true` 参数查看。

### 不可用（4个）
这些模板的 Docker 镜像不存在或无法访问，暂时无法使用：
- **manga-translator** - 镜像不存在
- **speech-translator** - 镜像不存在
- **whisperx** - 镜像不存在
- **trocr** - 镜像不存在

## GPU 模板使用

部分 AI 模板需要 GPU 支持，部署前请确保：

1. **服务器配置**
   - 安装 NVIDIA 驱动
   - 安装 NVIDIA Container Toolkit
   - 配置 Docker 使用 NVIDIA 运行时

2. **模板识别**
   - 模板详情中会显示 `gpu_required: true`
   - 模板卡片会显示 GPU 标签

3. **部署注意事项**
   - GPU 模板启动时间较长（可能需要下载模型）
   - 需要足够的显存（建议 8GB+）
   - 某些模板可能需要 GitHub Container Registry Token

## GitHub Container Registry 支持

部分模板使用 `ghcr.io` 镜像，需要配置 GitHub Personal Access Token：

1. **创建 Token**
   - 访问 GitHub Settings > Developer settings > Personal access tokens
   - 创建 Token，需要 `read:packages` 权限

2. **配置 Token**
   - 在 SSLcat 配置中设置 `GITHUB_TOKEN` 环境变量
   - 或在部署时提供 Token

## 最佳实践

### 1. 选择合适的模板
- 优先选择测试通过的模板
- 根据需求选择合适的版本
- 注意 GPU 和资源需求

### 2. 配置建议
- 使用有意义的应用名称
- 配置自定义域名（推荐）
- 启用自动 SSL 证书
- 设置合理的资源限制

### 3. 数据管理
- 定期备份数据卷
- 使用持久化存储
- 注意数据迁移

### 4. 安全建议
- 使用强密码（自动生成）
- 定期更新应用版本
- 配置防火墙规则
- 启用访问控制

## 常见问题

### Q: 如何查看模板的详细配置？
A: 点击模板卡片或使用 API 获取模板详情，查看 `variables` 字段了解所有配置选项。

### Q: 模板部署失败怎么办？
A: 检查部署日志，常见问题：
- 端口冲突：修改端口配置
- 资源不足：增加服务器资源
- 镜像拉取失败：检查网络和认证

### Q: 如何更新已部署的应用？
A: 可以通过修改应用的 Docker Compose 文件或重新部署来更新应用。

### Q: 模板支持自定义配置吗？
A: 是的，每个模板都支持通过 `variables` 进行配置，包括版本、端口、环境变量等。

### Q: 如何贡献新模板？
A: 参考模板开发文档，创建 `template.yaml` 和 `docker-compose.yml` 文件，提交 Pull Request。

## 相关文档

### 详细分类文档
- [模板市场详细文档索引](../templates/template-market-index.md) - 所有分类的详细文档索引
- [AI 应用详细文档](../templates/template-market-ai.md) - 76 个 AI 应用模板详细说明
- [数据库详细文档](../templates/template-market-database.md) - 21 个数据库模板详细说明
- [DevOps 详细文档](../templates/template-market-devops.md) - 12 个 DevOps 工具详细说明
- [CMS 详细文档](../templates/template-market-cms.md) - 12 个 CMS 模板详细说明
- [企业工具详细文档](../templates/template-market-tools.md) - 159 个企业工具详细说明
- [媒体服务详细文档](../templates/template-market-media.md) - 19 个媒体服务模板详细说明
- [协作工具详细文档](../templates/template-market-collaboration.md) - 14 个协作工具详细说明
- [分析工具详细文档](../templates/template-market-analytics.md) - 10 个分析工具详细说明
- [CRM 详细文档](../templates/template-market-crm.md) - 5 个 CRM 系统详细说明
- [客服系统详细文档](../templates/template-market-support.md) - 4 个客服系统详细说明
- [安全工具详细文档](../templates/template-market-security.md) - 4 个安全工具详细说明
- [RSS 阅读器详细文档](../templates/template-market-rss.md) - 5 个 RSS 阅读器详细说明
- [论坛平台详细文档](../templates/template-market-forum.md) - 5 个论坛平台详细说明
- [电商平台详细文档](../templates/template-market-ecommerce.md) - 5 个电商平台详细说明

### 其他文档
- [模板库统计报告](../templates/template-library-statistics.md)
- [模板测试状态](../testing/template-test-status.md)
- [Docker Compose 模板实现](../development/docker-compose-template-implementation.md)
- [模板扩展计划](../development/template-expansion-plan.md)

## 总结

SSLcat 模板市场提供了 **362+ 个**企业级应用模板，覆盖从 AI 应用到企业工具的全场景需求。通过一键部署、自动配置、安全可靠的特点，让应用部署变得简单高效。

无论您是开发者、运维人员还是企业用户，都可以在模板市场中找到适合的应用，快速搭建自己的服务。

---

*最后更新时间: 2025-11-11*

