# Docker Compose 模板化部署实施方案

本文档用于指导“模板驱动的一键部署”功能的落地实施，包括架构扩展、代码改动、模板资产准备、前后端联动、测试与上线流程。请在开发前完成全文审阅，后续代码实施需与本方案保持一致。

---

## 1. 里程碑与总体目标

1. **基础能力扩展**：完成模板管理器、Compose 生成器、凭证管理、域名增强、部署编排器等核心模块。
2. **模板资产建设**：首批内置 ≥120 个高频应用模板，覆盖 CMS、博客、论坛、RSS、电商、客服、Issue、CRM/ERP、统计分析、项目协作、DevOps、数据库等场景。
3. **API 与前端升级**：实现模板市场、部署向导、域名管理 UI；提供完整 REST API 以支撑自动化。
4. **测试与验证**：落实单元测试、集成测试、模板自动校验、端到端部署验证。
5. **上线准备**：完善使用文档、模板贡献指南、CI 流程与监控告警，确保可持续迭代。

---

## 2. 后端架构与代码结构

```
internal/
  runner/
    template_manager.go        # 模板加载、解析、索引、热更新
    template_registry.go       # 内置模板注册器（go:embed）
    compose_generator.go       # Compose 生成与变量注入
    service_orchestrator.go    # 多服务部署/回滚编排
    credential_manager.go      # 凭证生成、加密存储、脱敏展示
    domain_manager.go          # 多域名管理、证书自动化
    templates/                 # 内置模板（编译时嵌入）
      cms/...
      blog/...
    templates_manifest.go      # 内置模板清单（构建期自动生成）
  web/
    api_templates.go           # 模板市场相关 API
    api_domains.go             # 域名管理 API 扩展
frontend/
  src/
    pages/TemplateMarket/
    components/TemplateCard.tsx
    components/DeploymentWizard.tsx
```

### 2.1 TemplateManager

- **功能**：加载内置模板 & 用户模板，解析 `template.yaml`，校验引用关系，提供分类/标签/关键词检索；监听 `data/templates/`，支持热更新；发生冲突时用户模板优先。
- **关键接口**：`LoadAll()`、`Watch()`、`List(filters)`、`Get(id)`、`Validate(meta)`、`Reload(id)`。

### 2.2 ComposeGenerator

- **功能**：基于模板元数据、用户参数、系统参数（端口、域名、凭证）生成临时 `docker-compose.yml`；支持多模板合并（如 WordPress + Redis）；自动补齐网络、卷、服务依赖；写入应用专属目录以供后续调试查看。
- **占位符**：`{{APP_NAME}}`、`{{PRIMARY_DOMAIN}}`、`{{RANDOM:16}}`、`{{mysql.username}}` 等。

### 2.3 CredentialManager

- **功能**：根据模板凭证规则生成用户名/密码/数据库名；采用 `crypto/rand` + 指定字符集；敏感信息使用系统密钥 AES-256 加密后写入 `service_credentials` 表；API 端默认脱敏展示。
- **接口**：`Generate(template)`、`Store(app, service, creds)`、`GetMasked(app)`、`Regenerate(app, service)`。

### 2.4 DomainManager

- **功能**：支持主域名 + 多别名；部署时允许自定义域名；提供增删改查、DNS 验证、证书申请触发、Nginx/Traefik 规则同步；失败场景写入审计日志。
- **接口**：`SetPrimary(app, domain)`、`AddAlias(app, domain)`、`RemoveAlias(app, domain)`、`VerifyDNS(domain)`、`SyncProxy(app)`。

### 2.5 DeployOrchestrator

- **功能**：串联 Compose build/up、健康检查、实时日志、失败回滚（蓝绿部署）；支持多容器服务同时升级；记录部署历史。
- **步骤**：生成 Compose → 生成 `.env.sslcat` → `docker compose -p <tmp>` 启动 → 健康检查 → 切换流量 → 清理旧容器。

---

## 3. 模板体系设计

### 3.1 目录规范（用户可扩展）

```
data/templates/
├── cms/
├── blog/
├── forum_qna/
├── rss_reader/
├── ecommerce/
├── customer_support/
├── issue_tracking/
├── crm_erp/
├── analytics/
├── project_management/
├── devtools/
├── media/
├── databases/
└── custom/
```

每个模板目录必须包含：

- `docker-compose.yml`：核心服务定义。
- `template.yaml`：元数据（详见 3.2）。
- `README.md`：使用说明、镜像来源、默认凭证提示。
- `assets/`：截图、架构图（用于前端展示）。
- `init/`（可选）：SQL、配置样板、迁移脚本。

### 3.2 `template.yaml` 示例

```yaml
id: wordpress
name: WordPress
category: cms
subcategory: blog
tags: [php, mysql, cms]
description: 世界最流行的 CMS 平台，内置 MySQL 与可选 Redis 缓存。
icon: wordpress
version: 1.0.0
author: SSLcat Team
website: https://wordpress.org/

variables:
  - name: WORDPRESS_VERSION
    type: select
    default: "6.4.3"
    options: ["latest", "6.4.3", "6.3.2"]
  - name: ENABLE_REDIS_CACHE
    type: bool
    default: false

services:
  - name: wordpress
    type: web
    depends_on: [mysql]
    ports:
      - internal: 80
        external: null
    healthcheck:
      type: http
      path: /wp-login.php
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    env:
      required:
        - WORDPRESS_DB_HOST
        - WORDPRESS_DB_USER
        - WORDPRESS_DB_PASSWORD
        - WORDPRESS_DB_NAME

  - name: mysql
    type: database
    ports:
      - internal: 3306
        external: null
    volumes:
      - name: mysql-data
        path: /var/lib/mysql

credentials:
  mysql:
    username:
      pattern: "{app_name}_wp"
    password:
      pattern: random
      length: 18
    database:
      pattern: "{app_name}_wp"

connection_strings:
  mysql: "mysql://{mysql.username}:{mysql.password}@mysql:3306/{mysql.database}"

healthcheck_global:
  timeout: 10m
  strategy: sequential
```

### 3.3 模板分类覆盖（首批示例）

| 分类 | 典型模板举例 |
|------|--------------|
| CMS/博客 | WordPress、Drupal、Ghost、Strapi、Directus、Keystone、Wagtail、Hugo、Hexo、Docusaurus、Gatsby、Nuxt Content |
| 论坛/Q&A | Discourse、Flarum、phpBB、NodeBB、Talkyard、Answer、Question2Answer、Mattermost、Rocket.Chat、Zulip |
| RSS/阅读器 | FreshRSS、Miniflux、Tiny Tiny RSS、Nextcloud News、Selfoss、Stringer |
| 电商/商城 | Magento、PrestaShop、WooCommerce、Shopware、Bagisto、Medusa、Reaction Commerce、Saleor、Sylius、OpenCart |
| 客服系统 | Chatwoot、Zammad、FreeScout、osTicket、UVdesk、erxes、LiveHelperChat |
| Issue/项目 | Redmine、Taiga、OpenProject、Plane、Phabricator、MantisBT、Sentry |
| CRM/ERP/OA | Odoo、ERPNext、SuiteCRM、Dolibarr、EspoCRM、YetiForce、Corteza CRM、Axelor、Tryton |
| 统计/BI | Umami、Plausible、Matomo、Countly、Ackee、Fathom、GoatCounter、Metabase、Superset、Redash、Grafana、Kibana |
| 协作/知识库 | Nextcloud、OnlyOffice、Collabora、Wiki.js、BookStack、Outline、HedgeDoc、Kanboard、Wekan、Seafile |
| DevOps/工具 | GitLab、Gitea、Forgejo、Jenkins、Drone、Woodpecker、Harbor、Nexus3、SonarQube、Code-Server、Argo Workflows |
| 媒体/流媒体 | Owncast、PeerTube、Jellyfin、Navidrome、Airsonic、PhotoPrism、Nginx-RTMP |
| 数据库/中间件 | MySQL、MySQL 5.7、PostgreSQL、MariaDB、Redis、Redis Cluster、MongoDB、Elasticsearch、OpenSearch、ClickHouse、Kafka、RabbitMQ、NATS、Meilisearch、Typesense、MinIO、SeaweedFS |

> **目标**：首批上线模板数量不少于 120 个；每个模板须包含 README、截图、默认凭证说明、镜像来源与使用许可。

### 3.4 模板校验 CLI

- 命令：`sslcat templates validate [path|id]`
- 校验项：YAML 结构、变量是否被 Compose 引用、服务依赖、端口冲突、镜像标签合法性、必需文件是否存在。
- 集成 CI：Pull Request 中新增模板必须通过校验，否则阻止合并。

---

## 4. API 扩展

### 4.1 模板相关

- `GET /api/git-server/templates`：支持分页、分类、标签、关键字、收藏排序等过滤参数。
- `GET /api/git-server/templates/{id}`：返回模板 meta、变量定义、README（Markdown）、截图、依赖说明。
- `POST /api/git-server/templates`：上传 zip 包（仅用户模板）；后端完成解压、校验、注册。
- `DELETE /api/git-server/templates/{id}`：删除用户模板；内置模板不可删除。
- `POST /api/git-server/templates/reload`：手动触发全量重载（通常用于批量上传场景）。

### 4.2 应用部署

```
POST /api/git-server/apps
{
  "name": "myapp",
  "template_id": "wordpress",
  "domain": "blog.example.com",         // 可选，若为空则使用自动域名
  "domains": ["blog.example.com", "www.blog.example.com"],
  "auto_ssl": true,
  "parameters": {
    "WORDPRESS_VERSION": "6.4.3",
    "ENABLE_REDIS_CACHE": true
  }
}
```

响应包含：应用域名列表、端口、服务列表（名称/类型/状态/端口）、脱敏凭证、Compose 文件存放路径、部署日志 ID。

### 4.3 域名管理

- `PUT /api/git-server/apps/{name}/domain`：设置主域名。
- `POST /api/git-server/apps/{name}/domains`：新增别名域名（支持批量）。
- `DELETE /api/git-server/apps/{name}/domains/{domain}`：删除别名。
- `GET /api/git-server/apps/{name}/domains`：查看域名及 SSL 状态。
- `POST /api/git-server/apps/{name}/domains/{domain}/verify`：触发 DNS 验证流程。

---

## 5. 前端实现要点

1. **模板市场页**
   - 支持分类导航、标签筛选、关键词搜索、热度/更新时间排序。
   - 模板卡片：图标、简介、标签、服务数量、部署按钮。
   - 提供列表/网格两种视图切换。

2. **模板详情页**
   - 显示 README、预览截图、服务拓扑图、资源需求提示。
   - 动态表单渲染（根据 `variables` 自动生成表单控件）。

3. **部署向导**
   - Step1 选择模板 → Step2 填写变量 → Step3 配置域名/SSL → Step4 确认并实时查看部署日志。
   - 提示自动生成的凭证（脱敏展示，部署完成后可复制）。

4. **应用详情页增强**
   - 服务状态一览、端口、容器 ID、健康检查结果。
   - 域名列表 + SSL 状态 + DNS 验证按钮。
   - Compose YAML 只读查看、凭证复制、重新部署入口。

---

## 6. 测试策略

1. **单元测试**：TemplateManager、ComposeGenerator、CredentialManager、DomainManager、DeployOrchestrator 的核心逻辑与边界条件。
2. **集成测试**：API 端到端流程（模板列表→部署→域名更新）；Docker in Docker 环境下对常用模板执行真实部署。
3. **模板校验**：CI 中运行 `sslcat templates validate --all`，确保所有模板通过校验。
4. **端到端验证脚本**：针对代表性模板（WordPress、Umami、Chatwoot、Redmine、Odoo、Nextcloud、GitLab 等）提供自动化部署+可用性检查脚本。

---

## 7. 上线 Checklist

- [ ] 模板管理器、Compose 生成器、凭证/域名模块、部署编排器全部提交并通过测试。
- [ ] 模板校验 CLI 集成到 CI（新增模板必须通过校验）。
- [ ] 首批模板 ≥120 个，README、截图、默认凭证、镜像来源完整。
- [ ] REST API 文档、Swagger 描述、前端交互说明更新完毕。
- [ ] 模板市场与部署向导前端上线，兼容移动端。
- [ ] 完成端到端部署验证脚本与监控报警配置。
- [ ] 发布用户文档、模板贡献指南、常见问题处理列表。

---

## 8. 后续扩展方向

- 模板评分/收藏/下载量统计，支撑模板市场运营。
- 模板版本化（同一模板 ID 的多版本共存与切换）。
- 支持 Helm Chart / K8s 模板，兼容云原生场景。
- 镜像安全扫描与更新提醒，保障长期运行的安全性。
- 模板依赖关系与组合模板（如“WordPress + Redis + CDN Proxy”）。

---

请在编码前根据该文档落实需求拆分与任务认领，确保开发团队对整体目标与细节有统一理解，所有代码与模板提交须与此方案保持一致。

