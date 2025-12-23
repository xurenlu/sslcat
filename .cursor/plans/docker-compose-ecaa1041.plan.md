---
name: Docker Compose 模板化部署详细规划（加强版）
overview: ""
todos: []
---

# Docker Compose 模板化部署详细规划（加强版）

## 一、总体架构

- 内核仍基于现有 Git 部署服务，扩展模板引擎、Compose 生成器、域名管理器、服务编排器。
- 模板资源分为“内置模板（编译时嵌入）”与“用户模板（`data/templates/` 可热加载）”，按分类管理。
- 统一元数据格式 `template.yaml` 描述模板信息、变量、服务、凭证生成、健康检查、连接串格式。
- Compose 生成器负责变量替换、服务合并、网络拓扑、环境变量注入、域名信息注入。
- 数据库/服务凭证写入统一凭证仓库（SQLite，敏感信息加密存储）。
- 域名管理模块允许用户自定义主域名、追加多域名、触发反代更新与 SSL 申请。

## 二、模板系统设计

### 2.1 目录结构

```
internal/runner/templates/           # 内置模板（go:embed）
data/templates/                      # 用户模板，可热加载
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

### 2.2 模板元数据

- `template.yaml`：包含 id、name、category、tags、描述、图标、版本、变量、服务定义、凭证规则、健康检查、连接串模板、依赖关系等。
- 支持变量类型：`string`、`number`、`select`、`bool`、`password`。支持默认值、枚举、校验表达式。
- 服务定义支持 `type`（web/database/cache/message/queue/worker/etc）、端口映射、卷、依赖、环境变量、健康检查。
- 用户模板附带 `README.md` 说明、`screenshots/` 预览图（Web UI 展示用）。

### 2.3 模板加载与热更新

- 启动时扫描内置模板与 `data/templates/`，按分类构建索引。
- 使用 `fsnotify` 监听 `data/templates/`，新增/修改/删除模板实时生效。
- 冲突策略：用户模板优先于内置模板（同 `id`）。
- API 提供 `/api/git-server/templates/reload` 手动刷新入口。

## 三、模板目录（覆盖 120+ 应用）

下表按业务场景列出首批内置模板（可再扩充）。每个模板对应一个 `docker-compose.yml`、`template.yaml`、可选初始化数据。

### 3.1 CMS / Blog（内容管理与博客）

| ID | 名称 | 说明 |

|----|------|------|

| wordpress | WordPress | 全球最流行的 CMS，PHP+MySQL |

| wordpress-bedrock | WordPress Bedrock | 结构化 WordPress 项目 |

| drupal | Drupal | 企业级 CMS，PHP+PostgreSQL |

| joomla | Joomla | 开源 CMS |

| ghost | Ghost | Node.js 博客平台 |

| strapi | Strapi | Headless CMS，Node.js |

| directus | Directus | 数据驱动 CMS |

| keystone | KeystoneJS | Node.js Headless CMS |

| wagtail | Wagtail | 基于 Django 的 CMS |

| typo3 | TYPO3 | 企业级 PHP CMS |

| hexo | Hexo | Node.js 静态博客生成器 |

| hugo | Hugo | Go 静态站点生成器 |

| docusaurus | Docusaurus | 文档站点生成器 |

| gatsby | Gatsby | React 静态站 |

| nuxt-content | Nuxt Content | Vue 静态内容平台 |

### 3.2 Forum / Q&A / 社区

| ID | 名称 | 说明 |

|----|------|------|

| discourse | Discourse | Ruby on Rails + PostgreSQL |

| flarum | Flarum | 轻量 PHP 论坛 |

| phpbb | phpBB | 经典论坛 |

| nodebb | NodeBB | Node.js 实时论坛 |

| vanillaforum | Vanilla Forums | PHP 社区平台 |

| answer | Answer | 开源问答社区，Go + React |

| question2answer | Q2A | 问答社区 |

| zulip | Zulip | 团队聊天/话题流 |

| mattermost-community | Mattermost 社区版 |

| rocket-chat | Rocket.Chat | Meteor 实时聊天 |

| giscus | Giscus | GitHub Discussions 评论系统 |

| talkyard | Talkyard | 论坛 & Q&A |

| discourse-multisite | Discourse 多站点

### 3.3 RSS / Reader / 信息聚合

| ID | 名称 | 说明 |

|----|------|------|

| freshrss | FreshRSS | 自托管 RSS 聚合 |

| miniflux | Miniflux | Go 语言 RSS 阅读器 |

| ttrss | Tiny Tiny RSS | PHP RSS 阅读 |

| nextcloud-news | Nextcloud News | Nextcloud RSS 应用 |

| inoreader-clone | Inoreader Clone (Elune) |

| stringer | Stringer | Ruby RSS 阅读 |

| selfoss | Selfoss | 个人聚合器 |

| elfeed | Elfeed Web | Emacs RSS Web 版 |

### 3.4 Commerce / Shop（电商/商城）

| ID | 名称 | 说明 |

|----|------|------|

| magento | Magento 2 | PHP + Elasticsearch + RabbitMQ |

| prestashop | PrestaShop | PHP + MySQL |

| woocommerce | WooCommerce | WordPress 电商 |

| shopware | Shopware | PHP + Elasticsearch |

| bagisto | Bagisto | Laravel 电商 |

| medusa | MedusaJS | Node.js 无头电商 |

| reaction | Reaction Commerce | Node.js 电商 |

| saleor | Saleor | Django + GraphQL 电商 |

| shopify-cli | Shopify Hydrogen 开发环境 |

| opencart | OpenCart | PHP 电商 |

| nopcommerce | nopCommerce | .NET (需 container) |

| sylius | Sylius | Symfony 电商 |

### 3.5 Customer Support / Helpdesk（客服系统）

| ID | 名称 | 说明 |

|----|------|------|

| chatwoot | Chatwoot | 多渠道客服 |

| zammad | Zammad | 工单客服 |

| freeesupport | FreeScout | 开源 Zendesk 替代 |

| osticket | osTicket | 工单系统 |

| uvdesk | UVdesk | PHP 客服 |

| corteza-service-cloud | Corteza Service Cloud |

| erxes | Erxes | 客服 + CRM |

| livehelperchat | Live Helper Chat |

### 3.6 Issue Tracking / Bug Management

| ID | 名称 | 说明 |

|----|------|------|

| redmine | Redmine | Ruby 项目协作/问题跟踪 |

| taiga | Taiga | 敏捷项目管理 |

| openproject | OpenProject | 项目/问题/文档 |

| youtrack | YouTrack | JetBrains Issue Tracker |

| phabricator | Phabricator | 协作平台 |

| mantisbt | MantisBT | Bug 跟踪 |

| plane | Plane | 现代 Issue 平台 |

| sentry | Sentry | 错误监控（亦属观测类） |

### 3.7 CRM / ERP / OA

| ID | 名称 | 说明 |

|----|------|------|

| odoo | Odoo | Python 企业管理套件 |

| erpnext | ERPNext | Frappe/ERP |

| suitecrm | SuiteCRM | SugarCRM 分支 |

| dolibarr | Dolibarr | ERP & CRM |

| vtiger | Vtiger CRM |

| yetiforce | YetiForce CRM |

| espocrm | EspoCRM |

| corteza-crm | Corteza CRM |

| axelor | Axelor ERP |

| metasfresh | metasfresh ERP |

| tryton | Tryton ERP |

| kimai | Kimai | 工时管理 |

### 3.8 Analytics / BI / 统计

| ID | 名称 | 说明 |

|----|------|------|

| umami | Umami Analytics | 轻量网站分析 |

| plausible | Plausible | GDPR 友好统计 |

| matomo | Matomo | 自托管 Web Analytics |

| countly | Countly | 移动 & Web 分析 |

| ackee | Ackee | Node.js 分析 |

| fathom | Fathom Lite | 隐私友好统计 |

| goatcounter | GoatCounter | Go 语言统计 |

| metabase | Metabase | BI / Dashboard |

| superset | Apache Superset | 数据可视化 |

| redash | Redash | SQL Dashboard |

| grafana | Grafana | 监控可视化 |

| kibana | Kibana | Elastic Stack |

| loki-stack | Grafana Loki 日志 |

| clickhouse-grafana | ClickHouse + Grafana Demo |

### 3.9 Project Management / Collaboration

| ID | 名称 | 说明 |

|----|------|------|

| nextcloud | Nextcloud | 私有云 + 协作 |

| onlyoffice | OnlyOffice Docs | 在线协作编辑 |

| collabora | Collabora Online |

| etherpad | Etherpad | 实时协作文档 |

| hedgedoc | HedgeDoc | Markdown 协作 |

| wiki-js | Wiki.js | 知识库 |

| bookstack | BookStack | 文档知识库 |

| outline | Outline | 知识库 |

| kanboard | Kanboard | 看板管理 |

| wekan | Wekan | 看板 |

| outline-stack | Outline 全家桶 |

| jellyfin | Jellyfin | 媒体服务器（团队影音） |

| seafile | Seafile | 企业网盘 |

### 3.10 Developer Tools / CI / Git

| ID | 名称 | 说明 |

|----|------|------|

| gitlab | GitLab CE | DevOps 平台 |

| gitea | Gitea | 轻量 Git 服务 |

| forgejo | Forgejo | Gitea 社区分支 |

| jenkins | Jenkins | CI/CD |

| drone | Drone CI | 容器化 CI |

| woodpecker | Woodpecker CI |

| argo-workflows | Argo Workflows |

| harbor | Harbor | 镜像仓库 |

| nexus | Nexus3 | 制品库 |

| sonarqube | SonarQube | 代码质量 |

| semaphore | Semaphore | CI 工具 |

| code-server | VS Code Server |

| gitbucket | GitBucket |

### 3.11 Media / Streaming / 视频

| ID | 名称 | 说明 |

|----|------|------|

| attempts | Attempted streaming? (rename) -> remove? |

| nginx-rtmp | Nginx RTMP | 直播推流 |

| owncast | Owncast | 自托管直播 |

| peertube | PeerTube | 去中心化视频 |

| jellyfin | Jellyfin | 媒体服务器 |

| emby | Emby | 媒体服务器 |

| plex | Plex | 媒体中心 |

| navidrome | Navidrome | 音乐流媒体 |

| airsonic | Airsonic | 音乐服务 |

| searxng | SearXNG | 元搜索引擎 |

| photoprism | PhotoPrism | 照片管理 |

### 3.12 Databases / Messaging / Cache（服务实例）

| ID | 名称 | 说明 |

|----|------|------|

| mysql | MySQL 8.0 |

| mysql-5.7 | MySQL 5.7 |

| postgresql | PostgreSQL 15 |

| mariadb | MariaDB 10.11 |

| redis | Redis 7 |

| redis-cluster | Redis Cluster 三节点 |

| mongodb | MongoDB 7 |

| mongodb-replica | Mongo Replica Set |

| elasticsearch | Elasticsearch 8 |

| opensearch | OpenSearch |

| clickhouse | ClickHouse |

| kafka | Apache Kafka + Zookeeper |

| rabbitmq | RabbitMQ |

| nats | NATS Streaming |

| mosquitto | Mosquitto MQTT |

| meilisearch | Meilisearch |

| typesense | Typesense |

| etcd | etcd 集群 |

| consul | Consul |

| minio | MinIO |

| seaweedfs | SeaweedFS |

> **说明**：首批内置不少于 120 个模板（含变体）。上述列表展示主力模板，实施时按每类 8~15 个准备 Compose 及元数据。

## 四、域名管理增强

- CreateApp 接口新增 `domain`（可选）与 `domains[]`（多域名），支持用户在部署前指定。若为空则自动生成 `app.domain_suffix`。
- 新增 API：
  - `PUT /api/git-server/apps/:name/domain` 设置主域名。
  - `POST /api/git-server/apps/:name/domains` 批量添加域名。
  - `DELETE /api/git-server/apps/:name/domains/:domain` 移除域名。
  - `POST /api/git-server/apps/:name/domains/:domain/verify` 触发 DNS 验证。
- 代理管理：`addProxyRuleForApp` 调整为支持多域名，写入证书申请队列。
- SSL：自动申请/续期，失败回退（日志 + 通知）。
- UI：在应用详情页提供域名列表、状态、DNS 检查、证书状态、快速跳转。

## 五、核心模块

1. **TemplateManager**：扫描、解析、验证、索引、热更新模板。
2. **ComposeGenerator**：根据模板 + 用户参数 + 系统参数生成临时 Compose；支持 `extends` / 子模板组合。
3. **CredentialManager**：生成并加密保存数据库/服务凭证，暴露掩码展示 API。
4. **DomainManager**：自定义域名、证书管理、反代同步。
5. **DeployOrchestrator**：串联 Compose build/up、健康检查、日志聚合、失败回滚。
6. **TemplateCLI**（可选）：提供 `sslcat template list/inspect/add` CLI 工具。

## 六、API & UI

- 新增模板中心 API：`/api/git-server/templates` 支持分类、关键字、标签、排序（热度/更新时间）；`/api/git-server/templates/:id/preview` 返回 README、截图、服务拓扑。
- 模板上传 API：校验 `template.yaml` + Compose，允许 zip 上传。
- Web UI：
  - **模板市场页**（可搜索、过滤、查看详情）。
  - **模板详情页**（截图、简介、依赖、部署按钮）。
  - **部署向导**（步骤：选择模板 → 填参数 → 选域名 → 确认 → 观察实时部署日志）。
  - **应用详情页**（展示域名、服务、凭证、Compose 预览、更新/扩缩容按钮）。

## 七、实现阶段

1. **阶段 1 - 基础能力 (2 周)**：模板引擎、Compose 生成器、凭证管理、域名增强、关键 API 搭建。
2. **阶段 2 - 模板填充 (持续)**：按分类制作内置模板，验证、编写 README、截图；目标首批 ≥120 个。
3. **阶段 3 - 前端模板市场 (1.5 周)**：UI、筛选、部署向导、域名管理界面。
4. **阶段 4 - 测试与文档 (1 周)**：自动化测试、模板校验工具、用户文档、示例视频。

## 八、关键注意事项

- 模板合规性：避免引入需授权的商业镜像，使用官方/开源镜像。
- 资源配额：模板定义中提供 CPU/Memory hints，部署时可映射到 Compose `deploy.resources`。
- 安全：默认关闭外网数据库端口，优先内部网络访问；如需暴露需显式声明。
- 兼容性：大部分模板采用 `:latest` 以外的稳定 tag；提供升级策略。
- 扩展性：模板元数据支持 `extends`（例如 WordPress + Redis 组合）与 `variants`（不同数据库后端）。

## 九、交付物

- 代码：模板管理器、部署 orchestrator、新 API、UI。
- 模板库：≥120 个整理好的 `docker-compose.yml` + `template.yaml` + README。
- 文档：模板制作指南、部署指南、域名管理说明。
- 工具：模板校验 CLI、模板热加载监控脚本。
- 质量保障：完整测试矩阵、端到端部署验证脚本、烟雾测试。