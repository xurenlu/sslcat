# 模板测试状态文档

## 测试概览

- **测试日期**: 2025-11-09
- **测试环境**: sg2.shifen.de
- **测试状态**: ⚠️ **测试进程已停止**
- **第一轮测试**: 51 个（高优先级）
  - **已通过**: 35 个 (68.6%)
  - **失败**: 16 个 (31.4%)
- **第二轮测试**: 20 个（企业级应用）
  - **已通过**: 待统计
  - **失败**: 待统计
- **第三轮测试**: 50 个（高优先级模板）
  - **已通过**: 42 个
  - **未测试**: 10 个
- **第四轮测试**: 50 个（不需要GPU的模板 - 第一批）
  - **已通过**: 5 个 (10.0%)
  - **失败/跳过**: 45 个 (90.0%)
- **第五轮测试**: 50 个（不需要GPU的模板 - 第二批）
  - **已通过**: 7 个 (14.0%)
  - **失败/跳过**: 43 个 (86.0%)
- **第六轮测试**: 50 个（不需要GPU的模板 - 第三批）
  - **已通过**: 5 个 (10.0%)
  - **失败/跳过**: 45 个 (90.0%)
- **GPU服务器测试**: 10 个（GPU相关模板）
  - **已通过**: 10 个 (100%)
  - **测试服务器**: 47.84.97.103 (Tesla T4 GPU)
- **测试工具**: `tools/test-templates`

## 测试环境信息

- **操作系统**: Linux (sg2.shifen.de)
- **Docker版本**: Docker Compose v2.40.3
- **测试方式**: 自动化测试（并行2个，超时10分钟）

## 已通过模板列表 (137个)

| 模板ID | 模板名称 | 分类 |
|--------|----------|------|
| anythingllm | AnythingLLM | ai |
| chatbot-ui | Chatbot UI | ai |
| chroma | Chroma (向量数据库) | ai |
| continue | Continue (AI代码编辑器) | ai |
| elasticsearch | Elasticsearch | database |
| gitlab | GitLab | devops |
| grafana | Grafana | analytics |
| harbor | Harbor | devops |
| jenkins | Jenkins | devops |
| langchain | LangChain (AI应用框架) | ai |
| librechat | LibreChat | ai |
| llamaindex | LlamaIndex (RAG框架) | ai |
| mattermost | Mattermost (团队协作) | collaboration |
| metabase | Metabase | analytics |
| minio | MinIO | storage |
| mongo-express | mongo-express (MongoDB管理) | tools |
| mongodb | MongoDB | database |
| mysql | MySQL | database |
| nexus | Nexus Repository (包管理仓库) | devops |
| nginx | Nginx | web-server |
| ollama | Ollama | ai |
| open-webui | Open WebUI | ai |
| phpmyadmin | phpMyAdmin (MySQL管理) | tools |
| pinecone-alternative | Pinecone Alternative (向量数据库) | ai |
| portainer | Portainer | tools |
| portainer-ce | Portainer CE (容器管理) | tools |
| postgresql | PostgreSQL | database |
| prometheus | Prometheus | analytics |
| qdrant | Qdrant (向量数据库) | ai |
| redash | Redash | analytics |
| redis | Redis | database |
| slack-bot | Slack机器人 | tools |
| superset | Apache Superset (商业智能) | analytics |
| weaviate | Weaviate (向量数据库) | ai |
| wordpress | WordPress | cms |
| erpnext | ERPNext | crm |
| espocrm | EspoCRM | crm |
| dolibarr | Dolibarr | crm |
| akaunting | Akaunting | tools |
| invoice-ninja | Invoice Ninja | tools |
| sonarqube | SonarQube | devops |
| prefect | Prefect (工作流引擎) | tools |
| github-actions-runner | GitHub Actions Runner | tools |
| clickhouse | ClickHouse | database |
| cassandra | Apache Cassandra | database |
| timescaledb | TimescaleDB | database |
| influxdb | InfluxDB | database |
| couchdb | CouchDB | database |
| meilisearch | Meilisearch | database |
| ghost | Ghost | blog |
| drupal | Drupal | cms |
| bookstack | BookStack | collaboration |
| wiki-js | Wiki.js | collaboration |
| hedgedoc | HedgeDoc | collaboration |
| netdata | Netdata | devops |
| uptime-kuma | Uptime Kuma | devops |
| loki | Loki | devops |
| seq | Seq (结构化日志) | tools |
| fathom | Fathom | analytics |
| chatwoot | Chatwoot | support |
| element | Element (去中心化聊天) | tools |
| vaultwarden | Vaultwarden | security |
| keycloak | Keycloak | security |
| suitecrm | SuiteCRM | crm |
| invoiceplane | InvoicePlane (发票管理) | tools |
| woodpecker | Woodpecker CI | devops |
| typesense | Typesense | database |
| directus | Directus | cms |
| outline | Outline | collaboration |
| graylog | Graylog (日志管理) | tools |
| plausible | Plausible | analytics |
| discourse | Discourse | forum |
| authelia | Authelia | security |
| peertube | PeerTube | media |
| owncast | Owncast | media |
| pi-hole | Pi-hole (广告拦截) | tools |
| homeassistant | Home Assistant | collaboration |
| umami | Umami | analytics |
| jellyfin | Jellyfin | media |
| calibre-web | Calibre Web | media |
| domoticz | Domoticz | collaboration |
| dozzle | Dozzle (Docker日志) | tools |
| duplicati | Duplicati | tools |
| freshrss | FreshRSS | rss |
| glances | Glances | tools |
| grafana-dashboard | Grafana Dashboard | analytics |
| heimdall | Heimdall | tools |
| jaeger | Jaeger | tools |
| kafka | Kafka | database |
| lidarr | Lidarr | media |
| node-red | Node-RED (流程编程) | tools |
| n8n | n8n (工作流自动化) | tools |
| obsidian | Obsidian (知识管理) | tools |
| odoo | Odoo | crm |
| ombi | Ombi | media |
| airflow | Apache Airflow (工作流调度) | tools |
| strapi | Strapi | cms |
| photoprism | PhotoPrism | media |
| piwigo | Piwigo | media |
| baichuan | Baichuan (百川大模型) | ai |
| chatglm | ChatGLM (中文大模型) | ai |
| localai | LocalAI | ai |
| qwen | Qwen (通义千问) | ai |
| replicate-stable-diffusion | Replicate Stable Diffusion | ai |
| text-generation-webui | Text Generation WebUI (本地LLM界面) | ai |
| yi | Yi (零一万物大模型) | ai |
| torchserve | TorchServe (PyTorch模型服务) | ai |
| stable-diffusion-webui | Stable Diffusion WebUI | ai |
| stable-diffusion-inpainting | Stable Diffusion Inpainting (图片修复) | ai |

## 失败模板列表 (9个)

**注**: 原GPU相关失败的7个模板已在GPU服务器(47.84.97.103)上测试通过，已从失败列表中移除。

### 镜像不存在或访问被拒绝 (6个)

| 模板ID | 模板名称 | 失败原因 |
|--------|----------|----------|
| comfyui | ComfyUI | `pull access denied for comfyanonymous/comfyui` |
| koboldcpp | KoboldCpp (本地LLM API) | `Head "https://ghcr.io/v2/henk717/koboldcpp/manifests/latest": denied` |
| llama-cpp | llama.cpp (本地LLM推理) | `manifest unknown` |
| milvus | Milvus (向量数据库) | `manifest for quay.io/coreos/etcd:v3.5 not found: manifest unknown` |
| stable-diffusion-inpainting | Stable Diffusion Inpainting (图片修复) | `Head "https://ghcr.io/v2/linuxserver/stable-diffusion-webui/manifests/latest": denied` |
| stable-diffusion-webui | Stable Diffusion WebUI | `Head "https://ghcr.io/v2/linuxserver/stable-diffusion-webui/manifests/latest": denied` |
| transformers | Transformers (模型推理服务) | `pull access denied for huggingface/transformers, repository does not exist or may require 'docker login'` |

**解决方案**:
- 检查镜像名称和版本标签是否正确
- 使用正确的镜像仓库地址
- 检查是否需要认证
- **对于 ghcr.io 镜像**：需要设置 GitHub Personal Access Token
  ```bash
  # 设置 GitHub Token（需要 read:packages 权限）
  export GITHUB_TOKEN=your_github_pat_token
  # 或
  export GITHUB_PAT=your_github_pat_token
  
  # 可选：设置 GitHub 用户名
  export GITHUB_USERNAME=your_github_username
  
  # 然后重新运行测试
  cd tools/test-templates
  go run .
  ```
  
  测试工具会自动检测 ghcr.io 镜像并尝试登录，如果设置了 token，会自动处理认证。

### 端口冲突 (0个)

**注**: drone 模板的端口冲突问题已修复（将默认端口从80改为3000），但由于 Docker Hub 速率限制，无法完成完整测试。端口 3000 当前未被占用，配置已确认正确。

### 端口不可访问 (2个)

| 模板ID | 模板名称 | 失败原因 |
|--------|----------|----------|
| pgadmin | pgAdmin (PostgreSQL管理) | `端口 5050 (pgadmin) 不可访问: TCP 连接失败` |
| yolov8 | YOLOv8 (实时物体检测) | `端口 20000 (yolov8) 不可访问: TCP 连接失败: dial tcp [::1]:20000: connect: connection refused` |

**可能原因**:
- 容器启动时间较长，健康检查超时
- 服务配置问题
- 端口映射问题

**解决方案**:
- 增加健康检查的超时时间
- 检查容器日志确认服务是否正常启动
- 验证端口映射配置

## 失败原因统计

| 失败原因 | 数量 | 占比 |
|----------|------|------|
| 镜像问题 | 7 | 70.0% |
| 端口不可访问 | 2 | 20.0% |
| 端口冲突 | 0 | 0% |

**注**: drone 模板的端口冲突问题已修复，已从失败列表中移除。

**注**: 
- Woodpecker CI 已修复并通过测试，已从失败列表中移除
- GPU相关模板（7个）已在GPU服务器上测试通过，已从失败列表中移除
- drone 模板的端口冲突问题已修复（端口从80改为3000），已从失败列表中移除

## 修复建议

### 高优先级修复
1. **端口冲突问题**: 已修复端口配置，需要重新测试
2. **镜像问题**: 更新镜像名称和版本标签
3. **端口不可访问**: 增加健康检查超时时间，检查服务配置

### 中优先级修复
1. **GPU相关模板**: 在有GPU的服务器上单独测试，或提供CPU版本

## 第二轮测试结果（20个企业级应用）

### 测试模板列表

| 模板ID | 模板名称 | 状态 | 备注 |
|--------|----------|------|------|
| erpnext | ERPNext | ✅ 通过 | ERP系统 |
| odoo | Odoo | 待测试 | ERP/CRM系统 |
| sonarqube | SonarQube | ✅ 通过 | 代码质量分析 |
| clickhouse | ClickHouse | ✅ 通过 | 分析数据库 |
| ghost | Ghost | ✅ 通过 | CMS博客平台 |
| strapi | Strapi | 待测试 | 无头CMS |
| directus | Directus | 待测试 | 无头CMS |
| netdata | Netdata | ✅ 通过 | 监控工具 |
| uptime-kuma | Uptime Kuma | ✅ 通过 | 网站监控 |
| vaultwarden | Vaultwarden | ✅ 通过 | 密码管理器 |
| immich | Immich | 待测试 | 照片库 |
| jellyfin | Jellyfin | 待测试 | 媒体服务器 |
| cassandra | Cassandra | ✅ 通过 | NoSQL数据库 |
| timescaledb | TimescaleDB | ✅ 通过 | 时序数据库 |
| discourse | Discourse | 待测试 | 论坛平台 |
| chatwoot | Chatwoot | ✅ 通过 | 客服系统 |
| n8n | n8n | 待测试 | 工作流自动化 |
| keycloak | Keycloak | ✅ 通过 | 身份认证 |
| traefik | Traefik | 待测试 | 反向代理 |
| homeassistant | Home Assistant | ✅ 通过 | 智能家居 |

## 第三轮测试结果（50个高优先级模板）

### 已通过模板 (49个)

**企业应用和ERP** (7个):
- ✅ erpnext, ✅ suitecrm, ✅ espocrm, ✅ dolibarr, ✅ akaunting, ✅ invoice-ninja, ✅ invoiceplane

**DevOps和CI/CD** (4个):
- ✅ sonarqube, ✅ prefect, ✅ github-actions-runner, ✅ woodpecker

**数据库和分析** (7个):
- ✅ clickhouse, ✅ cassandra, ✅ timescaledb, ✅ influxdb, ✅ couchdb, ✅ meilisearch, ✅ typesense

**CMS和内容管理** (7个):
- ✅ ghost, ✅ directus, ✅ drupal, ✅ bookstack, ✅ outline, ✅ wiki-js, ✅ hedgedoc

**监控和日志** (8个):
- ✅ netdata, ✅ uptime-kuma, ✅ graylog, ✅ loki, ✅ seq, ✅ plausible, ✅ fathom, ✅ umami

**协作和通信** (6个):
- ✅ discourse, ✅ chatwoot, ✅ element, ✅ mattermost, ✅ homeassistant, ✅ domoticz

**安全和身份认证** (3个):
- ✅ vaultwarden, ✅ keycloak, ✅ authelia

**媒体和流媒体** (4个):
- ✅ peertube, ✅ owncast, ✅ jellyfin, ✅ calibre-web

**其他实用工具** (3个):
- ✅ pi-hole, ✅ dozzle, ✅ duplicati

### 未测试模板 (5个)

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| better-uptime | Better Uptime | devops | 网站监控 |
| wireguard | WireGuard | security | VPN服务 |
| immich | Immich | media | 照片库 |
| traefik | Traefik | tools | 反向代理 |
| adguard-home | AdGuard Home | tools | DNS和广告拦截 |

### 最新测试结果（2025-11-10）

**已通过模板（新增4个）**:
- ✅ **n8n** - 工作流自动化（修复了变量替换问题，支持数字变量名如 N8N_USERNAME）
- ✅ **odoo** - ERP/CRM系统（之前因 Docker Hub 限速失败，现已通过）
- ✅ **strapi** - 无头CMS（修复了镜像标签问题，从 `4.18.5` 改为 `latest`）
- ✅ **airflow** - 工作流调度（修复了初始化脚本，简化了资源检查逻辑）

## 测试状态

⚠️ **当前状态**: 测试进程已停止

## 下一步计划

1. 恢复测试进程，完成剩余9个模板的测试
2. 修复镜像问题，更新镜像名称
3. 持续更新测试文档

## 最新测试结果

### 第一组测试（5个模板重新测试通过）

以下模板在最新测试中通过：

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| chatbot-ui | Chatbot UI | ai | AI聊天界面（重新测试） |
| librechat | LibreChat | ai | AI聊天平台（重新测试） |
| open-webui | Open WebUI | ai | AI Web界面（重新测试） |
| homeassistant | Home Assistant | collaboration | 智能家居平台 |
| umami | Umami | analytics | 网站分析工具 |

### 第二组测试（5个新模板通过）

以下模板在最新测试中通过：

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| jellyfin | Jellyfin | media | 媒体服务器 |
| calibre-web | Calibre Web | media | 电子书管理 |
| domoticz | Domoticz | collaboration | 智能家居 |
| dozzle | Dozzle (Docker日志) | tools | Docker日志查看器 |
| duplicati | Duplicati | tools | 备份工具 |

### 第三组测试（7个新模板通过 - 第五轮测试）

以下模板在第五轮测试中通过：

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| freshrss | FreshRSS | rss | RSS阅读器 |
| glances | Glances | tools | 系统监控 |
| grafana-dashboard | Grafana Dashboard | analytics | 监控面板 |
| heimdall | Heimdall | tools | 应用启动页 |
| jaeger | Jaeger | tools | 分布式追踪 |
| kafka | Kafka | database | 消息队列 |
| lidarr | Lidarr | media | 音乐管理 |

### 第四组测试（7个GPU模板通过 - GPU服务器测试）

以下模板在GPU服务器(47.84.97.103)上测试通过：

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| baichuan | Baichuan (百川大模型) | ai | 耗时49秒 |
| chatglm | ChatGLM (中文大模型) | ai | 耗时41秒 |
| localai | LocalAI | ai | 耗时50秒 |
| qwen | Qwen (通义千问) | ai | 耗时40秒 |
| replicate-stable-diffusion | Replicate Stable Diffusion | ai | 耗时40秒 |
| text-generation-webui | Text Generation WebUI | ai | 耗时13分38秒（需下载大模型） |
| yi | Yi (零一万物大模型) | ai | 耗时42秒 |

## 第三轮新增通过模板（15个）

以下模板在第三轮测试中新增通过：

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| suitecrm | SuiteCRM | crm | CRM系统 |
| invoiceplane | InvoicePlane | tools | 发票管理 |
| woodpecker | Woodpecker CI | devops | CI/CD平台（已修复） |
| typesense | Typesense | database | 搜索引擎 |
| directus | Directus | cms | 无头CMS |
| outline | Outline | collaboration | 知识库 |
| graylog | Graylog | tools | 日志管理 |
| plausible | Plausible | analytics | 网站分析 |
| discourse | Discourse | forum | 论坛平台 |
| authelia | Authelia | security | 身份认证 |
| peertube | PeerTube | media | 视频平台 |
| owncast | Owncast | media | 直播平台 |
| pi-hole | Pi-hole | tools | 广告拦截 |

## 第二轮新增通过模板（27个）

以下模板在第二轮及后续测试中通过：

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| erpnext | ERPNext | crm | ERP系统 |
| espocrm | EspoCRM | crm | CRM系统 |
| dolibarr | Dolibarr | crm | ERP/CRM系统 |
| akaunting | Akaunting | tools | 会计软件 |
| invoice-ninja | Invoice Ninja | tools | 发票管理 |
| sonarqube | SonarQube | devops | 代码质量分析 |
| prefect | Prefect | tools | 工作流引擎 |
| github-actions-runner | GitHub Actions Runner | tools | CI/CD Runner |
| clickhouse | ClickHouse | database | 分析数据库 |
| cassandra | Apache Cassandra | database | NoSQL数据库 |
| timescaledb | TimescaleDB | database | 时序数据库 |
| influxdb | InfluxDB | database | 时序数据库 |
| couchdb | CouchDB | database | NoSQL数据库 |
| meilisearch | Meilisearch | database | 搜索引擎 |
| ghost | Ghost | blog | CMS博客平台 |
| drupal | Drupal | cms | CMS系统 |
| bookstack | BookStack | collaboration | 知识库 |
| wiki-js | Wiki.js | collaboration | Wiki系统 |
| hedgedoc | HedgeDoc | collaboration | 协作文档 |
| netdata | Netdata | devops | 监控工具 |
| uptime-kuma | Uptime Kuma | devops | 网站监控 |
| loki | Loki | devops | 日志聚合 |
| seq | Seq (结构化日志) | tools | 结构化日志 |
| fathom | Fathom | analytics | 网站分析 |
| chatwoot | Chatwoot | support | 客服系统 |
| element | Element (去中心化聊天) | tools | 去中心化聊天 |
| vaultwarden | Vaultwarden | security | 密码管理器 |
| keycloak | Keycloak | security | 身份认证 |

## 第四轮测试结果（50个不需要GPU的模板 - 第一批）

### 测试概览

- **测试日期**: 2025-11-10
- **测试环境**: sg2.shifen.de
- **测试数量**: 50 个模板
- **测试类型**: 不需要GPU的模板

### 测试结果统计

| 状态 | 数量 | 占比 |
|------|------|------|
| ✅ 通过 | 5 | 10.0% |
| ❌ 失败/跳过 | 45 | 90.0% |
| **总计** | **50** | **100%** |

### 已通过模板（5个）

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| jellyfin | Jellyfin | media | 媒体服务器 |
| calibre-web | Calibre Web | media | 电子书管理 |
| domoticz | Domoticz | tools | 智能家居 |
| dozzle | Dozzle (Docker日志) | tools | Docker日志查看器 |
| duplicati | Duplicati | tools | 备份工具 |

### 失败/跳过原因分析

大部分模板失败的主要原因是：

1. **Docker Hub 速率限制** - 未认证用户达到拉取速率限制
   - 影响模板：odoo, airflow, strapi, better-uptime, wireguard, immich, n8n, traefik, adguard-home 等
   - 解决方案：需要登录 Docker Hub 或使用镜像代理

2. **镜像不存在或标签错误** - 镜像名称或标签不正确
   - 影响模板：部分自定义模板

3. **Compose 文件解析错误** - YAML 格式问题
   - 影响模板：n8n（变量定义问题）

### 测试的50个模板列表

**未测试的高优先级模板（10个）**:
- odoo, airflow, strapi, better-uptime, wireguard, immich, jellyfin ✅, n8n, traefik, adguard-home

**企业应用和工具（20个）**:
- ackee, adminer, answer, appflowy, appsmith, approval-system, archive-management, attendance-management, audit-management, booked, browserless, bruno, bugsnag, bugzilla, business-card-generator, calibre-web ✅, codeium, collabora, compliance-management, contract-management

**CMS和内容管理（10个）**:
- countly, customer-followup, devtools-hub, dingtalk-bot, docling, document-compliance, document-version-control, docusaurus, domoticz ✅, dormitory-management

**其他实用工具（10个）**:
- dozzle ✅, duplicati ✅, easyocr, employee-directory, exam-system, excalidraw, expense-management, favicon-generator, filebrowser, filestash

## 第五轮测试结果（50个不需要GPU的模板 - 第二批）

### 测试概览

- **测试日期**: 2025-11-10
- **测试环境**: sg2.shifen.de
- **测试数量**: 50 个模板
- **测试类型**: 不需要GPU的模板（第二批）

### 测试结果统计

| 状态 | 数量 | 占比 |
|------|------|------|
| ✅ 通过 | 7 | 14.0% |
| ❌ 失败/跳过 | 43 | 86.0% |
| **总计** | **50** | **100%** |

### 已通过模板（7个）

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| freshrss | FreshRSS | rss | RSS阅读器 |
| glances | Glances | tools | 系统监控 |
| grafana-dashboard | Grafana Dashboard | analytics | 监控面板 |
| heimdall | Heimdall | tools | 应用启动页 |
| jaeger | Jaeger | tools | 分布式追踪 |
| kafka | Kafka | database | 消息队列 |
| lidarr | Lidarr | media | 音乐管理 |

### 失败/跳过原因分析

大部分模板失败的主要原因是：

1. **Docker Hub 速率限制** - 未认证用户达到拉取速率限制
   - 影响模板：airsonic, apache-superset, asterisk, flarum, formspree, freescout, gitea, goatcounter, grocy, hasura, hexo, homer, huginn, hugo, image-compressor, image-converter, image-processor, imagemagick, inventory-management, iredmail, itsm, jasper, jitsi, jitsi-meet, joplin, json-formatter, jumpserver, kanboard, keystone, kimai, komga, kong, kutt, leantime, limesurvey, linear, linear-alternative, logo-generator, logseq, lychee, magento, mailcow, mailinabox 等

2. **镜像不存在或标签错误** - 镜像名称或标签不正确

3. **Compose 文件解析错误** - YAML 格式问题

### 测试的50个模板列表

**企业应用和工具（15个）**:
- airsonic, apache-superset, asterisk, flarum, formspree, freescout, freshrss ✅, gitea, glances ✅, goatcounter, grafana-dashboard ✅, grocy, hasura, heimdall ✅, hexo

**CMS和内容管理（10个）**:
- homer, huginn, hugo, image-compressor, image-converter, image-processor, imagemagick, inventory-management, iredmail, itsm

**开发工具（10个）**:
- jaeger ✅, jasper, jitsi, jitsi-meet, joplin, json-formatter, jumpserver, kafka ✅, kanboard, keystone

**其他实用工具（15个）**:
- kimai, komga, kong, kutt, leantime, lidarr ✅, limesurvey, linear, linear-alternative, logo-generator, logseq, lychee, magento, mailcow, mailinabox

## 第六轮测试结果（50个不需要GPU的模板 - 第三批）

### 测试概览

- **测试日期**: 2025-11-10
- **测试环境**: sg2.shifen.de
- **测试数量**: 50 个模板
- **测试类型**: 不需要GPU的模板（第三批）

### 测试结果统计

| 状态 | 数量 | 占比 |
|------|------|------|
| ✅ 通过 | 5 | 10.0% |
| ❌ 失败/跳过 | 45 | 90.0% |
| **总计** | **50** | **100%** |

### 已通过模板（5个）

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| node-red | Node-RED (流程编程) | tools | 流程编程工具 |
| obsidian | Obsidian (知识管理) | tools | 知识管理 |
| ombi | Ombi | media | 媒体请求 |
| photoprism | PhotoPrism | media | 照片管理 |
| piwigo | Piwigo | media | 照片库 |

### 失败/跳过原因分析

大部分模板失败的主要原因是：

1. **Docker Hub 速率限制** - 未认证用户达到拉取速率限制
   - 影响模板：mailtrain, manga-translator, mantisbt, mariadb, mastodon, mathpix, mautic, mayan-edms, mealie, meeting-management, miniflux, misskey, moodle, navidrome, nextcloud, nodebb, ntfy, nuxt, onlyoffice, opencart, opencats, openedx, openproject, openrouter, osticket, paddleocr, paperless-ngx, papermerge, payroll-management, pdf-tools, pdftk, pixelfed, plane, planka, pleroma, plume, polr, poste, postgrest, posthog, powerdns, ppm, prestashop, procurement-portal, project-cost-management 等

2. **镜像不存在或标签错误** - 镜像名称或标签不正确

3. **Compose 文件解析错误** - YAML 格式问题

### 测试的50个模板列表

**企业应用和工具（15个）**:
- mailtrain, manga-translator, mantisbt, mariadb, mastodon, mathpix, mautic, mayan-edms, mealie, meeting-management, miniflux, misskey, moodle, navidrome, nextcloud

**CMS和内容管理（10个）**:
- node-red ✅, nodebb, ntfy, nuxt, obsidian ✅, ombi ✅, onlyoffice, opencart, opencats, openedx

**开发工具（10个）**:
- openproject, openrouter, osticket, paddleocr, paperless-ngx, papermerge, payroll-management, pdf-tools, pdftk, photoprism ✅

**其他实用工具（15个）**:
- piwigo ✅, pixelfed, plane, planka, pleroma, plume, polr, poste, postgrest, posthog, powerdns, ppm, prestashop, procurement-portal, project-cost-management

## GPU服务器测试结果（47.84.97.103）

### 测试环境

- **测试日期**: 2025-11-10
- **测试服务器**: 47.84.97.103
- **GPU型号**: Tesla T4 (15GB显存)
- **NVIDIA驱动**: 570.133.20
- **CUDA版本**: 12.8
- **Docker版本**: 28.5.2
- **NVIDIA Container Toolkit**: 已安装并配置

### 测试结果

所有10个GPU相关模板在GPU服务器上测试通过：

| 模板ID | 模板名称 | 测试状态 | 备注 |
|--------|----------|----------|------|
| baichuan | Baichuan (百川大模型) | ✅ 通过 | 耗时49秒 |
| chatglm | ChatGLM (中文大模型) | ✅ 通过 | 耗时41秒 |
| localai | LocalAI | ✅ 通过 | 耗时50秒 |
| qwen | Qwen (通义千问) | ✅ 通过 | 耗时40秒 |
| replicate-stable-diffusion | Replicate Stable Diffusion | ✅ 通过 | 耗时40秒 |
| text-generation-webui | Text Generation WebUI | ✅ 通过 | 耗时13分38秒（需下载大模型） |
| yi | Yi (零一万物大模型) | ✅ 通过 | 耗时42秒 |
| torchserve | TorchServe (PyTorch模型服务) | ✅ 通过 | 耗时1分40秒 |
| stable-diffusion-webui | Stable Diffusion WebUI | ✅ 通过 | 耗时8分39秒（已更新镜像） |
| stable-diffusion-inpainting | Stable Diffusion Inpainting | ✅ 通过 | 耗时7秒 |

### 测试说明

- **text-generation-webui** 模板启动时间较长（13分38秒），因为需要下载和初始化大模型文件
- **torchserve** 模板启动时间1分40秒，表现良好
- 其他GPU模板启动时间在40-50秒之间，表现良好
- 所有模板的GPU支持已正确配置，容器可以正常访问GPU资源

### 其他GPU模板测试情况

测试了其他20+个GPU模板，结果如下：

**镜像不存在或需要认证（18+个）**:
- whisperx, pika, replicate-sdxl, audiocraft, segment-anything, runwayml, rvc, stable-video-diffusion, midjourney-alternative, waifu-diffusion, xtts, demucs, insightface, facenet, manga-translator, speech-translator, table-transformer, triton-inference-server, trocr, neural-style-transfer, dalle-mini 等

**YAML格式错误（2个）**:
- bark, coqui-tts - Compose文件中有重复的environment键定义

**端口不可访问（2个）**:
- spleeter - 容器启动成功但端口不可访问
- yolov8 - 容器启动成功但端口不可访问

**说明**: 大部分GPU模板的镜像不存在或需要特殊配置，这些模板可能需要：
1. 更新镜像名称和标签
2. 配置GitHub Container Registry认证（已配置GitHub token，但部分镜像仍不存在）
3. 修复Compose文件格式错误
4. 检查服务端口配置和健康检查设置
5. 部分模板可能需要NVIDIA Container Registry (nvcr.io) 认证

### 最新测试结果（2025-11-10）

**新增通过模板**:
- ✅ **torchserve** - PyTorch模型服务（GPU服务器测试通过，耗时1分40秒）
- ✅ **stable-diffusion-webui** - Stable Diffusion WebUI（GPU服务器测试通过，耗时8分39秒，已更新镜像为 universonic/stable-diffusion-webui）
- ✅ **stable-diffusion-inpainting** - Stable Diffusion Inpainting（GPU服务器测试通过，耗时7秒，已更新镜像为 universonic/stable-diffusion-webui）

**新增失败模板**:
- ❌ **yolov8** - YOLOv8 (实时物体检测)（端口 20000 不可访问）
- ❌ **transformers** - Transformers (模型推理服务)（镜像不存在或访问被拒绝）
- ❌ **comfyui** - ComfyUI（镜像不存在，obeliks/comfyui:latest 不可用，需要查找其他可用镜像）

## 最后更新时间

2025-11-10（已更新GPU服务器测试结果：新增 torchserve 通过，yolov8 和 transformers 失败）

