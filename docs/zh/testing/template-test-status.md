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
- **测试工具**: `tools/test-templates`

## 测试环境信息

- **操作系统**: Linux (sg2.shifen.de)
- **Docker版本**: Docker Compose v2.40.3
- **测试方式**: 自动化测试（并行2个，超时10分钟）

## 已通过模板列表 (106个)

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

## 失败模板列表 (15个)

### GPU相关失败 (9个)

这些模板需要 NVIDIA GPU 支持，但测试服务器没有配置 NVIDIA runtime。

| 模板ID | 模板名称 | 失败原因 |
|--------|----------|----------|
| baichuan | Baichuan (百川大模型) | `unknown or invalid runtime name: nvidia` |
| chatglm | ChatGLM (中文大模型) | `unknown or invalid runtime name: nvidia` |
| localai | LocalAI | `unknown or invalid runtime name: nvidia` |
| qwen | Qwen (通义千问) | `unknown or invalid runtime name: nvidia` |
| replicate-stable-diffusion | Replicate Stable Diffusion | `unknown or invalid runtime name: nvidia` |
| text-generation-webui | Text Generation WebUI (本地LLM界面) | `unknown or invalid runtime name: nvidia` |
| yi | Yi (零一万物大模型) | `unknown or invalid runtime name: nvidia` |

**解决方案**: 
- 在有GPU的服务器上测试
- 或者修改模板移除GPU要求（功能受限）

### 镜像不存在或访问被拒绝 (5个)

| 模板ID | 模板名称 | 失败原因 |
|--------|----------|----------|
| comfyui | ComfyUI | `pull access denied for comfyanonymous/comfyui` |
| koboldcpp | KoboldCpp (本地LLM API) | `Head "https://ghcr.io/v2/henk717/koboldcpp/manifests/latest": denied` |
| llama-cpp | llama.cpp (本地LLM推理) | `manifest unknown` |
| milvus | Milvus (向量数据库) | `manifest for quay.io/coreos/etcd:v3.5 not found: manifest unknown` |
| stable-diffusion-inpainting | Stable Diffusion Inpainting (图片修复) | `Head "https://ghcr.io/v2/linuxserver/stable-diffusion-webui/manifests/latest": denied` |
| stable-diffusion-webui | Stable Diffusion WebUI | `Head "https://ghcr.io/v2/linuxserver/stable-diffusion-webui/manifests/latest": denied` |

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

### 端口冲突 (1个)

| 模板ID | 模板名称 | 失败原因 |
|--------|----------|----------|
| drone | Drone CI | `Bind for 0.0.0.0:3000 failed: port is already allocated` |

**解决方案**: 
- 已修复：将默认端口从80改为3000
- 需要重新测试

### 端口不可访问 (1个)

| 模板ID | 模板名称 | 失败原因 |
|--------|----------|----------|
| pgadmin | pgAdmin (PostgreSQL管理) | `端口 5050 (pgadmin) 不可访问: TCP 连接失败` |

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
| GPU相关 | 7 | 43.8% |
| 镜像问题 | 6 | 37.5% |
| 端口不可访问 | 1 | 6.2% |
| 端口冲突 | 1 | 6.2% |

**注**: Woodpecker CI 已修复并通过测试，已从失败列表中移除。

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

### 已通过模板 (44个)

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

**协作和通信** (5个):
- ✅ discourse, ✅ chatwoot, ✅ element, ✅ mattermost, ✅ homeassistant

**安全和身份认证** (3个):
- ✅ vaultwarden, ✅ keycloak, ✅ authelia

**媒体和流媒体** (2个):
- ✅ peertube, ✅ owncast

**其他实用工具** (1个):
- ✅ pi-hole

### 未测试模板 (10个)

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| odoo | Odoo | crm | ERP/CRM系统 |
| airflow | Airflow | devops | 工作流调度 |
| strapi | Strapi | cms | 无头CMS |
| better-uptime | Better Uptime | devops | 网站监控 |
| wireguard | WireGuard | security | VPN服务 |
| immich | Immich | media | 照片库 |
| jellyfin | Jellyfin | media | 媒体服务器 |
| n8n | n8n | tools | 工作流自动化 |
| traefik | Traefik | tools | 反向代理 |
| adguard-home | AdGuard Home | tools | DNS和广告拦截 |

## 测试状态

⚠️ **当前状态**: 测试进程已停止

## 下一步计划

1. 恢复测试进程，完成剩余10个模板的测试
2. 修复镜像问题，更新镜像名称
3. 持续更新测试文档

## 最新测试结果（5个模板重新测试通过）

以下模板在最新测试中通过：

| 模板ID | 模板名称 | 分类 | 备注 |
|--------|----------|------|------|
| chatbot-ui | Chatbot UI | ai | AI聊天界面（重新测试） |
| librechat | LibreChat | ai | AI聊天平台（重新测试） |
| open-webui | Open WebUI | ai | AI Web界面（重新测试） |
| homeassistant | Home Assistant | collaboration | 智能家居平台 |
| umami | Umami | analytics | 网站分析工具 |

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

## 最后更新时间

2025-11-09（已更新第三轮测试结果）

