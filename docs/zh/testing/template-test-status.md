# 模板测试状态文档

## 测试概览

- **测试日期**: 2025-11-09
- **测试环境**: sg2.shifen.de
- **第一轮测试**: 51 个（高优先级）
  - **已通过**: 35 个 (68.6%)
  - **失败**: 16 个 (31.4%)
- **第二轮测试**: 20 个（企业级应用）
  - **已通过**: 待统计
  - **失败**: 待统计
- **测试工具**: `tools/test-templates`

## 测试环境信息

- **操作系统**: Linux (sg2.shifen.de)
- **Docker版本**: Docker Compose v2.40.3
- **测试方式**: 自动化测试（并行2个，超时10分钟）

## 已通过模板列表 (35个)

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

## 失败模板列表 (16个)

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

### 端口冲突 (1个)

| 模板ID | 模板名称 | 失败原因 |
|--------|----------|----------|
| drone | Drone CI | `Bind for 0.0.0.0:3000 failed: port is already allocated` |

**解决方案**: 
- 已修复：将默认端口从80改为3000
- 需要重新测试

### 端口不可访问 (2个)

| 模板ID | 模板名称 | 失败原因 |
|--------|----------|----------|
| pgadmin | pgAdmin (PostgreSQL管理) | `端口 5050 (pgadmin) 不可访问: TCP 连接失败` |
| woodpecker | Woodpecker CI | `端口 8000 (woodpecker-server) 不可访问: TCP 连接失败` |

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
| 端口不可访问 | 2 | 12.5% |
| 端口冲突 | 1 | 6.2% |

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
| erpnext | ERPNext | 待测试 | ERP系统 |
| odoo | Odoo | 待测试 | ERP/CRM系统 |
| sonarqube | SonarQube | 待测试 | 代码质量分析 |
| clickhouse | ClickHouse | 待测试 | 分析数据库 |
| ghost | Ghost | 待测试 | CMS博客平台 |
| strapi | Strapi | 待测试 | 无头CMS |
| directus | Directus | 待测试 | 无头CMS |
| netdata | Netdata | 待测试 | 监控工具 |
| uptime-kuma | Uptime Kuma | 待测试 | 网站监控 |
| vaultwarden | Vaultwarden | 待测试 | 密码管理器 |
| immich | Immich | 待测试 | 照片库 |
| jellyfin | Jellyfin | 待测试 | 媒体服务器 |
| cassandra | Cassandra | 待测试 | NoSQL数据库 |
| timescaledb | TimescaleDB | 待测试 | 时序数据库 |
| discourse | Discourse | 待测试 | 论坛平台 |
| chatwoot | Chatwoot | 待测试 | 客服系统 |
| n8n | n8n | 待测试 | 工作流自动化 |
| keycloak | Keycloak | 待测试 | 身份认证 |
| traefik | Traefik | 待测试 | 反向代理 |
| homeassistant | Home Assistant | ✅ 通过 | 智能家居 |

## 第三轮测试计划（50个高优先级模板）

### 测试模板列表

**企业应用和ERP** (8个):
- erpnext, odoo, suitecrm, espocrm, dolibarr, akaunting, invoice-ninja, invoiceplane

**DevOps和CI/CD** (5个):
- sonarqube, airflow, prefect, github-actions-runner, woodpecker

**数据库和分析** (7个):
- clickhouse, cassandra, timescaledb, influxdb, couchdb, meilisearch, typesense

**CMS和内容管理** (8个):
- ghost, strapi, directus, drupal, bookstack, outline, wiki-js, hedgedoc

**监控和日志** (8个):
- netdata, uptime-kuma, better-uptime, graylog, loki, seq, plausible, fathom

**协作和通信** (5个):
- discourse, chatwoot, element, mattermost, rocketchat

**安全和身份认证** (4个):
- vaultwarden, keycloak, authelia, wireguard

**媒体和流媒体** (4个):
- immich, jellyfin, peertube, owncast

**其他实用工具** (1个):
- n8n, traefik, homeassistant, adguard-home, pi-hole

## 下一步计划

1. 完成第二轮20个模板的测试结果统计
2. 开始第三轮50个模板的测试
3. 修复镜像问题，更新镜像名称
4. 持续更新测试文档

## 最后更新时间

2025-11-09

