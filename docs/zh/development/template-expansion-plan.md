# 模板库扩展计划

## 目标
将模板库从当前的 120+ 个扩展到 **300+ 个**，打造企业级一站式应用部署平台。

## 当前状态
- **已实现：** 120+ 个模板
- **目标：** 300+ 个模板
- **缺口：** 180+ 个模板

## 扩展方向

### 一、AI 和机器学习（目标：20+ 个）

#### 已实现（2个）
- Ollama - LLM 运行环境
- Open WebUI - AI 聊天界面

#### 待添加（18+ 个）
1. **文本生成和对话**
   - Text Generation WebUI - 文本生成 Web UI
   - Kobold AI - AI 文本生成服务
   - SillyTavern - AI 角色扮演聊天
   - Jan - 本地 AI 助手

2. **图像生成**
   - Stable Diffusion WebUI - 图像生成
   - InvokeAI - 专业 AI 图像生成
   - ComfyUI - 节点式 AI 工作流
   - Fooocus - 简化版 Stable Diffusion

3. **语音和视频**
   - Whisper WebUI - 语音转文字
   - Coqui TTS - 文字转语音
   - RVC - 声音克隆

4. **AI 工具集**
   - AnythingLLM - 私有化 ChatGPT
   - LibreChat - ChatGPT 替代品
   - LocalAI - OpenAI 兼容 API
   - vLLM - 高性能 LLM 推理

### 二、PDF 和文档处理（目标：15+ 个）

#### 已实现（2个）
- Stirling PDF - 全功能 PDF 工具
- PDFtk Server - PDF 处理服务

#### 待添加（13+ 个）
1. **PDF 处理**
   - PDF.js - PDF 查看器
   - PDF24 Creator - PDF 创建和编辑
   - PDFsam - PDF 分割合并
   - PDFtk Builder - PDF 构建工具

2. **文档转换**
   - LibreOffice Online - 在线办公套件
   - OnlyOffice（已有，可增强）
   - Collabora Online（已有，可增强）

3. **文档管理**
   - Mayan EDMS - 企业文档管理系统
   - Papermerge - 文档管理系统
   - Docspell - 文档组织工具

4. **OCR 和识别**
   - Tesseract OCR Server - OCR 服务
   - PaddleOCR - 中文 OCR
   - EasyOCR - 多语言 OCR
   - TrOCR - Transformer OCR

### 三、图片处理（目标：15+ 个）

#### 已实现（1个）
- ImageMagick - 图片处理工具

#### 待添加（14+ 个）
1. **图片编辑**
   - Photopea - 在线 Photoshop
   - GIMP - 图片编辑器
   - Krita - 数字绘画
   - Pinta - 简单图片编辑

2. **图片管理**
   - Piwigo（已有）
   - Lychee（已有）
   - Photoprism（已有）
   - Immich（已有）
   - LibrePhotos - 照片管理
   - Photoview - 照片查看器

3. **图片处理服务**
   - Thumbor - 智能图片服务
   - ImageProxy - 图片代理服务
   - Picfit - 图片缩放服务

4. **公式识别**
   - Mathpix Snip - 公式识别
   - MathOCR - 数学公式 OCR

### 四、短链接和文件分享（目标：10+ 个）

#### 已实现（4个）
- Polr - 短链接服务
- Kutt - 现代化短链接
- Transfer.sh - 文件分享
- Send - 加密文件分享

#### 待添加（6+ 个）
1. **短链接**
   - YOURLS - 自托管短链接
   - Shlink - RESTful 短链接 API
   - Shorty - 轻量短链接

2. **文件分享**
   - Firefox Send（已停止，可用 Send 替代）
   - Lufi - 加密文件分享
   - OnionShare - 匿名文件分享
   - Pingvin Share - 文件分享平台

### 五、表单和调查（目标：10+ 个）

#### 已实现（1个）
- Typeform - 表单工具

#### 待添加（9+ 个）
1. **表单构建器**
   - FormBuilder - 表单构建器
   - Form.io - 企业表单平台
   - OhMyForm - 开源表单工具
   - FormSpree - 表单后端服务

2. **调查工具**
   - LimeSurvey - 专业调查工具
   - SurveyJS - 调查问卷库
   - FormKeep - 表单收集

3. **金数据类**
   - FormBuilder（类似金数据）
   - Typeform（已有）

### 六、知识库和文档（目标：20+ 个）

#### 已实现（5个）
- BookStack - Wiki 平台
- Outline - 现代化知识库
- Wiki.js - Wiki 系统
- Docusaurus - 文档站点
- HedgeDoc - Markdown 编辑器

#### 待添加（15+ 个）
1. **知识库**
   - TiddlyWiki - 个人知识库
   - Confluence（开源替代）
   - Notion（开源替代）
   - Logseq - 大纲笔记
   - Obsidian（自托管方案）

2. **文档平台**
   - GitBook - 文档平台
   - MkDocs - Markdown 文档
   - Sphinx - 文档生成器
   - VitePress - Vue 文档生成器

3. **笔记应用**
   - Joplin - 笔记应用
   - Standard Notes - 加密笔记
   - Turtl - 安全笔记
   - AppFlowy - Notion 替代品

### 七、邮件服务（目标：10+ 个）

#### 待添加（10+ 个）
1. **邮件服务器**
   - Mailcow - 完整邮件解决方案
   - Mail-in-a-Box - 一键邮件服务器
   - iRedMail - 企业邮件系统
   - Poste.io - 邮件服务器

2. **邮件客户端**
   - Roundcube - Web 邮件客户端
   - Rainloop - Web 邮件客户端
   - SnappyMail - 快速邮件客户端

3. **邮件工具**
   - Mailtrain - 邮件营销
   - Listmonk - 邮件营销平台
   - Mailu - 邮件服务器套件

### 八、检索和搜索（目标：10+ 个）

#### 已实现（4个）
- Elasticsearch - 搜索引擎
- Meilisearch - 快速搜索
- Typesense - 容错搜索
- Solr（可添加）

#### 待添加（6+ 个）
1. **搜索引擎**
   - Apache Solr - 企业搜索
   - Sphinx Search - 全文搜索
   - Zinc - 轻量搜索

2. **站内搜索**
   - Algolia（开源替代）
   - Swiftype（开源替代）

### 九、员工通讯录和 HR（目标：10+ 个）

#### 待添加（10+ 个）
1. **通讯录**
   - Baikal - 联系人管理
   - CardDAV Server - 通讯录服务器
   - SOGo - 群件套件（含通讯录）

2. **HR 系统**
   - OrangeHRM - HR 管理系统
   - Odoo HR（已有 Odoo）
   - Sentrifugo - HRMS
   - TimeOff - 请假管理

3. **考勤系统**
   - Attendance - 考勤管理
   - TimeClock - 时间追踪

### 十、报单和审批系统（目标：10+ 个）

#### 待添加（10+ 个）
1. **审批流程**
   - Flowable - 工作流引擎
   - Camunda - BPM 平台
   - Activiti - 工作流引擎
   - ProcessMaker - 流程管理

2. **报单系统**
   - OTRS - 工单系统
   - Request Tracker - 工单系统
   - GLPI - IT 资产管理
   - iTop - IT 服务管理

### 十一、文件管理（目标：15+ 个）

#### 已实现（3个）
- Nextcloud - 文件同步
- Seafile - 文件同步
- MinIO - 对象存储

#### 待添加（12+ 个）
1. **文件管理器**
   - FileBrowser - 文件浏览器
   - TinyFileManager - 轻量文件管理
   - Filestash - 文件管理器
   - Kodexplorer - 可道云

2. **文件分享**
   - Pydio - 企业文件同步
   - ownCloud - 文件同步（Nextcloud 前身）
   - Filerun - 文件管理器

3. **存储服务**
   - SeaweedFS - 分布式文件系统
   - MinIO（已有）
   - S3Proxy - S3 代理

### 十二、相册和媒体（目标：20+ 个）

#### 已实现（8个）
- Jellyfin - 媒体服务器
- PhotoPrism - 照片管理
- Immich - 照片库
- Pixelfed - 照片分享
- Piwigo - 照片库
- Lychee - 照片管理
- Navidrome - 音乐服务器
- Airsonic - 音乐服务器

#### 待添加（12+ 个）
1. **相册**
   - LibrePhotos - 照片管理
   - Photoview - 照片查看器
   - Chevereto - 图片托管
   - Lychee（已有）

2. **媒体服务器**
   - Plex - 媒体服务器（需考虑授权）
   - Emby - 媒体服务器
   - Jellyfin（已有）

3. **音乐**
   - Funkwhale - 去中心化音乐
   - Ampache - Web 音频文件管理器
   - Subsonic - 音乐流媒体

### 十三、监控和运维（目标：15+ 个）

#### 已实现（5个）
- Grafana - 监控面板
- Prometheus - 监控系统
- Uptime Kuma - 网站监控
- Netdata - 实时监控
- Glances - 系统监控

#### 待添加（10+ 个）
1. **监控工具**
   - Zabbix - 企业监控
   - Nagios - 监控系统
   - Icinga - 监控系统
   - LibreNMS - 网络监控

2. **日志管理**
   - Loki（已有）
   - Graylog - 日志管理
   - ELK Stack - 日志分析
   - Seq - 结构化日志

3. **APM**
   - Jaeger - 分布式追踪
   - Zipkin - 分布式追踪
   - Pinpoint - APM 工具

### 十四、开发工具（目标：20+ 个）

#### 已实现（3个）
- GitLab - DevOps 平台
- Gitea - Git 服务
- Jenkins - CI/CD

#### 待添加（17+ 个）
1. **代码仓库**
   - Gitea（已有）
   - GitLab（已有）
   - Gogs - 轻量 Git 服务
   - Forgejo - Gitea 分支

2. **CI/CD**
   - Drone CI（已有）
   - Woodpecker CI（已有）
   - Concourse - CI/CD 平台
   - Tekton - CI/CD 框架

3. **代码质量**
   - SonarQube（已有）
   - CodeClimate - 代码质量
   - Snyk - 安全扫描

4. **API 管理**
   - Kong - API 网关
   - Tyk - API 网关
   - WSO2 API Manager
   - Hasura - GraphQL 引擎

5. **开发工具**
   - Theia - IDE 平台
   - Code Server - VS Code 服务器
   - Jupyter - 数据科学环境

### 十五、协作和沟通（目标：15+ 个）

#### 已实现（8个）
- Mattermost（可添加）
- Rocket.Chat（可添加）
- Element（可添加）
- Matrix（可添加）

#### 待添加（7+ 个）
1. **即时通讯**
   - Mattermost - Slack 替代品
   - Rocket.Chat - 团队聊天
   - Element - Matrix 客户端
   - Zulip - 主题式聊天

2. **视频会议**
   - Jitsi Meet - 视频会议
   - BigBlueButton - 在线教室
   - OpenVidu - WebRTC 平台

3. **协作工具**
   - Etherpad - 协作文档
   - CryptPad - 加密协作
   - OnlyOffice（已有）

### 十六、安全和身份认证（目标：10+ 个）

#### 待添加（10+ 个）
1. **身份认证**
   - Keycloak - 身份管理
   - Authelia - 认证服务器
   - Authentik - 身份提供者
   - Ory Kratos - 身份管理

2. **密码管理**
   - Vaultwarden - Bitwarden 服务器
   - Passbolt - 密码管理
   - Psono - 密码管理器

3. **VPN**
   - WireGuard - VPN 服务
   - OpenVPN - VPN 服务
   - Pritunl - VPN 管理

### 十七、数据库管理工具（目标：10+ 个）

#### 待添加（10+ 个）
1. **数据库管理**
   - phpMyAdmin - MySQL 管理
   - Adminer - 数据库管理
   - pgAdmin - PostgreSQL 管理
   - DBeaver（Web 版）

2. **数据库工具**
   - Metabase（已有）
   - Superset（已有）
   - Redash（已有）

### 十八、其他企业工具（目标：20+ 个）

1. **时间追踪**
   - Kimai - 时间追踪
   - Toggl Track - 时间追踪
   - Timeular - 时间追踪

2. **项目管理**
   - Taiga（已有）
   - Plane（已有）
   - Wekan（已有）
   - Focalboard - 看板工具

3. **客户服务**
   - Chatwoot（已有）
   - Zammad（已有）
   - osTicket（已有）

4. **财务和会计**
   - GnuCash - 财务管理
   - InvoicePlane - 发票管理
   - Akaunting - 会计软件

5. **库存管理**
   - Odoo（已有）
   - ERPNext（已有）
   - PartKeepr - 零件管理

## 实施计划

### 第一阶段：核心企业工具（30个）
- AI 工具（5个）
- PDF/OCR（5个）
- 图片处理（5个）
- 短链接/文件分享（5个）
- 表单工具（5个）
- 邮件服务（5个）

### 第二阶段：协作和知识管理（30个）
- 知识库扩展（10个）
- 文档管理（5个）
- 协作工具（5个）
- 文件管理（5个）
- 通讯录/HR（5个）

### 第三阶段：业务流程（30个）
- 审批系统（10个）
- 报单系统（5个）
- 项目管理扩展（5个）
- 时间追踪（5个）
- 财务工具（5个）

### 第四阶段：开发运维（30个）
- 开发工具扩展（10个）
- 监控工具扩展（10个）
- 安全工具（10个）

### 第五阶段：其他工具（60个）
- 各种实用工具补充

## 优先级排序

### 高优先级（企业刚需）
1. ✅ AI 工具（Ollama, Open WebUI）
2. ✅ PDF 处理（Stirling PDF）
3. ✅ OCR 服务
4. ✅ 短链接服务
5. ✅ 文件分享服务
6. ✅ 表单工具
7. ⏳ 邮件服务
8. ⏳ 知识库扩展
9. ⏳ 审批系统
10. ⏳ 员工通讯录

### 中优先级（常用工具）
1. ⏳ 图片处理扩展
2. ⏳ 文档管理
3. ⏳ 文件管理扩展
4. ⏳ 监控工具扩展
5. ⏳ 开发工具扩展

### 低优先级（专业工具）
1. ⏳ 财务工具
2. ⏳ 库存管理
3. ⏳ 专业开发工具

## 预期时间表

- **第一阶段：** 2-3 周（30个模板）
- **第二阶段：** 2-3 周（30个模板）
- **第三阶段：** 2-3 周（30个模板）
- **第四阶段：** 2-3 周（30个模板）
- **第五阶段：** 3-4 周（60个模板）

**总计：** 11-16 周完成 180+ 个新模板

## 质量标准

每个模板必须包含：
1. ✅ 完整的 `docker-compose.yml`
2. ✅ 详细的 `template.yaml` 元数据
3. ✅ 数据持久化配置
4. ✅ 健康检查配置
5. ✅ 自动凭证生成
6. ✅ 连接字符串配置
7. ✅ 版本选择支持
8. ✅ README.md 使用说明（可选但推荐）

## 成功指标

- ✅ 模板总数 ≥ 300
- ✅ 覆盖主要企业应用场景
- ✅ 所有模板可一键部署
- ✅ 文档完整清晰
- ✅ 用户反馈良好

