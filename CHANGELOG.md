## [1.3.5-rc1] - 2025-01-02

### Fixed
- 🔧 **证书下载功能**: 修复SSL管理页面证书下载功能，现在可以真正下载证书文件到本地
- 📁 **文件下载实现**: 前端使用临时a标签触发浏览器下载，支持cert、key、bundle三种文件类型
- 🛡️ **错误处理增强**: 后端添加文件存在性检查，文件不存在时返回404错误和友好提示
- 📋 **HTTP头优化**: 设置正确的Content-Type和Content-Disposition头，确保浏览器正确处理下载

### Technical
- 前端downloadCertificate函数实现真正的API调用
- 后端handleSSLDownload添加os.Stat文件存在检查
- 支持动态adminPrefix路径构建
- 改进用户反馈，下载成功时显示绿色状态提示

---

## [1.3.4] - 2025-01-02

### Added
- 🎨 **侧边栏Logo显示**: 在管理面板左侧添加Logo图片显示，支持模糊效果和hover交互
- 🌍 **完整语言切换功能**: 修复右上角语言切换器，支持实时切换中文、英文、日文等多语言
- 📊 **真实版本显示**: 系统状态中显示真实的SSLcat版本号，不再是硬编码版本
- 🔧 **API认证修复**: 修复前端API请求缺少adminPrefix导致的401认证错误

### Fixed
- 🔑 **认证状态同步**: 修复useLanguage hook架构问题，确保所有组件共享同一语言状态
- 🖼️ **Logo路径问题**: 修复Logo图片路径不包含adminPrefix导致的显示问题
- 📡 **API请求路径**: 修复Dashboard、Security、Notifications等页面API请求路径问题
- 🔤 **TypeScript类型**: 修复多语言翻译文件的TypeScript类型错误

### Enhanced
- 🎭 **Logo交互效果**: 默认模糊(blur 2px)，hover时清晰显示并轻微缩放
- 🌐 **多语言支持**: 完善西班牙语、法语、韩语、德语、俄语、繁体中文翻译
- 📱 **响应式设计**: Logo和语言切换功能适配不同屏幕尺寸
- 🔄 **状态管理**: 改进语言切换的Context架构和状态同步

### Technical
- 重构useLanguage hook，将状态管理移到LanguageProvider中
- 添加图片类型声明文件支持PNG等格式导入
- 优化API请求路径构建，确保包含正确的adminPrefix
- 改进Dashboard组件数据处理，支持多种后端字段格式

---

## [1.3.3] - 2025-01-03

### Added
- 🎯 **智能MIME类型检测**: 基于文件内容的高精度MIME类型识别，支持静态站点智能内容类型设置
- 📁 **静态站点增强**: 改进静态文件处理，支持更精确的MIME类型检测和内容类型设置
- 🔧 **MIME检测器**: 新增独立的MIME类型检测模块，提供更准确的文件类型识别

### Technical
- 实现基于文件内容的MIME类型检测算法
- 新增MIME检测器模块：`internal/cache/mime_detector.go`
- 增强静态文件处理器：`internal/web/static_handler.go`
- 改进静态站点MIME类型配置和自动检测

### Performance
- 静态文件MIME类型检测性能优化
- 智能内容类型设置，提升浏览器兼容性
- 减少不必要的MIME类型误判

### Documentation
- STATIC_SITE_MIME_GUIDE.md：静态站点MIME类型配置指南
- STATIC_SITE_ENHANCEMENT_SUMMARY.md：静态站点功能增强总结
- SMART_CONTENT_TYPE_GUIDE.md：智能内容类型检测指南

---

## [1.3.2] - 2025-09-28

### Added
- 🔄 **企业级负载均衡系统**: 支持6种算法(Round Robin, Weighted Round Robin, Least Connections, IP Hash, Random, Consistent Hash)
- 🏥 **完整健康检查机制**: HTTP健康检查、自动故障转移、恢复检测、会话保持(IP/Cookie/Header)
- 📦 **Brotli高效压缩**: 支持Brotli+Gzip智能压缩，压缩率达98.9%，显著提升传输效率
- 🔥 **配置热重载**: 零停机配置更新，支持文件监听和API管理，配置修改后自动生效
- 💾 **上游静态文件缓存**: 智能缓存上游静态资源，遵循Cache-Control策略，压缩存储节省60-90%空间
- 🎨 **完整前端UI支持**: 负载均衡、压缩、缓存等所有新功能均可通过Web界面配置
- 🛠️ **配置验证工具**: 命令行`--test`和`--check`参数，Web界面配置验证和重载

### Technical
- 实现高性能负载均衡器：纳秒级算法选择，支持权重、优先级、连接限制
- 集成Brotli压缩库：智能算法选择，压缩级别可配置，文件类型过滤
- 配置文件监听器：使用fsnotify实时监听，防抖处理，哈希验证
- 上游缓存系统：Cache-Control解析，TTL计算，压缩存储，自动清理
- 组件化重载架构：ReloadableComponent接口，原子性操作，错误隔离

### Performance
- 负载均衡性能：Round Robin ~508ns/op, Least Connections ~559ns/op
- 压缩性能：Gzip ~84μs/op (98.1%), Brotli ~220μs/op (98.9%)
- 缓存命中率：上游缓存通常达85%以上，响应时间降至毫秒级

### Frontend
- 新增LoadBalancerConfig组件：完整的负载均衡配置界面
- 新增CompressionConfig组件：压缩参数配置界面
- 新增UpstreamCacheConfig组件：缓存配置和统计界面
- 新增ConfigTest页面：配置验证和重载管理界面
- 更新ProxyAdd/ProxyEdit页面：支持负载均衡配置

### Documentation
- LOAD_BALANCER_GUIDE.md：负载均衡详细使用指南
- CONFIG_HOT_RELOAD_GUIDE.md：配置热重载使用指南
- UPSTREAM_CACHE_GUIDE.md：上游缓存使用指南
- NGINX_CADDY_COMPARISON.md：与nginx/caddy功能对比分析
- ENTERPRISE_FEATURES_SUMMARY.md：企业级功能总结

---

## [1.3.1] - 2025-09-27

### Added
- **配置导入diff界面增强**: 支持显示负载均衡、压缩、缓存配置的变更
- **前端路由优化**: 改进SPA路由处理和静态资源服务
- **WebSocket连接优化**: 增强WebSocket代理的缓冲和超时控制

### Technical
- 扩展ConfigDiff结构：支持CompressionChanges和CDNCacheChanges
- 优化代理规则比较：包含负载均衡、会话保持、健康检查等新字段
- 改进错误处理：更详细的错误信息和日志记录

---

## [1.3.0] - 2025-09-26

### Added
- **基础负载均衡框架**: 实现负载均衡器接口和基础算法
- **压缩模块重构**: 统一的压缩接口，支持多种算法
- **配置结构扩展**: 为负载均衡和压缩功能扩展配置结构

### Technical
- 创建loadbalancer包：定义Backend、LoadBalancerConfig等核心类型
- 创建compression包：统一的压缩器接口和中间件
- 扩展ProxyRule：添加负载均衡、健康检查、会话保持等配置字段
- 扩展Config：添加CompressionConfig配置结构

### Infrastructure
- 建立企业级功能的基础架构
- 为后续功能实现奠定基础
- 保持向后兼容性

---

## [1.2.2] - 2025-09-17

### Fixed
- **阿里云OSS代理问题**: 修复访问阿里云OSS时返回403 AccessDenied错误
- **Host信息泄露**: 解决HostId显示为`local.de:9933`的问题
- **Host头部格式**: 对云服务自动移除标准端口号（80/443）
- **代理头部清理**: 对云服务完全避免设置可能触发防盗链的代理头部

### Technical
- 智能Host头部处理：同步设置`req.Host`和`Header['Host']`
- 调整Director函数调用顺序，防止Host设置被覆盖
- 增强云服务检测：支持阿里云、AWS、腾讯云等
- 实现两阶段头部清理机制：预清理 + Director清理
- 添加详细的Host字段追踪日志

### Compatibility
- 扩展云服务支持：阿里云OSS、AWS S3、腾讯云COS
- 保持向后兼容：普通代理功能不受影响
- 现有配置文件无需修改

---

## [1.2.1] - 2025-09-16

### Added
- **智能重试机制**: SSL证书申请失败时自动重试，HTTP-01失败自动切换到DNS-01验证
- **域名解析预检查**: 申请前检查域名是否解析到当前服务器，提前预警验证失败
- **重试状态跟踪**: 详细的重试过程日志和用户反馈，支持手动触发重试
- **API重试端点**: 新增`/api/ssl/retry`和`/api/ssl/retry-config`端点

### Technical
- 实现智能重试策略：HTTP-01验证3次重试，DNS-01验证2次重试
- 递增等待时间机制：10s, 20s, 30s (HTTP) / 15s, 30s (DNS)
- 域名解析状态检查和服务器IP匹配验证
- 增强的错误处理和日志记录系统
- 支持批量域名申请的重试机制

---

## [1.2.0] - 2025-09-16

### Added
- **DNS验证SSL证书申请**: 支持Cloudflare、阿里云、腾讯云、GoDaddy、自定义API等DNS服务商
- **代理访问控制**: 为代理规则添加用户名/密码验证，支持多用户和会话管理
- **通配符证书支持**: 通过DNS验证支持`*.example.com`类型的通配符证书申请
- **DNS服务商管理**: 完整的DNS服务商配置、编辑、删除和状态监控界面
- **代理认证界面**: 美观的登录页面和用户管理界面

### Technical
- 实现完整的DNS-01挑战验证机制
- 支持多种DNS服务商API集成（HMAC-SHA1、Bearer Token等认证方式）
- 添加代理认证中间件和会话管理
- 统一的DNS Provider接口设计
- 自动DNS记录传播监控和清理

---

## [1.1.3] - 2025-09-14

### Added
- **完整 CRUD API**：新增代理规则、SSL证书、系统设置、静态/PHP站点的完整 API 支持
- **第三方客户端支持**：标准化 RESTful API，支持外部客户端完整管理 SSLcat
- **API 端点扩展**：12+ 新增 API 端点，涵盖所有核心功能的增删改查
- **多语言国际化**：为安全、CDN、TOTP 页面新增 35+ 翻译键
- **API 标准化**：统一响应格式、错误处理和认证机制

### API Endpoints
- `POST /api/proxy-rules/manage` - 添加/更新代理规则
- `DELETE /api/proxy-rules/delete` - 删除代理规则  
- `POST /api/ssl/generate` - 申请 SSL 证书
- `POST /api/ssl/upload` - 上传 SSL 证书
- `DELETE /api/ssl/delete` - 删除 SSL 证书
- `GET /api/settings` - 获取系统设置
- `PUT /api/settings/update` - 更新系统设置
- `POST /api/security/unblock` - 解除 IP 封禁
- `GET|POST /api/static-sites` - 静态站点管理
- `GET|POST /api/php-sites` - PHP 站点管理

### Internationalization
- 安全防护页面多语言支持（验证码、PoW、DDoS 设置）
- CDN 缓存页面多语言支持（统计、配置）
- TOTP 二次验证页面多语言支持（设置、扫码）

---

## [1.1.2] - 2025-09-13

### Added
- **无第三方人机验证**：客户端 PoW + 蜜罐 + 最小填写时长，与图形验证码并用
- **安全配置化**：人机验证参数可配置（`enable_captcha`、`enable_pow`、`pow_bits`、`min_form_ms`）
- **TLS 指纹持久化**：TLS ClientHello 指纹记录到 `./data/tls_fp.log`（JSONL + 轮转）
- **DDoS 攻击日志**：攻击记录持久化到 `./data/ddos_attacks.log`（JSONL + 轮转）
- **DDoS 防护中间件**：接入请求链路，支持多级别防护（off/low/medium/high/extreme）
- **Prometheus 指标**：`/metrics` 端点暴露系统、安全、CDN、DDoS 等关键指标
- **CDN 缓存统计**：命中率、容量利用率、对象数等实时统计与可视化
- **MFA (TOTP)**：管理后台可选启用双因素认证，支持 Google Authenticator
- **安全设置页面**：统一的人机验证、DDoS 防护、TLS 指纹、攻击记录管理界面
- **密码安全增强**：bcrypt 哈希存储，明文自动迁移，常量时间比较

### Changed
- **图形验证码优化**：移除混淆字符（I、L、8、!），提升可读性
- **智能验证策略**：TOTP 启用时自动禁用 PoW 和验证码，避免用户负担过重
- **蜜罐检测优化**：空值不算填写，提高容错性
- **DDoS 阈值调整**：Medium 级别放宽到 3000次/分钟，避免正常用户误拦
- **PoW 难度优化**：默认从 18 位降至 16 位，提升用户体验（50-150ms）

### Security
- **TOTP 密钥安全**：存储到独立文件（0600），不保存到配置 JSON
- **配置热加载**：支持 fsnotify 监听，配置变更实时生效
- **日志轮转**：防止日志文件无限增长（10MB×10 文件）

### APIs
- **扩展 API**：`/api/tls-fingerprints?limit=N`（含 last_seen）
- **新增 API**：`/api/security/attacks?limit=N`（DDoS 攻击记录）
- **监控 API**：`/metrics`（Prometheus 格式）
- **统计 API**：`/api/cdn-cache/stats`（增强统计）

### UI/UX
- **安全设置页**：人机验证开关、DDoS 防护配置、实时攻击展示
- **CDN 缓存页**：命中率、利用率等统计卡片
- **TOTP 设置页**：二维码生成、验证码绑定、状态管理
- **登录体验**：根据安全级别智能调整验证要求

### Docs
- 新增《无第三方人机验证技术实现.md》技术文档

## [1.1.0] - 2025-09-08

### Added
- Static Sites and PHP Sites management support
- Configurable server timeouts: `read_timeout_sec`, `write_timeout_sec`, `idle_timeout_sec`
- Configurable `max_upload_bytes` (default 1 GiB) for uploads
- Language selector and official site link added to Dashboard/Static Sites/PHP Sites sidebars

### Changed
- Single certificate and ZIP bulk uploads now stream to disk with total-size limits to avoid memory usage
- Unified sidebar order across pages; fixed missing icons on dynamic pages
- Temporarily disabled login captcha (kept implementation for future re-enable)

### Docs
- Updated multilingual READMEs to v1.1.0
- Updated roadmap to v1.1.0 status

## [1.0.21] - 2025-09-07

### Fixed
- 登录页验证码脚本注入使用 template.JS，修复 `loadCaptchaQuestion is not defined` 报错

### Improved
- 代理上游连接复用与 HTTP/2 强制尝试已在文档中强调，提示实际性能收益场景

## [1.0.20] - 2025-09-07

### Added
- Admin 面板显示公网 IPv4（来自 ip4.dev/myip）以便用户自行解析域名
- IP 访问到 AdminPrefix 时，若存在有效 LE 证书且域名解析到本机公网 IP，则强制跳转至 https://{domain}{AdminPrefix}
- 每 30 秒自动校验可用域名与 DNS 指向，实时更新跳转策略
- 代理规则管理页新增 enabled 与 ssl_only 开关（ssl_only 将 HTTP 自动 301 到 HTTPS）

### Changed
- 404/502 未命中代理响应改为简洁纯文本
- 安装脚本下载地址切换至新命名：
  - GitHub: https://github.com/xurenlu/sslcat/releases/download/v${VER}/sslcat_v${VER}_${OS}-${ARCH}${EXT}
  - 中国大陆镜像: https://sslcat.com/xurenlu/sslcat/releases/download/v${VER}/sslcat_v${VER}_${OS}-${ARCH}${EXT}
  （失败自动切换主/备）
- 代理转发参数修正：若 Target 已含协议则直接使用，避免重复协议造成崩溃

### Fixed
- 修复未启用规则也被展示为“活跃”的状态显示问题
- 修复 302 未命中行为必须填写重定向 URL 的校验

## [1.0.15] - 2025-01-03
- Switch all logs to English across core modules
- Add runtime ACME temporary allowlist for panel-initiated requests
- Add ACME cache sync to certs/keys with admin UI button
- Fix i18n translator mkdir on empty dir and embedded loading
- Use net.JoinHostPort for IPv6-safe dialing/URLs

## [1.0.13] - 2025-01-03

### 🌐 集群架构重大升级
- **Master-Slave集群架构**: 支持多节点部署，实现高可用性
- **三种运行模式**: Standalone（独立）、Master（主控）、Slave（从属）
- **自动配置同步**: Master配置变更实时推送到所有Slave节点
- **SSL证书共享**: 集群内自动分发和同步SSL证书
- **权限分离控制**: Slave模式下严格限制可修改功能
- **集群管理界面**: 完整的节点状态监控和管理功能

### 🔧 技术实现
- **ClusterManager**: 核心集群管理组件
- **同步机制**: 基于HTTP的配置和证书同步
- **认证安全**: 共享密钥认证，保障集群通信安全
- **权限中间件**: 动态控制Slave模式下的功能访问
- **故障恢复**: 自动重连和断线恢复机制

### 🚀 使用场景
- **多机房部署**: 主从节点分布在不同机房，提供容灾能力
- **负载均衡**: 多个节点承担服务负载，提升性能
- **配置统一管理**: Master统一管理配置，避免配置不一致
- **运维成本降低**: 集中管理，减少重复配置工作

### 📋 功能限制
- **Slave模式限制**: 仅可修改密码、面板路径、解除Slave模式
- **配置排除**: 敏感配置（密码、面板路径）不参与同步
- **网络要求**: 需要稳定的内网连接支持集群通信

## [1.0.12] - 2025-01-03

### 🔐 安全功能重大升级
- **智能验证码系统**: 实现JS动态填充的编码数学验证码
- **条件安全触发**: 仅在有真实SSL证书时启用高级验证
- **编码防护机制**: 字符偏移+Base64编码，防止源代码泄露题目
- **行为安全分析**: 一次性使用、10分钟超时、自动清理机制

### 🚀 功能增强
- **SSL证书智能检测**: 自动区分自签名和CA签发证书
- **多语言验证码**: 支持中英文错误提示和界面
- **API安全接口**: 新增验证码生成和验证API
- **用户体验优化**: 验证码刷新、智能加载、错误处理

### 📋 规划文档
- **未来功能路线图**: 详细的2025年四季度发展规划
- **技术实现方案**: SSL重定向和真人验证完整技术方案
- **测试指导文档**: 完整的验证码功能测试指南

## [1.0.11] - 2025-01-03

### 🎉 重大更新
- **完整多语言支持**: 所有 README 文件完整翻译为英语、日语、西班牙语、法语、俄语版本
- **用户体验优化**: 改进初始访问流程和安全设置
- **文档结构优化**: 统一版本管理和文档结构

### 🔒 安全增强
- **强制管理面板路径设置**: 首次登录必须自定义管理面板访问路径
- **初始访问安全指导**: 明确区分 IP/HTTP 和域名/HTTPS 访问方式
- **密码管理优化**: 改进密码存储和恢复机制

### 📚 文档改进
- **新增**: 《版本1.0.11完整功能简要说明.md》
- **移除**: 过时的自动安装和嵌入式部署部分
- **优化**: 所有语言版本的 README 结构和内容一致性
- **改进**: 安装部署说明和故障排除指南

### 🔧 技术改进
- **版本号统一**: 所有文件中的版本号更新为 1.0.11
- **构建优化**: 简化发布流程和版本管理
- **代码清理**: 移除未使用的部署脚本和配置

### 🌐 国际化支持
- **英语**: 完整的英语文档和界面支持
- **日语**: 日本用户友好的文档和界面
- **西班牙语**: 西班牙语地区用户支持
- **法语**: 法语地区用户支持
- **俄语**: 俄语地区用户支持

### 🛠️ 兼容性改进
- **向下兼容**: 保持与旧版本的配置兼容性
- **平滑升级**: 支持从旧版本无缝升级
- **配置迁移**: 自动处理配置文件格式变更

## [1.0.10] - 2025-09-06
- 新增：系统设置支持 ACME 邮箱与“禁用自签名回退”开关
- 默认：安装即禁用自签名回退，缺证书时不再自签
- 向导：首次登录要求填写合法邮箱并自动启用 ACME
- 证书：续期在禁用自签时不再生成自签，优先尝试 ACME

## [1.0.8] - 2025-09-05
- 证书管理新增“类型”列，显示自签/CA签发
- ACME 严格化：仅对已配置域名申请，保存规则时预取证书
- i18n 修复：URL>Cookie>Accept-Language；加载嵌入翻译；降噪日志

# Changelog

All notable changes to this project will be documented in this file.

## [1.0.4] - 2025-09-05
### Changed
- Upgrade QUIC dependency to quic-go and stabilize build
- Update install snippets to v1.0.4

## [1.0.1] - 2025-09-05
### Added
- 配置导出/导入流程：支持上传或粘贴 JSON，预览差异（分区表格与规则变更），确认后应用并持久化到配置文件
- 证书上传/下载：支持 .crt/.pem 与 .key/.pem，上传后自动加载缓存；提供下载证书/私钥/bundle
- 系统设置页入口：新增“导出配置 / 导入配置(预览diff) / 查看上次导入的diff”按钮
- 发布脚本与文档：scripts/release/* 与 RELEASE.md，支持多架构构建与发布

## [1.0.3] - 2025-09-05
### Added
- HTTP/3 (QUIC) support alongside HTTPS (ALPN h3, fallback to h2/h1)
- Sidebar link to official site (sslcat.com)
- Docs and paths unified to sslcat branding

## [1.0.2] - 2025-09-05
### Added
- 维护者发布指南 `MAINTAINER_RELEASE_GUIDE.md`
- 安装包脚本：DEB（package-deb.sh）、RPM（package-rpm.sh）、Homebrew（package-brew.sh）
- Docker Compose 一键起 `docker-compose.yml`
- 证书到期提醒（15/7/3天），可经由环境变量启用的 notifier 推送

### Changed
- 安全设置页增加“审计日志”分区与导出JSON
- RELEASE.md 新增安装包与升级助手用法

### Changed
- 导出配置接口改为附件下载（Content-Disposition: attachment）
- 保存配置错误信息包含具体路径（目录/文件）
- 持久化：证书列表从磁盘扫描，重启后仍可见

### Fixed
- 应用导入配置时遗失 ConfigFile 路径导致保存失败的问题

## [1.0.0] - 2025-09-05
- 初始发布：基础管理面板、反向代理、SSL 管理、自签名证书、多语言、模板渲染与基本监控等
