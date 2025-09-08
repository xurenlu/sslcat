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
