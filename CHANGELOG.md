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
