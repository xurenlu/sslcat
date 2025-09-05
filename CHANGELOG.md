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
