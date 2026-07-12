# Product Overview

> 最后更新：2026-07-12 | 当前版本：v2.4.0-rc4

## 项目简介

SSLcat 是一个集成反向代理、SSL 证书管理、安全防护和运维管理后台的 Go 服务。

## 核心功能

- HTTP/HTTPS 反向代理与站点管理
- 自动申请、续期和管理 TLS 证书
- WAF、限流、DDoS 防护和威胁情报 IOC 检测
- 管理后台、CLI、MCP 运维接口及运行状态观测
- root / sudo 专用的交互式管理员密码重置命令 `sslcat reset-password`
- 未识别 CLI 子命令会立即报错退出，不会误启动服务
- WebAuthn 支持显式配置公网 RP ID / Origin，避免监听地址与实际域名不一致
- WebAuthn 在域名不匹配时会直接提示凭证绑定的完整访问地址
- 管理前缀下的 Logo 由后端直接嵌入提供，不依赖未跟踪的前端哈希图片
- 有界威胁情报持久化队列，防止批量 IOC 导入耗尽 goroutine

## 技术栈

- 后端：Go 1.25、SQLite、net/http
- 前端：React、TypeScript、Vite
- 部署：systemd

## 部署

- 构建：`go build -o sslcat .`
- 运行：`./sslcat --config /etc/sslcat/sslcat.conf`
- 服务：`systemctl restart sslcat`

## 已知问题 / 待办

- Tor Exit Nodes 外部源在部分网络环境不可达，默认停用；需要时由管理员手动启用并确认出口网络可达性。
