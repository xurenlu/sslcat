# Product Overview

> 最后更新：2026-11-20 | 当前版本：v2.5.0-rc2

## 项目简介

SSLcat 是一个集成反向代理、SSL 证书管理、安全防护和运维管理后台的 Go 服务。

## 核心功能

- HTTP/HTTPS 反向代理与站点管理
- 保留生产已有的静态站点 Basic Auth，并在管理 API 与 CLI 输出中隐藏密码哈希
- 自动申请、续期和管理 TLS 证书
- TLS 优先选择当前有效的精确 SAN 证书，泛域名证书作为后续候选
- 泛域名后台续期使用 DNS-01，签发失败保留原证书与覆盖范围
- WAF、限流、DDoS 防护和威胁情报 IOC 检测
- 管理后台、CLI、MCP 运维接口及运行状态观测
- root / sudo 专用的交互式管理员密码重置命令 `sslcat reset-password`
- 未识别 CLI 子命令会立即报错退出，不会误启动服务
- WebAuthn 支持显式配置公网 RP ID / Origin，避免监听地址与实际域名不一致
- WebAuthn 在域名不匹配时会直接提示凭证绑定的完整访问地址
- 管理前缀下的 Logo 由后端直接嵌入提供，不依赖未跟踪的前端哈希图片
- 有界威胁情报持久化队列，防止批量 IOC 导入耗尽 goroutine
- pprof 使用独立 loopback 监听器，默认 `127.0.0.1:6060`，不进入业务端口路由
- 上游连接池具备单主机总连接上限，慢上游不会无限扩张拨号 goroutine
- 异步轮转日志使用有界队列并在停机时可靠排空

## 技术栈

- 后端：Go 1.25、SQLite、net/http
- 前端：React、TypeScript、Vite
- 部署：systemd

## 部署

- 构建：`go build -o sslcat .`
- 运行：`./sslcat --config /etc/sslcat/sslcat.conf`
- 服务：`systemctl restart sslcat`
- 发布仓库：`niuwoai/sslcat`；国内镜像使用 `https://img.niuwoai.com`，版本对象路径保持 `xurenlu/sslcat/releases/<tag>/`，最新目录为 `latest/`。
- 当前预编译发布平台：Linux AMD64、macOS Intel 和 macOS Apple Silicon；Linux ARM64 构建暂未启用。

## 已知问题 / 待办

- 本次修复不扩展多 SAN 证书签发器；后台遇到多个 SAN 时明确报错并保留原证书，避免续期后丢失域名覆盖。此类证书仍需由支持完整 SAN 集合的现有外部流程管理。
- Tor Exit Nodes 外部源在部分网络环境不可达，默认停用；需要时由管理员手动启用并确认出口网络可达性。
- AI 流式上游若超过 10 秒仍未返回响应头会触发快速失败；可按单条代理规则调整 `response_header_timeout_sec`，不影响响应头到达后的长时间流式传输。
