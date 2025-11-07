---
title: 动态域名 / 内网穿透服务概览
description: SSLcat 计划支持的隧道服务、依赖与配置能力对比
date: 2025-11-07
---

# 动态域名 / 内网穿透服务概览

以下总结了 Cloudflare Tunnel、ngrok、frp 与花生壳四类常见的公网穿透方案，便于后续在 SSLcat 中抽象统一的管控模型。

## 能力对比

| 服务 | 定位 | 主要优势 | 常见限制 |
| --- | --- | --- | --- |
| Cloudflare Tunnel | 零信任接入、反向代理 | 全球 CDN、内置 TLS、DDoS 防护、支持多隧道 | 需绑定 Cloudflare 域名账号；免费版连接数有限 |
| ngrok | SaaS 反向代理 | 快速试用、HTTP/TCP 支持、开箱监控 API | 免费带宽有限、域名复用、长期连接需付费 |
| frp | 自建内网穿透 | 开源易定制、性能优、协议丰富 | 需自建 frps、权限控制自担、缺乏托管监控 |
| 花生壳 | 商业 DDNS/穿透 | 国内节点多、备案域名/二级域名、桌面/终端丰富 | CLI 资料较少、免费版带宽/端口受限、依赖厂商账号 |

## CLI 依赖与部署要求

| 服务 | 依赖二进制 | 安装方式 | 运行备注 |
| --- | --- | --- | --- |
| Cloudflare Tunnel | `cloudflared` | 官方包 / Homebrew / Docker | 生成 `cert.pem` 与 `~/.cloudflared/` 配置，需 CF 账号授权 |
| ngrok | `ngrok` | 下载官方压缩包或 `brew install ngrok/ngrok` | 需 `ngrok config add-authtoken` 写入本地配置，支持 `ngrok api` 查询状态 |
| frp | `frpc` | 官方发布包 / 构建 | 需配合 `frps` 服务；配置文件支持 INI/TOML，多路代理共享同实例 |
| 花生壳 | `phddns` / `phtunnel` CLI | 厂商提供安装包 | 需绑定 Oray 账号；配置包含 `authcode`、`device_id` 等字段 |

## 通用抽象建议

- **认证凭据**：统一存储为类型化结构（token、证书、用户名密码），持久化时加密或不可逆脱敏。
- **服务实例**：每个 Provider 支持多个隧道（Cloudflare Tunnel 多 tunnel、ngrok 多 session、frp 多 proxy、花生壳多映射），需要 ID、名称与本地端口/域名。
- **运行控制**：对 CLI 采用守护进程管理（systemctl 替代或本地 supervisor），提供启动、停止、重启 API；实时状态可读取本地 socket/API 或解析日志。
- **健康检查**：定义统一的状态枚举（`disconnected`、`connecting`、`connected`、`error`），并支持最近一次错误说明。
- **安全注意事项**：
  - 限制日志输出中的敏感 token；
  - 提示用户在独立系统账号下运行 CLI（除本项目需 root 的特权端口外，尽可能降权执行）；
  - 针对自建 frp 的服务端地址、花生壳的设备授权需二次校验。

## 对接要点

### Cloudflare Tunnel
- 必备：Cloudflare 账号与域名、`cloudflared` 二进制。
- 配置：`cloudflared tunnel create <name>` 生成 `credentials.json`；`cloudflared tunnel route dns <name> mydomain.com` 指定外部域名；本地服务通过 `cloudflared tunnel --config config.yml run <name>` 运行。
- 管理接口：`cloudflared tunnel list/info/delete`，以及 Cloudflare API V4（需 API Token）。
- 状态获取：`cloudflared tunnel info --output json` 或本地 `metrics` 端口（默认 127.0.0.1:MetricsPort）。

### ngrok
- 必备：ngrok 账号、`ngrok` 二进制、Auth Token。
- 配置：`ngrok config add-authtoken <token>` 写入 `~/.config/ngrok/ngrok.yml`；运行 `ngrok http 8080 --domain=<custom>` 或 `ngrok tunnel` 配置文件模式。
- 管理接口：`ngrok api` 子命令以及本地 `http://127.0.0.1:4040/api/` REST 接口。
- 状态获取：本地 API `/api/tunnels`、`/api/requests`，或 `ngrok api tunnels list`。

### frp (frpc)
- 必备：访问 frps（服务器地址、端口、鉴权 token/oidc）。
- 配置：`frpc.ini` 中定义 `[common] server_addr`、`server_port`、`token`；每个隧道使用 `[web] type = http local_port = 80 custom_domains = ...`。
- 管理接口：`frpc reload` 支持热更新；0.52+ 支持 `frpc admin_addr` 暴露 HTTP API（JSON）。
- 状态获取：启用 `admin_addr` 后可 GET `/api/config`、`/api/status`；或解析日志输出。

### 花生壳（Oray PeanutHull）
- 必备：Oray 账号、授权码（或子账号 API key）、厂商 CLI（`phddns` 或 `phtunnel`）。
- 配置：通常使用 `phddns config set --authcode=...`、`phddns config set --lan=127.0.0.1:8080`、`phddns run`；部分版本提供 `~/.oray/phddns.conf`。
- 管理接口：官方提供 Web API（需要企业版），CLI 多通过命令输出状态（`phddns status --json`）。
- 状态获取：CLI 的 JSON 输出或轮询日志；必要时辅以抓取 Web 面板 API。

## 后续扩展方向
- Tailscale Funnel/Serve（基于 WireGuard）、ZeroTier Moon、Teleport Application Access 等。
- 与现有 DNS 模块联动，自动创建 CNAME / A 记录。
- 纳入速率/流量统计，结合监控模块输出。

