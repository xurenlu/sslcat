# HTTP/3 (QUIC) 故障排除

## 现象：Alt-Svc 有返回，但 QUIC 连接无法建立

使用 [http3check.net](https://http3check.net/) 等工具检测时，可能出现：

- **响应头**中有 `Alt-Svc: h3=":443"; ma=86400`（说明 SSLcat 已启用 HTTP/3 并对外宣告）
- **检测结果**显示：`QUIC connection could not be established`（QUIC 连接无法建立）

说明客户端能通过 TCP 443 访问到 SSLcat（HTTPS 正常），但通过 **UDP 443** 建立 QUIC 连接时失败。

## 常见原因与处理

### 1. 前置反向代理/负载均衡未转发 UDP 443（最常见）

**原因**：SSLcat 前有 Nginx、HAProxy、云厂商负载均衡、CDN 等时，通常只配置了 **TCP 443** 转发，**UDP 443** 未转发到 SSLcat。QUIC 使用 UDP 443，若 UDP 未转发，外网无法与 SSLcat 的 HTTP/3 服务建立连接。

**处理**：

- **方案 A（推荐）**：在前置代理/负载均衡上开启 **UDP 443** 转发到 SSLcat 所在机器的 443 端口，并放行防火墙 UDP 443。
- **方案 B**：若前置代理支持 HTTP/3（如 Nginx 1.25+、Cloudflare），可在代理层终结 HTTP/3，由代理用 HTTP/2 或 HTTP/1.1 回源到 SSLcat；此时 SSLcat 上的 HTTP/3 可关闭，避免重复宣告。
- **方案 C**：暂时关闭 SSLcat 的 HTTP/3（系统设置 → SSL 设置 → 取消「启用 HTTP/3」），这样不会下发 `Alt-Svc`，客户端不会尝试 QUIC，仅用 HTTP/2/1.1。

### 2. 防火墙或安全组未放行 UDP 443

**原因**：机器或云安全组只放行了 TCP 443，未放行 UDP 443。

**处理**：在防火墙/安全组中为 **UDP 443** 添加入站规则，允许客户端访问 SSLcat 所在主机。

### 3. Docker/Kubernetes 未暴露 UDP 443

**原因**：容器或 K8s Service 只映射了 TCP 443，未映射 UDP 443。

**处理**：

- **Docker**：`-p 443:443` 会同时映射 TCP 和 UDP；若只映射了 TCP，需改为同时暴露 UDP，例如 `-p 443:443 -p 443:443/udp` 或确认端口映射包含 UDP。
- **Kubernetes**：Service 的 `ports` 中需包含 `protocol: UDP` 的 443 端口，且 Pod 所在节点/网络允许 UDP 443 入站。

### 4. 本机 UDP 443 被占用或权限不足

**原因**：另一进程已绑定 UDP 443，或当前进程无权限绑定 443。

**处理**：在 SSLcat 所在机器上检查 UDP 443 占用（如 `ss -ulnp | grep 443` 或 `lsof -i UDP:443`），关闭占用进程或改用其他端口（若改端口，需同步修改 Alt-Svc 或前置代理配置）；若为权限问题，需以有权限绑定 443 的用户运行 SSLcat 或使用 capability（如 `setcap`）。

### 5. HTTP/3 服务启动失败但配置仍为启用

**原因**：配置中启用了 HTTP/3，但 HTTP/3 服务因端口占用、TLS 配置等问题启动失败；此时 Alt-Svc 仍可能被添加（仅依据配置），导致客户端尝试 QUIC 却连不上。

**处理**：查看 SSLcat 日志中是否有 `HTTP/3 server error` 或 `Failed to start HTTP/3 server`，若有则按报错处理（释放端口、修正 TLS 等）；若暂时无法修复，可先关闭 HTTP/3 开关，避免误导客户端。

### 6. 客户端侧使用翻墙/代理软件（VPN、Clash、V2Ray 等）

**原因**：检测是从**你的电脑**发起的，若本机或网关走了翻墙/代理（如 Clash、V2Ray、Shadowsocks、各类 VPN），很多这类软件对 **UDP** 或 **QUIC** 支持不完整：只转发 TCP、不转发 UDP 443，或直接不支持 HTTP/3。结果是：HTTPS（TCP 443）经代理正常到达 SSLcat，所以你能看到 Alt-Svc；但 QUIC（UDP 443）被代理丢弃或未正确转发，http3check 就会报「QUIC 连接无法建立」。**此时问题在客户端路径，不在 SSLcat 服务端。**

**处理**：

- **验证服务端**：用**未走代理**的环境测一次（例如同一局域网内另一台设备、或服务器本机 `curl -sI --http3 https://你的域名`），若未走代理时 QUIC 能通，即可确认是客户端代理导致。
- **接受现状**：在不支持 QUIC 的代理下，浏览器会自动降级到 HTTP/2/1.1，正常访问不受影响；只是 http3check 从你当前网络会一直报 QUIC 失败。
- **可选**：若希望从当前网络也测通 QUIC，可换用支持 UDP 转发/HTTP/3 的代理或模式，或临时关闭代理再测。

## 快速检查清单

| 检查项 | 说明 |
|--------|------|
| 前置是否有代理/LB | 若有，是否转发 **UDP 443** 到 SSLcat？ |
| 客户端是否走翻墙/代理 | 若检测端走 VPN/Clash/V2Ray 等，其可能不转发 UDP 443，导致 QUIC 失败 |
| 防火墙/安全组 | 是否放行 **UDP 443** 入站？ |
| 容器/编排 | 是否暴露 **UDP 443**？ |
| 本机端口 | UDP 443 是否被占用？SSLcat 是否有权限绑定？ |
| 日志 | 是否有 HTTP/3 启动或运行错误？ |

## 测试 HTTP/3 的常用工具（类 curl）

在**未走代理**的环境下，可用以下命令行工具验证服务端 QUIC 是否可达：

| 工具 | 用法 | 说明 |
|------|------|------|
| **curl** | `curl -sI --http3 https://你的域名` | 需 curl 7.66+ 且编译时启用 HTTP/3（ngtcp2 或 quiche）。`--http3-only` 禁止回退到 HTTP/2/1.1。 |
| **xh** | `xh -h3 https://你的域名` 或 `xh --http-version=3 https://你的域名` | 类 HTTPie 的现代 CLI，支持 HTTP/3（基于 rustls）。安装：`cargo install xh` 或各系统包管理器。 |
| **h2load**（nghttp2） | `h2load -n1 -c1 --npn-list=h3 https://你的域名` | 压测/基准用，可指定 ALPN 为 h3。需 nghttp2 编译时启用 HTTP/3。 |

- **curl**：多数系统自带的 curl 未带 HTTP/3，需按下面「如何安装带 HTTP/3 的 curl」获取；详见 [curl HTTP/3 文档](https://curl.se/docs/http3.html)。
- **xh**：Rust 编写，默认可能走系统/rustls 的 HTTP/3，适合快速手测。
- 若上述工具在未走代理时能连上，说明服务端 HTTP/3 正常；若只有走代理时失败，则多为客户端代理不支持 QUIC。

## 如何安装带 HTTP/3 的 curl

| 平台 | 方式 | 说明 |
|------|------|------|
| **Windows** | [curl.se/windows](https://curl.se/windows/) 下载官方 zip | 官方预编译已含 ngtcp2、nghttp3，支持 `--http3`。解压后把 `curl.exe` 所在目录加入 PATH。 |
| **macOS** | `brew install curl` | 当前 Homebrew 的 curl 已依赖 libngtcp2，一般自带 HTTP/3。安装后用 `brew --prefix curl` 的 bin 优先于系统 curl（或 `export PATH="$(brew --prefix curl)/bin:$PATH"`）。若没有，可试 `brew tap cloudflare/homebrew-cloudflare` 后 `brew install cloudflare/cloudflare/curl`。 |
| **Linux** | 预编译 / 自编译 | **预编译**：如 [stunnel/static-curl](https://github.com/stunnel/static-curl/releases) 等第三方静态包（看说明是否带 HTTP/3）；或 `conda install -c conda-forge curl`。**自编译**：按 [curl 官方 HTTP/3 构建说明](https://curl.se/docs/http3.html)（OpenSSL 3.5+ 或 quictls + nghttp3 + ngtcp2）在本地编译。 |

**验证**：安装后执行 `curl -V`，输出里应出现 **ngtcp2**、**nghttp3** 或 **HTTP3**；再执行 `curl -sI --http3 https://你的域名` 测试。

## 参考

- [HTTP/3 可行性分析](./http3-feasibility-analysis.md)
- [RFC 9114 HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
