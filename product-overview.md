# SSLcat Product Overview

## 当前定位

SSLcat 是一个集成 SSL 证书管理、反向代理、WAF、安全审计、站点托管和 Git 部署能力的自托管网关管理工具。2.0.x rc 主线侧重稳定性，2.1.x 起新增 **MCP 内置接入**，让 AI 客户端可以直接担任运维助理；2.2.x 起补强 CLI 运维工具箱，让无 Web/无 AI 客户端的服务器现场也能完成基础诊断和站点管理。

## 主要功能

- 自动签发、续期和热加载 SSL/TLS 证书。
- 域名反向代理、静态站点、PHP 站点、模板化应用部署和分层 Runner 部署。
- 管理面板、多用户、会话、审计日志和配置版本管理。
- WAF、DDoS、防爆破、IP/UA/TLS 指纹封禁和白名单管理。
- 运行监控、慢请求分析、缓存、压缩和图片优化。
- **MCP（Model Context Protocol）内置服务**：sslcat 自身即是 MCP server，可被 Claude / Cursor / Cherry Studio 等 AI 客户端直接调用，AI 通过 tool 调用即可完成站点、证书、转发的查询与管理。默认关闭；启用时需通过 `sslcat mcp token create` 颁发独立 token，支持 scope、IP 白名单、速率限制与审计日志。
- **CLI 运维能力**：`status` / `doctor` 输出配置摘要与本地自检；`site` 管理静态/PHP 站点；`proxy health-check` 探测上游后端；支持 `--json` 输出和命令前置 `-config`，方便脚本、监控和故障现场使用。

## 当前设计取向

- 默认配置优先保障新用户可进入管理面板，不因少量误操作立即封禁自己。
- 安全策略保持可配置：生产环境可收紧阈值，初始化和测试环境默认更宽松。
- 高并发代理链路优先避免共享锁、上游单连接流控和过小 HTTP/2/HTTP/3 窗口造成整体排队。
- 长时间运行优先减少请求路径上的同步磁盘 I/O、避免调试日志泄露敏感信息，并保证代理热更新不会复用过期传输配置。
- HTTP/2、HTTP/3、WebSocket 与 SSE 场景优先保持连接生命周期可控，证书申请等长任务通过心跳、写超时豁免和同域并发隔离降低卡住或互相拖慢的概率。
- Runner 部署入口分层设计：上传目录/二进制、直接 Docker 镜像、Git push 构建镜像和模板部署最终归一到同一套运行规格。
- sslcat 服务自身重启时只对账 Runner Docker 容器状态，恢复管理态与代理规则，不把已有业务容器跟随重启。
- 版本号需要在 CLI、服务端 API 响应、前端包信息和变更记录中保持一致。
- CLI 危险操作默认需要显式确认，例如删除站点必须追加 `--yes`。

## 近期待改进

- 将安全策略预设拆成“初始化/宽松/标准/严格”几档，减少手动调参。
- 继续收敛 React 页面中的硬编码文案，保证新增界面走 i18n。
- 为登录、防封禁、WAF 阈值和配置迁移补充更多自动化回归测试。

## 版本记录

- `2.2.0-rc1`：CLI 运维增强 P1。新增 `status`、`doctor`、静态/PHP `site` 管理、`proxy health-check`，支持 JSON 输出与命令前置 `-config`。
- `2.1.0`：**正式版**。MCP 内置接入 P5（前端管理页 + Ruby 端到端 + 多客户端文档）+ 完成 P1~P5 全部能力。20 个工具 + 3 个 resource + Web 管理后台「MCP」页面 + 24 用例 e2e + 4 客户端接入示例。
- `2.1.0-rc8`：MCP 内置接入 P4。新增 4 个转发工具 `proxy_route_add / update / delete / upstream_health_check`（PathPrefixRule 级别 CRUD + 并发 TCP 拨号探测，destructive delete 走二次确认）；新增 MCP Resource 协议层（`resources/list / templates/list / read`），实现 3 个核心 resource：`sslcat://config/current`（脱敏快照，深拷贝不污染原 config）、`sslcat://metrics/snapshot`（站点/证书/任务统计 JSON）、`sslcat://logs/access{?since,domain,limit}`（按时间窗口/域名/limit 过滤的访问日志尾部）。
- `2.1.0-rc6`：MCP 内置接入 P3。证书 CRUD 工具 `cert_issue / cert_renew / cert_upload / cert_delete / cert_dns_provider_list`；新增 MCP 长任务模型（`TaskRegistry` + owner 隔离 + 7 天 GC），异步任务 `task_status` 轮询，ACME 进度事件通过 `ssl.Manager` 既有 progress channel 实时桥接到任务事件流；destructive `cert_delete` 走二次确认。
- `2.1.0-rc5`：AI 异常检测真实化补测。修复 `FeatureExtractor.extractBehavioralFeatures` 在 `ipStatesMutex` 释放后仍访问 `IPState` 内部 map/slice 引发的 data race（被 `go test -race` 抓到，接入主流量后必然触发），以及 `InferenceEngine.Predict` 在模型未加载时直接调 nil 特征提取器导致 panic 的问题。新增 Go 单元测试（21 用例）覆盖 sampler/persistence/inference 关键路径，新增 Ruby 黑盒集成测试（10 用例，`tests/ml_regression.rb` + `cmd/ml-testserver`）驱动训练→推理→持久化→重启加载完整链路，报告同时输出 `reports/ml_regression.json` 与 `.md`。
- `2.1.0-rc4`：MCP 内置接入 P2。新增站点写类工具 `site_add / site_update / site_enable / site_disable / site_delete`；引入 destructive 二次确认机制（dry-run 返回 `confirm_token`，60 秒 TTL，绑定 token name+tool+args 哈希，防重放）；接入 Prometheus 指标 `sslcat_mcp_requests_total / request_duration_seconds / destructive_pending_confirmations`。复用现有 `/api/proxy` 的保存行为（`cfg.Save` + 异步证书预取）。
- `2.1.0-rc3`：AI 异常检测真实化。修复前端"训练模型"按钮空转、"最近检测"硬编码假数据、`total_predictions` 永远为 0 的问题。新增内置 `RequestSampler` 真实流量采样、模型 JSON 持久化（`${data_dir}/ml/isolation_forest.json`）、训练历史 JSON 存储、`InferenceEngine` 真实统计与最近预测环形缓冲、新接口 `predictions/recent` 与 `training/history`、`ServeHTTP` defer 异步采样+推理接入主流量。
- `2.1.0-rc1`：MCP 内置接入 P1。新增 `internal/mcp` 协议骨架、Streamable HTTP transport、独立 Token + Scope/RBAC 鉴权、审计日志，以及 4 个只读工具 `version_info / site_list / cert_list / proxy_route_list`。新增 CLI 子命令 `sslcat mcp [enable|disable|token|doctor]`。默认关闭。
- `2.0.0-rc41`：移除 GitHub Actions 中 setup-node 的 Yarn 缓存预探测，避免其在 Corepack 启用前调用全局 Yarn 1 导致 release 构建失败。
- `2.0.0-rc40`：固定 GitHub Actions 前端构建使用 Yarn 4.15.0，并让锁文件元数据与 CI 使用的 Yarn 版本一致，避免不可变安装阶段因 lockfile 迁移失败。
- `2.0.0-rc39`：新增 Runner Docker 容器启动对账，sslcat 重启后只读同步容器状态并恢复代理规则，不主动重启、停止或删除已运行容器。
- `2.0.0-rc38`：Git Deploy 创建应用入口支持 Git push、上传目录、上传二进制和直接 Docker 镜像，并新增 artifact 上传 API 保留目录结构写入 Runner 运行规格。
- `2.0.0-rc37`：新增统一 Runner 运行规格骨架，为上传目录/二进制、直接 Docker 镜像、Git push 构建镜像和模板部署共用同一套环境变量、端口、挂载与启动命令模型打基础。
- `2.0.0-rc36`：补强 Git 自动化部署闭环，内部部署触发源不再被应用 SSH key 绑定误拦截，并新增 Git hook 生成语法回归测试。
- `2.0.0-rc35`：重新默认启用内置 Git Deploy Server，新安装与 Docker 示例配置会开启 `runners.git`，并修复 Git hook 模板百分号转义导致的编译问题。
- `2.0.0-rc34`：报告调度器首次执行等待改为可中断，Stop 改为幂等，减少热重载/停止时报告 goroutine 长时间滞留风险。
- `2.0.0-rc33`：监控组件 Stop 统一改为幂等关闭，避免重复关闭和 stop channel 置空带来的竞态，提升热重载/长期运行稳定性。
- `2.0.0-rc32`：WAF Stop/清理器关闭路径改为幂等，并确保引擎停止时关闭多维封禁器后台清理 goroutine，降低热重载和重复关闭风险。
- `2.0.0-rc31`：WAF 请求检测改为规则快照匹配，避免慢 body 读取期间持有规则读锁，降低高并发下规则更新/清理等待导致后续请求变慢的风险。
- `2.0.0-rc30`：WAF 主转发路径只扫描请求体前 1MB，并恢复完整请求体供下游继续处理，降低大 body 高并发下的内存和 GC 压力。
- `2.0.0-rc29`：为 WAF/WebAuthn 管理 API 增加请求体大小限制，移除 WebAuthn 响应体调试日志，并补强配置版本文件原子落盘。
- `2.0.0-rc28`：管理日志 API 改为尾部有界读取，避免大日志文件读全量内存，并补强启动密钥与首次设置标记的原子落盘。
- `2.0.0-rc27`：补强 CDN 缓存数据/元数据/预压缩副本原子落盘，限制预压缩并发，并提升配置保存的崩溃一致性。
- `2.0.0-rc26`：修复 API Token 删除持久化死锁，补强文件会话存储关闭生命周期、session/TOTP/token 原子落盘和 session key 校验。
- `2.0.0-rc25`：补齐 Edge Routing、Service Mesh 和 GeoIP 自动更新停止路径的幂等保护，降低热重载与长期运行重复清理时的 panic 风险。
- `2.0.0-rc24`：强化上游缓存同 key 并发读写、缓存文件原子落盘、热点命中 metadata 写盘节流，并修复 WebSocket 事件分发与代理退出路径的并发可靠性问题。
- `2.0.0-rc23`：补强证书申请 SSE 在 HTTP/2/HTTP/3 场景下的长连接稳定性，降低 WebSocket 高并发退出路径阻塞风险，并增加同域证书申请并发保护、证书/私钥原子落盘和证书 API 域名校验。
- `2.0.0-rc22`：新增管理员一次性恢复码重置密码能力，并将管理员密码/恢复码文件写入改为原子替换，提升忘记密码和异常中断场景下的可恢复性。
- `2.0.0-rc21`：为 `sslcat.block` 与白名单文件增加运行时变更监控，删除或编辑文件后自动重载内存状态，手工解封无需重启服务。
- `2.0.0-rc20`：补齐多个后台组件 Stop/Close 幂等保护，降低热重载、重复关闭和 CDN processing 超时清理并发触发时的 panic 风险。
- `2.0.0-rc19`：补强访问日志异步化、DDoS 攻击记录有界队列、上游/CDN 缓存请求路径减负与清理器生命周期、内存缓存并发统计、响应写包装器能力透传、代理缓存键隔离和 debug 日志脱敏，进一步降低高并发与长期运行风险。
- `2.0.0-rc18`：放宽初始化阶段封禁阈值，补齐旧配置兜底，移除密码敏感日志，优化高并发代理/HTTP2/HTTP3 行为，并统一版本可观测性。
