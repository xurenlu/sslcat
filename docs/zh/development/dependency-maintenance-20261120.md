# 依赖维护记录（2026-11-20）

> 源码候选版本：2.5.0-rc3。基线：已包含镜像链接修复的 main（58ff6ff0）。初轮验证：2026-11-21；主分支合入复验：2026-11-22。Go 全量短测试、核心 race、双 SQLite 驱动、三平台编译与漏洞扫描已完成；安装器 234 个计划检查分两批取得通过结果，保留首批整轮超时记录。前端保留已确认的 3 项存量测试失败及全库 lint 问题，具体结果见验证记录。

## 范围与依据

本次为既有项目维护，覆盖根 Go 模块的 29 个直接依赖、13 个重点间接依赖，独立 `tools/test-templates` 模块，以及前端基线的 41 个直接依赖声明；升级后移除废弃的国际化类型占位包，前端直接声明为 40 项。版本来自 Go 官方下载接口、Go module proxy 和 npm 官方 registry 的实际查询。Go 官方于 2026-11-10 发布 1.27.4，当前支持 1.27 与 1.26；原项目声明的 1.25 已退出支持。

Go 升级到最新稳定版 1.27.4。前端采用仍受支持并与现有 React 18 界面兼容的工具组合；涉及组件体系、凭证存储或模块路径的迁移单独评估，不仅按版本数字判断兼容性。

## Go 升级清单

以下为本次选定的直接依赖目标，实际模块图以 go.mod/go.sum 为准。

| 模块 | 基线版本 | 目标版本 |
| --- | --- | --- |
| Go | go 1.25 / toolchain 1.25.1 | 1.27.4 |
| logrus | 1.9.3 | 1.10.2 |
| bigcache/v3 | 3.1.0 | 3.2.0 |
| brotli | 1.2.0 | 1.3.0 |
| aws-sdk-go-v2 | 1.39.4 | 1.48.0 |
| aws-sdk-go-v2/config | 1.31.15 | 1.33.21 |
| aws-sdk-go-v2/credentials | 1.18.19 | 1.21.3 |
| aws-sdk-go-v2/service/route53 | 1.59.1 | 1.72.0 |
| bubbles | 0.21.0 | 1.0.0 |
| go-sqlite3 | 1.14.32 | 1.14.53 |
| prometheus/client_golang | 1.23.2 | 1.25.0 |
| quic-go | 0.59.0 | 0.59.1 |
| x/crypto | 0.48.0 | 0.59.0 |
| x/image | 0.32.0 | 0.48.0 |
| x/term | 0.40.0 | 0.48.0 |
| modernc/sqlite | 1.29.6 | 1.62.0 |
| fsnotify | 1.6.0 | 1.10.1 |
| x/net | 0.50.0 | 0.63.0 |
| x/sys | 0.41.0 | 0.50.0 |

重点间接依赖包括 JWT 5.3.1、x/text 0.44.0。AWS 配套模块随 SDK 解析。modernc/sqlite 1.62.0 明确要求 libc 1.80.1；其官方文档要求精确配套，不独立升级到 libc 1.82.3。

未改动的当前模块路径最新版本包括 webp 1.4.0、bubbletea 1.3.10、lipgloss 1.1.0、uuid 1.6.0、mux 1.8.1、websocket 1.5.3、gofpdf 1.16.2、geoip2-golang 1.13.0、otp 1.5.0、gopkg.in/yaml.v3 3.0.1。WebAuthn 0.10.2 保留现有凭证模型，迁移边界见下文。

## 前端升级选择

| 依赖 | 基线锁定 | 选定版本 |
| --- | --- | --- |
| Vite | 5.4.20 | 7.3.8 |
| plugin-react | 4.7.0 | 5.2.0 |
| Vitest | 1.6.1 | 4.1.12 |
| TypeScript | 5.9.2 | 5.9.3 |
| ESLint | 8.57.1 | 10.15.0 |
| typescript-eslint parser/plugin | 6.21.0 | 8.73.0 |
| react-hooks ESLint 插件 | 4.6.2 | 7.1.1 |
| react-refresh ESLint 插件 | 0.4.21 | 0.5.8 |
| Axios | 1.12.2 | 1.21.1 |
| react-router-dom | 6.30.1 | 7.18.6 |
| Chakra UI | 2.10.9 | 2.10.10 |
| Sentry React | 10.19.0 | 10.78.0 |
| i18next | 25.5.3 | 25.10.10 |
| react-i18next | 16.0.0 | 16.6.6 |
| Playwright | 1.55.1 | 1.65.1 |
| testing-library/react | 14.3.1 | 16.3.3 |
| testing-library/jest-dom | 6.9.1 | 7.0.1 |
| jsdom | 27.0.1 | 27.4.0 |

前端继续使用 Yarn 4.15.0，yarn.lock 是本次安装和审计依据。本地验证使用 Node.js 24.8.0；新工具组合建议使用 Node.js 24 LTS，或至少 22.13 的 22.x。发布 CI 已使用 Node.js 22，README、中英文系统要求与本地构建指南同步 Go 1.27.4、macOS 13 及前端构建工具要求。React / React DOM 保持 18.3.1，Three.js 运行库为 0.182.x，类型锁到 0.182.0；移除已由 react-i18next 自带类型替代的 @types/react-i18next 占位包。其余类型和测试辅助库使用各自兼容分支的更新版本。

Vite 5 和 Vitest 1 已退出支持。选定 Vite 7.3 与 Vitest 4.1 均仍接受重要及安全修复，保留现有 Rollup 构建路径。没有将 Vite 8 的 Rolldown 切换混入本次维护。TypeScript 最新 7.0.2 不满足当前 typescript-eslint 的普通 peer 范围，使用兼容的 5.9.3。jest-dom 6.10.0 是官方标记的错误 minor 发布，明确排除。

ESLint 10 采用 flat config，并要求 @typescript-eslint/no-explicit-any 为 error。旧仓库没有跟踪的 ESLint 配置；首次有效 lint 可能揭示存量问题，其结果与本次依赖导致的回归分别记录，禁止通过大面积禁用规则掩盖问题。

## 审计发现与安全边界

升级前，Go 官方漏洞库版本核对覆盖 go.mod 的 87 项声明依赖，8 个第三方模块的版本落入共 48 个独立公告范围。本机 Go 1.26.3 落入 28 项标准库公告范围。针对代理、TLS 和压缩包的局部静态扫描确认 23 个独立公告存在符号调用链；全量扫描曾因缺失模块下载超时未完成。

重点修复包括 HTTP/2、Unicode 规范化、X.509、Brotli 和 JWT 的相关问题。quic-go 0.59.1 修复 GO-2026-5676（HTTP/3 QPACK trailer 资源消耗），本次不跨到 0.65 进行额外 API 迁移。Go 1.27.4 在本次官方公告范围核对中未命中。

旧前端锁文件经 npm 官方 bulk 接口核对，共 631 个 npm 包名、675 个包版本；30 个包返回 129 项受影响版本区间，按 GHSA URL 去重为 112 个公告（critical 4、high 49、moderate 56、low 3）。这包含开发工具、可选依赖及需要特定条件才能触发的问题，不等于生产 SPA 有同样数量的可利用漏洞。废弃提示不计为安全漏洞。

React Router 6.30.6 仍在两项新公告范围内，7.18.6 支持 React 18，可独立迁移。仅将 Vite 5 或 Vitest 1 更新补丁不足以修复其全部已知问题；Vitest 3.2.7 也仍在 mocker 路径遍历公告范围内，故选定 4.1.12。传递依赖优先按父包兼容范围刷新，不能用破坏性的跨主版本 resolutions 强行消除告警。

## 保留的兼容性边界

- WebAuthn 最新 0.18.2 删除 RPOrigin/Timeout，并对凭证 flags、UV 等认证状态有额外要求。现有持久化只还原凭证 ID、公钥及计数器，升级需要覆盖旧凭证登录和存储兼容性，不能只替换配置字段。
- Charm TUI v2 改变 View 返回类型、按键事件与终端模式；GeoIP v2 改为 netip.Addr；YAML 新模块路径也需要 import 与序列化回归。
- React 19、Fiber 9、Drei 10 与 Leaflet 5 存在成套 peer 约束。Chakra 3、Recharts 3 虽可继续使用 React 18，也涉及组件或图表 API 迁移。本次保持现有界面组合；旧 Recharts 依赖的 Lodash 可独立做兼容安全更新。
- Go 1.27 的 macOS 最低支持版本是 macOS 13。Alpine builder 使用 1.27.4-alpine3.24，Debian builder 使用 1.27.4-bookworm；1.27.4-bullseye 经官方查询不存在，不能机械替换版本号。
- 纯 Go 构建成功不能证明所有直接使用 mattn/sqlite3 的业务模块在 CGO 关闭后可用。静态链接、Zig 和容器构建须各自验收。

## 验证记录

已完成升级前基线：本机 Go 1.26.3 上执行全量 Go 短测试通过，TLS、管理后台和代理测试亦单独通过。旧前端 immutable 安装停留在 Fetch 阶段，已取消该基线任务；没有得到旧前端构建或测试结果。

### 已确认的工具链与模块结果

- 隔离工具链实际输出 `go version go1.27.4 darwin/arm64`。darwin/arm64 归档为 68,231,011 字节，SHA-256 与 Go 官方下载 JSON 一致；未覆盖本机全局 Go。
- `go mod tidy` 已完成，`go mod verify` 返回 `all modules verified`。完整模块清单为 140 项，模块图为 497 条边。
- 直接依赖集合仍为 29 项，其中 18 项升级；33 项既有间接依赖升级，MVS/tidy 新增与移除各 5 项间接声明。声明依赖总数仍为 87。
- `modernc.org/sqlite v1.62.0` 实际选择 `modernc.org/libc v1.80.1`；保留的 WebAuthn、TUI、GeoIP、YAML 模块版本已核对。
- 新增 SQLite 驱动回归覆盖隔离文件数据库的参数化写入、事务回滚、UPSERT、关闭重开与完整性检查；默认优化的 CGO 驱动与 `CGO_ENABLED=0` 的纯 Go 驱动测试均通过。纯 Go 测试仅证明 `internal/database` 的驱动行为；其他直接指定 `sqlite3` 的模块仍有既有 CGO 限制。
- 缓存首次针对测试真实失败：100ms TTL 在压缩和两次 fsync 后已过期，且临时目录配置误写入 CDNCache 而非实际 UpstreamCache。现改用正确的隔离配置与确定性落盘过期时间，两个用例各重复 20 次通过；随后 cache/compression 整包复验通过。
- 原 BigCache 测试实际选择默认 simple 后端；现显式使用 BigCache，CRUD、metadata、expiry、clear 等 5 个子用例通过。
- 独立 `tools/test-templates` 模块同步 Go 1.27.4，并更新 logrus 1.10.2、x/net 0.63.0、x/sys 0.50.0；`tidy`、`verify` 与只读 `go test ./...` 编译检查通过（该模块无单测），未执行远端模板测试。离线首轮因旧依赖元数据与 YAML 测试依赖未缓存而失败，精确修改清单并补齐缓存后才完成验证。
- Linux 源码安装器使用独立的 `/opt/sslcat-toolchains/go1.27.4`，同步当前会话 PATH、GOROOT 与 GOTOOLCHAIN；后续编译和模板测试 SSH 入口会重新选择工具链。初版实现的稳定版本比较 45 项、安装隔离 mock 42 项及 5 个 Shell 语法检查曾通过，但独立复核仍发现中断残留目录、继承旧 GOROOT、探测隐式下载及后续 SSH 会话选择等缺陷。现已加入同文件系统暂存发布、备份恢复和清理，并比对五入口选择逻辑一致；初版 mock 结果不能代替这些新增恢复路径的验证。

### 安装器恢复验证

2026-11-21 继续验收。此前驱动使用 macOS `/usr/bin/ruby` 启动 shim，模拟 PATH 内的 `uname` 又回调同一驱动，导致递归子进程并耗尽新进程启动额度。遗留进程已清理，自动 Shell 入口恢复；通过 `file` 与 `--version` 核实 Homebrew Ruby 为真实 Mach-O arm64 二进制后，驱动固定使用该解释器，并只以内建函数模拟架构。独立静态复核已完成，发现的中断报告问题已修正：信号退出记录为失败和中止，并保留非成功退出语义。另修正了运行预检中发现的空日志读取问题；不把两次失败预检计为有效验收。

第一轮完整矩阵实际为 234 项中 183 通过、51 失败。51 项均落在三个安装入口的失败或信号路径，报错 `staging leaked`。最小复现确认 Bash 3.2 显式 `exit` 会先释放函数局部变量，使 EXIT trap 丢失路径。现将目标、暂存和备份路径保存在隔离子 shell 的状态中，三个入口实现一致，父 Shell 不残留这些变量。

修正后的首轮复验在 109 项通过后触发单例 10 秒上限，矩阵立即停止并回收自有进程组，报告为 `completed=false, stopped=true`。文件时间戳显示该例最后清理动作发生在第 9.327 秒，实际暂存目录已删除；检查时主机 1 分钟平均负载为 106.40。随后将单例上限调整为 30 秒、整轮上限调整为 540 秒，守护组上限随之为 32 秒；仍限制最多 400 次执行、回收等待 2 秒，任何 timeout/EAGAIN 均停止整轮。

30 秒单例上限的完整矩阵随后取得 197 项通过，但触及 540 秒整轮上限，实际退出码为 1，`completed=false, stopped=true`；报告保留 1 条 `matrix stopped` 驱动中止记录，没有已完成用例的断言失败。未再次放宽时间上限，改为按最后通过的精确用例名称补测，跳过项单独记录且不计入补测通过数。补测的 37 项全部通过，实际退出码为 0，`completed=true, stopped=false`。

| 批次 | 通过检查 | 用例断言失败 | 驱动中止记录 | 所选范围完成 | 实际子执行次数 |
| --- | ---: | ---: | ---: | --- | ---: |
| 完整矩阵尝试 | 197 | 0 | 1 | 否 | 272 |
| 剩余项目补测 | 37 | 0 | 0 | 是 | 60 |

最终结论为 **234 个计划检查分批覆盖通过，完整单轮未完成**。汇总器逐项比对原始 234 项清单、197 个已通过项、补测恢复点、197 个跳过项与 37 个补测项，确认名称与顺序完整、无遗漏或重复计数，并核对两批的完成标记、计数、执行边界及五个脚本在补测核查时的 SHA-256。两批实际子执行共 332 次，包含 heredoc 捕获、失败后重试及整轮中断前尚未形成用例结果的子执行，不等同于检查项数。

验证覆盖五入口稳定版本比较、双架构及别名、SHA 校验、旧或预发布工具链、继承旧 GOROOT、探测失败与禁止隐式下载、不完整目录/文件/悬空链接保留、下载/校验/解压/完整性/备份/发布/恢复失败、HUP/INT/TERM、发布前后信号、同目录重试，以及两个后续 SSH 入口的工具链选择。所有脚本语法、五入口选择 helper 一致性、版本与源码差异格式检查通过。

本地证据同时输出 JSON 与 Markdown，位于隔离工作树的忽略目录：

- 原始完整清单与首次真实失败：`build/go-install-entry-mock-20261121-68686-x63ets/results.json`（同目录含 `results.md`）。
- 修正后首批超时记录：`build/go-install-entry-mock-20261121-9816-oesit7/results.json`（同目录含 `results.md`）。
- 37 项补测记录：`build/go-install-entry-mock-20261121-75733-3h3c8z/results.json`（同目录含 `results.md`）。
- 最终汇总：`build/go-install-validation-summary-20261121-97663-o436gf/results.json` 与 `results.md`。

这些记录仅证明本地隔离模拟的覆盖与恢复行为，不替代真实 Linux 安装或远端运行验收。安装器验证未发起真实下载或系统安装，未连接 SSH、部署服务或执行模板集成测试；本机编译使用前文已校验的隔离 Go 工具链。Go 和前端的已完成结果不受验证驱动故障影响。

### 前端结果

| 验证 | 实际结果 |
| --- | --- |
| Yarn 安装与 `install --immutable` | 通过，Yarn 4.15.0；TLS 与完整性校验保持开启 |
| 构建 | 通过，2579 个模块；输出到 `build/frontend-dependencies-20261120`，不覆盖跟踪中的嵌入资源 |
| TypeScript | `tsc --noEmit` 通过 |
| 单元测试 | 36 项中 33 通过、3 失败；5 个文件中 4 通过、1 失败 |
| 新增路由回归 | AuthGuard 的 3 项与站点编辑查询参数导航的 1 项全部通过 |
| 全库 lint | 失败：429 errors、54 warnings、0 fatal；本轮修改的配置与测试文件定向 lint 通过 |
| Yarn 全树安全扫描 | 扫描完成，仅返回 2 条 deprecation，原始退出码 1；`--no-deprecations` 退出码 0 |
| npm 官方 bulk 独立复核 | HTTP 200，覆盖 523 个包名、563 个包版本；受影响包数 0，响应 `{}` |

剩余 3 项单测失败位于原有 `src/utils/proxyLoopDetection.ts:29`：按首个冒号截断主机名，使 `::1`、`::` 与对应代理环路检测错误。已直接提取 `58ff6ff0` 基线源码转译运行，确认相同失败；未修改产品逻辑或跳过测试。失败结果如下：

| 用例（`src/utils/proxyLoopDetection.test.ts`） | 期望 | 实际 |
| --- | --- | --- |
| 应该识别 IPv6 loopback | `isLocalhost('::1') === true` | `false` |
| 应该识别 IPv6 any | `isLocalhost('::') === true` | `false` |
| 应该检测到 ::1:80 的循环 | `detectProxyLoop('::1', 80)` 非空 | `null` |

首次设置测试的旧翻译 mock 已改为真实中文资源，相关 3 项全部通过。

全库 lint 揭示 237 项 unused、191 项 explicit-any、1 项旧 Hooks 回调违规；另有 48 条 Hooks dependencies 和 6 条 Refresh 警告。旧仓库没有跟踪的 ESLint 配置，因此不能将该结果描述成升级前 lint 已通过、升级后失败；本次首次形成有效规则检查，未用抑制掩盖存量问题。

2 条 deprecation 分别为 Recharts 2.15.4 停止维护与 Drei 引入的 three-mesh-bvh 0.7.8 兼容性提示，未计为安全漏洞。构建仍有大 chunk 与空 react-vendor chunk 提示，安装仍有 4 条上游内部 React peer 缺失提示；实际构建、类型检查与路由回归已通过。未执行浏览器 E2E 或覆盖率统计。

### Go 编译、运行与安全复扫

所有下列检查均使用隔离的 Go 1.27.4 与最终依赖清单。根模块及独立工具模块的离线 `go mod tidy -diff` 均无差异。

| 验证 | 实际结果 |
| --- | --- |
| 全量 Go 短测试 | 默认 CGO 优化，`go test -p=4 -mod=readonly -count=1 -short -timeout=120s ../...` 通过；最终缓存测试修改已包含在此轮运行中 |
| 核心 race | `internal/ssl`、`internal/web`、`internal/proxy` 全部通过，分别耗时 25.165s、12.522s、1.564s |
| CGO SQLite | `TestSQLiteDriverPersistence` 通过；默认编译优化，包耗时 0.376s |
| 纯 Go SQLite | `CGO_ENABLED=0` 的同一持久化测试通过，包耗时 3.512s |
| Linux AMD64 | CGO + musl 静态编译通过；`file` 确认为 x86-64 ELF，`readelf` 无 INTERP、无动态段 |
| macOS ARM64 | CGO 编译通过；Mach-O arm64，最低 macOS 13；本机实际执行 `--version` 为 `SSLcat v2.5.0-rc3 (build: dependency-verification)` |
| macOS AMD64 | CGO 交叉编译通过；Mach-O x86_64，最低 macOS 13；未在 Intel 机器实际运行 |
| Go 源码安全扫描 | govulncheck v1.9.0 全量 symbol/source 扫描完成，实际解析 JSON 为 0 条 `finding`；扫描器自身使用 Go 1.27.4 构建 |

全量测试首轮曾因旧缓存用例的 100ms TTL 失败；修复隔离配置与确定性过期后，最终 `-count=1` 运行通过。早期临时降低 C 优化级别的功能验证不作为最终构建依据；上表测试与三平台产物均已使用默认优化完成。

全局原有 govulncheck 虽为 v1.9.0，但以 Go 1.26 构建，首次扫描无法解析 Go 1.27 新语法并报错。现使用真正的 Go 1.27.4 将同版本扫描器重建到隔离目录后重跑，未覆盖全局扫描器。最终 JSON 含 config 1 条、SBOM 1 条、progress 2 条、OSV 记录 295 条、`finding` 0 条；295 是扫描加载的公告记录数量，不是漏洞命中数。漏洞库为 `https://vuln.go.dev`，返回的数据库更新时间为 `2026-11-11T02:51:11Z`。该结论受该次数据库内容及静态分析范围约束，不等于证明不存在任何漏洞，也不能只凭 JSON 模式退出码 0 得出结论。

本地产物位于 `build/verify-dependencies-20261120/`，均注入候选版本 `2.5.0-rc3`，并非正式发布包：

| 产物 | SHA-256 |
| --- | --- |
| `sslcat-linux-amd64` | `a7702cfb36c342b0d46c8cba3814723976952c884568664c3dea4f244a45fc13` |
| `sslcat-darwin-arm64` | `51906d1d6eb0df246af2ef61b5328add697842b2b96ceaab12fd804ae04bf370` |
| `sslcat-darwin-amd64` | `44aefebad188894c0fa7547a8dad9cb78efe6e3683f220f6ffcdf79275622dca` |

Docker daemon 与 Zig 在本机不可用，未实际执行容器或 Zig 构建；Linux 产物未在目标 Linux 主机实际运行。Go 验证包使用仓库跟踪的嵌入资源，新前端另行构建到隔离目录，未做新前后端组合的浏览器 E2E。未运行非 short 的外部环境集成测试。

验证阶段未执行生产部署、数据库 schema 迁移或发布标签；提交与推送状态以 Git 记录及 PR 为准。

## 2026-11-22 主分支合入复验

依赖维护原提交为 `f482413c15d9ebd27a5c58a6169b17243ef43e77`。本次从 `origin` 获取的最新 `main` 为 `2d895f947f3e147184d30b034bd9cd8b56721c66`，执行普通合并，未 rebase 或重写分支历史。Git 自动合并成功，没有未解决条目；保留主分支的管理授权、配置重载、监控、PHP 配置和目录整理，以及本分支的依赖升级，候选版本保持 `2.5.0-rc3`。

两个 CGO Dockerfile 以内容不变的重命名移至 `docker/Dockerfile.cgo` 与 `docker/Dockerfile.cgo.zig`，保留 Go 1.27.4 构建镜像；活跃构建脚本已使用新路径。`main.go` 相对本次主分支仅保留候选版本差异，同时完整保留新的配置应用与重载调用。新增 PR CI 继续通过 `go-version-file: go.mod` 选择工具链，并使用 Node 22 和 Yarn immutable 安装；未发现与本分支声明冲突的配置。

以下为合并后的本地复验，使用隔离 Go 1.27.4、CGO 默认优化、只读模块以及已有本地模块缓存：

| 检查 | 实际结果 |
| --- | --- |
| 全项目构建 | `go build -p=4 -mod=readonly ./...` 通过 |
| 全项目 Go 短测试 | `go test -p=4 -mod=readonly -count=1 -short -timeout=120s ./...` 通过，所有含测试的包均成功，进程退出码为 0 |
| CI 对应非 short 回归 | `internal/config`、`internal/web`、`internal/ssl`、`internal/monitor` 均通过，包耗时分别为 0.828s、1.436s、5.532s、0.346s |
| CI 对应 race | `internal/config`、`internal/monitor` 通过，包耗时分别为 1.668s、1.426s |
| 前端类型与构建 | 显式使用 `corepack yarn@4.15.0` 执行 `build`（含 tsc），2579 个模块构建通过，Vite 构建耗时 5.40s |
| 合并与版本静态核对 | 无未解决条目；迁移路径、默认版本与主分支重载调用均保留；当前版本统一为 `2.5.0-rc3` |

前端第一次调用 `corepack yarn --cwd ...` 时，由于启动目录位于前端项目之外，实际选择了 Yarn 1.22.22。该次虽通过，但不作为 Yarn 4 的验证依据；最终已显式指定 Yarn 4.15.0 并重跑通过。最终输出位于 `build/frontend-main-merge-20261122-2d895f94-f482413c-yarn4/`，保留原有大 chunk 与空 react-vendor 提示，没有覆盖跟踪中的嵌入资源。

安装器及依赖清单在合入主分支时没有实现变更，沿用前文的分批恢复测试与安全扫描结果。本轮未重新执行前端完整单测、全库 lint、安全扫描、安装器模拟或容器 / Zig 构建；前文记载的限制继续有效。未进行真实 Linux 安装、PHP-FPM / 集群集成、生产部署或浏览器 E2E。本地检查不等同于 GitHub Ubuntu / Node 22 CI 结果，远端结果由 PR 自动修复监控接收。

## 官方资料

- https://go.dev/dl/?mode=json
- https://go.dev/doc/devel/release
- https://go.dev/doc/go1.27
- https://pkg.go.dev/vuln/
- https://vuln.go.dev/
- https://registry.npmjs.org/
- https://vite.dev/releases
- https://vitest.dev/releases
- https://eslint.org/version-support/
- https://eslint.org/docs/latest/use/migrate-to-10.0.0
