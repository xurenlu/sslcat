# SSLcat 设计风险与整改记录

审查日期：2026-11-20。对象为当前工作区，包含未提交变更。静态审查、已实现修改与实际测试结果分别记录；本文不代表全部风险已关闭。

## 预期行为

- 管理 API 统一校验身份；只读令牌不能通过 POST、PUT、PATCH、DELETE 执行写操作。
- 配置变更日志只记录字段名和变更级别，不输出配置值；新写入的配置与备份仅所有者可读写。
- 强制重载遇到解析、校验或组件应用失败时返回错误，保留上次成功配置与哈希；并发重载串行执行。
- 文件监听、集群同步与手动重载使用一致的默认值、校验与应用流程；启动时字段保留当前运行值，磁盘中的新值留待重启。
- Web 客户端转发头只能由显式配置的可信代理提供，正确处理 IPv4、IPv6、多级代理和无效信任边界。

## 问题与整改状态

| 编号 | 优先级 | 证据与影响 | 实现与验证状态 |
| --- | --- | --- | --- |
| R1 | 高 | 中央管理鉴权原先只验证令牌存在；清缓存 handler 未单独检查写角色。 | 已实现：中央入口对非 GET/HEAD/OPTIONS 请求要求 write 角色，并新增令牌权限及清缓存入口回归。依赖补齐后，管理鉴权定向回归已通过。GET 运维端点的完整权限审计仍待完成。 |
| R2 | 高 | 重载日志打印配置旧值、新值，可能包含 Admin、Cluster、SSL 凭据；配置及备份原以 0644 保存。 | 已实现：重载日志删除配置值；配置、版本备份、日备份原子写入 0600；保存时收紧已有常规备份权限。日志与权限回归通过 config 包测试及 race 检查。原有 Save 仍将备份失败作为警告，旧备份无法 chmod 时不保证完成权限收紧。 |
| R3 | 高 | Web handler、代理和安全组件共享可变 Config；UpdateConfig 更换指针，部分 API 原地修改切片/映射。局部互斥不构成统一事务。 | 未关闭：已移除 Slave 原地覆盖配置的路径，并串行化重载，但 api_sites 等写接口与代理读路径仍共享对象。完整整改需要不可变运行快照、独立编辑配置和统一保存/发布事务；不能将 config 包 race 通过解释为全系统无竞态。跨组件迁移尚未实施及验证。 |
| R4 | 高 | Slave 的两条重复监听器直接向零值 Config 做 json.Unmarshal，差异配置遗漏字段后丢失默认值，并绕过主应用路径。 | 已实现：删除 Web 自建监听、零值加载、原地应用和无同步路由替换；main 的 ConfigWatcher 为唯一文件监听入口，使用 config.Load 与统一组件应用回调。新增默认值及发布运行配置的回归已通过 config 包测试；真实 Slave 集成尚未验证。 |
| R5 | 中 | ForceReload 原先始终返回 nil；组件应用失败后存在部分生效；ACME 重载错误仅记录日志。 | 已实现：传播实际错误、序列化重载、失败时保留 watcher 配置与哈希；逆序尝试回滚所有已尝试组件并合并回滚错误；ACME 先准备成功再替换状态，清空邮箱会关闭旧管理器。config 回归及 ACME 重载回归已通过。回滚为尽力恢复，不构成跨组件原子事务；DNS 提供商初始化失败仍有仅记录日志的路径。 |
| R6 | 中 | HardReload 分类原先不保证启动监听器或路由重建，可能报告成功但运行行为与配置字段不一致。 | 已实现文件重载路径：ReloadEffective 保留启动时字段，应用其余热更新；watcher 只发布实际运行配置，磁盘请求配置保持不变。API 返回 restart_required/restart_fields；已观察到的重启需求持续到进程重启。启动字段与混合热更新回归通过 config/race。直接修改共享配置的 API 路径仍受 R3 影响，不能据此宣称全部设置入口一致。 |
| R7 | 中 | Web getClientIP 隐式信任私网转发头，并按冒号裁切 RemoteAddr，IPv6 解析错误。 | 已实现 Web 入口：显式 IP/CIDR 信任列表、可选单一头、默认 XFF 从右向左处理，遇无效边界回退对端；IPv6、多头、伪造头、重复头及可信代理匹配回归已通过。其他组件的独立 IP 提取函数仍需统一，详见代理配置说明。 |

## 实现边界

- 主重载入口是 `main.go` → `ConfigWatcher.OnConfigApply` → `ReloadManager.ReloadEffective` → 成功回调发布运行配置。
- 组件应用失败会停止后续应用并尝试回滚；回滚失败会一并返回错误，不能保证外部副作用已撤销。
- 启动字段包括监听地址/端口、HTTPS/HTTP2/HTTP3、超时、pprof、会话存储、数据目录、SecretKey、管理及 Bot API 前缀。文件更新不会假装这些字段已热生效。
- 磁盘请求配置与运行配置已区分，但后续 API 保存仍可能覆盖待重启字段；需随 R3 的统一编辑事务一起解决。
- [可信代理配置](configuration/trusted-proxies.md) 仅约束 Web getClientIP 调用者，不代表 WAF、代理等全部独立解析器已修复。

## 历史审查更正

- 当前工作区已有 `admin_api_auth.go`，旧审查的“83 个匿名 API”不能作为本轮已证实结果。
- Bot 更新通过外层 handler 调用 `authorizeAPI(..., false)`，不能只看内部更新函数就判定未鉴权。
- `docs/repository-review-20260929.md` 保留历史建议，其测试数量、构建通过和复现结论不代表当前快照。
- 本次提交仅包含设计整改代码、回归测试及相关文档；目录整理、版本准备、监控与 PHP 的其他改动保留在工作区。未执行发布、部署、推送、打标签或 Git 历史重写。

## 验证记录

- 此前 `proxy.golang.org` 连接超时；`goproxy.cn` 可下载但速度较慢，批量下载曾超时。随后使用命令级 `GOPROXY=https://proxy.golang.com.cn` 补齐 Web/SSL 的直接和传递依赖，模块解析通过。未关闭校验，未修改全局 Go 配置，`go.mod` 和 `go.sum` 无变化。
- 依赖补齐后，Web 实际编译发现 `server_setup.go` 在删除重复监听器后遗留未使用的 `net/http` 导入；已删除该导入，并重跑原测试命令。
- `go test ./internal/config ./internal/web -run 'Test(Reload|ChangeDetector|DetectChanges|AdminAPIAuth)' -count=1`：通过，config 0.263s、Web 0.576s。此前的 Web setup failed 已由实际编译及断言通过取代。
- `go test ./internal/ssl -run TestACMEReload -count=1`：通过，0.614s，覆盖 ACME 缓存目录准备失败保留旧状态、成功切换及清空邮箱禁用旧管理器。
- `go test ./internal/web -run 'Test(ClientIP|IsTrustedProxy)' -count=1`：通过，0.325s，覆盖默认不信任转发头、可信代理链、IPv6、多头与无效信任边界。
- 此前 `go test ./internal/config -count=1`：通过，0.757s；随后增加运行配置校验后，`go test -race ./internal/config -count=1` 通过，1.778s，包含日志/权限、并发强制重载、失败回滚、默认值和待重启字段测试。该结果仅覆盖 config 包。
- `git diff --check`：通过；仅证明补丁无空白错误，不能替代编译或行为验证。

以上为定向回归，尚未通过完整 Web/SSL 测试、全项目构建或系统级并发验证。R3、R1 的完整 GET 运维权限审计、跨组件事务、全部 IP 解析器统一及真实集群集成仍保持开放。
