# PR 持续集成

## 触发与权限

此前仓库仅有标签推送或手动触发的 Release Builds，以及发布 Release 后触发的 OSS 同步；普通分支推送和 PR 更新没有对应检查。

`.github/workflows/ci.yml` 为所有目标分支的 PR 提供检查，包括以功能分支为目标的堆叠 PR。创建、更新、重新打开或标记为可审查时触发；合入 main 后及手动运行时也执行。同一 PR 的旧运行可被新运行取消。

工作流只授予 `contents: read`，不使用发布凭据，不创建 Release、标签或上传 OSS。发布流程继续使用独立的 Release 工作流。

## 检查范围

- 使用仓库声明的 Go 版本、Node.js 22 和 packageManager 指定的 Yarn。
- 按不可变锁文件安装前端依赖，执行 TypeScript 检查与 Vite 构建，将产物放入 Go 嵌入目录后编译全部 Go 包。
- 完整运行 `internal/config`、`internal/web`、`internal/ssl`、`internal/monitor` 的现有测试。
- 对配置和监控包运行完整 `-race` 检查。

这是上述模块的回归门禁，不等同于全仓库所有测试、浏览器端到端测试或生产部署验证。真实 PHP-FPM 测试需要独立配置 `PHPTEST_FCGI` 和 `PHPTEST_SCRIPT`；缺少环境时的跳过不代表真实 FPM 行为已验证。

只有 PR 当前提交对应的所有检查成功，才可报告该 PR 的 CI 通过。工作流新增或分支更新后，应以 GitHub 实际运行结果核对，不能用本地测试或旧提交的绿色结果替代。
