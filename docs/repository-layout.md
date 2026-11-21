# 仓库目录约定

根目录保留源码包入口、依赖清单、版本与概览，以及公开安装和默认运行入口。历史报告、示例和维护工具按用途下沉。

| 位置 | 用途 |
| --- | --- |
| `main.go`、`signal_handler.go`、根目录 Go 测试 | Go 主包；与 `go build .` / `go test .` 保持一致 |
| `internal/`、`cmd/`、`frontend/` | 后端模块、命令与前端 |
| `docs/design-review.md` | 设计风险、整改状态及验证边界；按具体记录判断完成情况 |
| `docs/reports/` | 历史诊断、实现总结和技术评估 |
| `docs/notes/` | 与核心产品无关的规划资料 |
| `docs/product/` | 详细产品说明及历史信息 |
| `docs/changelog/` | 历史更新日志 |
| `scripts/diagnostics/` | 诊断、性能分析及历史故障处理工具 |
| `scripts/maintenance/` | 文档等维护工具 |
| `examples/config/` | 配置示例；不能替代真实运行配置 |
| `tests/fixtures/` | 回归测试配置夹具 |
| `tests/test-websocket.sh` | 手动 WebSocket 联调脚本；会访问运行站点，需单独配置测试环境 |
| `docker/` | 备用 Dockerfile；构建上下文仍为仓库根目录 |

默认 `Dockerfile`、`docker-compose.yml`、`sslcat.conf` 和 systemd 服务模板保留在根目录，避免改变现有部署入口。`install.sh`、`install-sslcat.sh`、`upgrade.sh` 保留公开调用地址。`dev.sh`、`local.sh` 与 `build-linux-static.sh` 保留开发构建入口。

## 调用示例

在仓库根目录执行：

```bash
docker build -f docker/Dockerfile.cgo -t sslcat-cgo:local .
./sslcat --config tests/fixtures/test-valid-config.json
```

历史报告保留当时的诊断和结论，不应当作当前测试通过的凭据。诊断和故障修复脚本可能操作远端或服务，整理时仅做静态检查，不执行这些操作。

## 本地文件

未跟踪的运行配置、数据目录和凭据不纳入迁移。旧的构建产物和测试日志可放入已有的 `build/`、`dist/`、`test-results/` 等忽略目录；保留运行入口 `./sslcat`，避免影响正在使用的工作区。
