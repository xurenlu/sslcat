# SSLcat 仓库整体 Review 与修复计划

> 历史审查记录：下文的测试结果、统计与状态属于原审查基线，未在本次目录整理中重新确认。当前整改状态及验证边界以 [设计审查](design-review.md) 为准。

- 日期：2026-09-29
- 审查基线：分支 `fix/goroutine-monitor-false-positive`（HEAD `4c77fcae`）+ 工作区未提交变更
- 审查方法：`go build ./...`、`go vet ./...`、`go test ./...` 全量；注册路由与 handler 鉴权状态的静态交叉比对；仓库对象库与被跟踪文件统计；关键路径定点阅读

## 结论摘要

构建通过；`go vet` 仅 1 条告警；全量测试 6m46s 只有 1 个时间敏感型 flaky 失败。主要问题集中在**管理 API 缺少统一登录鉴权**（83 条已注册路由指向无鉴权 handler）与**编译产物被纳入版本控制**（`.git` 已达 1.29 GiB），前者是本次修复的首要目标。

## 高危

### H1 管理前缀下的 API 缺少统一登录鉴权

- 状态：代码已落盘（新增 `internal/web/admin_api_auth.go` 与测试，`internal/web/server.go:1502` 插入调用），构建与测试结果待取，尚未提交
- 证据：
  - `internal/web/server.go:1355-1361` 只有「是否跳过 WAF 检查」时才读 session，不构成鉴权
  - `internal/web/server_security.go:115` 的 `securityMiddleware` 只做 IP 黑名单、UA 与机器人过滤
  - 交叉比对 272 条注册路由，其中 83 条指向函数体内不存在任何凭据校验的 handler
  - 已抽查证实：`internal/web/api_bot_detection.go:83`、`internal/web/api_cache_stats.go:160`、`internal/web/server_http2.go:112`、`internal/web/server_http2.go:129`
  - 附带发现：`/api/cluster/settings` 已有会话鉴权（`internal/web/api_cluster.go:19`），但 `authorizeAPI` 不接受 `X-Cluster-Key`，而 Slave 正是以该头调用它（`internal/web/api_cluster.go:347-349`），因此集群连通性探测必然返回 403——属既有功能缺陷，与本次改造一并处理
- 复现：`curl -X POST -H 'Content-Type: application/json' -d '{"enabled":false,"domain":"example.com"}' https://<host>/sslcat-panel/api/bot-detection/config`，无需任何凭据即可改配置并落盘
- 影响：匿名可关闭 Bot 检测、删 WAF 白名单、清空缓存、开关 HTTP/2、改集群配置（含 `auth_key` 与 master 地址）
- 修法：在 `ServeHTTP` 分发给 `s.mux` 之前，对管理前缀下的 `/api/` 路径统一要求 session 或 Bearer token；公开端与使用独立鉴权机制的端点走白名单；集群对等端点补共享密钥校验
- 白名单（保持公开）：
  - `/api/auth/login`、`/api/auth/totp-login`、`/api/auth/logout`
  - `/api/settings/public`（`internal/web/server.go:814` 注释即写明供登录页使用）
  - `/api/captcha`、`/api/captcha/image`
  - `/api/webauthn/login/begin`、`/api/webauthn/login/finish`
  - 注意 `/api/webauthn/credentials` 与其 `delete` 属登录后操作，**不**入白名单
- 使用独立鉴权、必须列入白名单的端点：
  - `/api/cluster/export-certs`（自校验 `X-Cluster-Key`，`internal/web/api_cluster.go:134-138`）
  - 经全仓排查，`internal/web` 中使用自定义鉴权头的仅此一处，无 webhook 签名型入站端点

### H2 编译产物被纳入版本控制

- 状态：部分完成（`.gitignore` 已补齐，`git rm --cached` 待执行）
- 证据：`git ls-files` 中 `sslcat-static-linux-amd64`(51MB)、`tools/list_users`(8.7MB)、`tools/test_dns_config`(8.4MB)、`tools/test_web_api`(8MB)、`deploy/withssl-linux`(7.7MB)、`tools/test_sqlite`(6.4MB)；`git count-objects -vH` 显示 22 packs / 1.29 GiB
- 根因：现有 `.gitignore` 只有 `sslcat-linux-amd64` 与 `withssl-linux-amd64`，不匹配 `sslcat-static-linux-amd64` 与 `deploy/withssl-linux`；`tools/` 下只忽略了 `test-templates/`
- 修法：`git rm --cached` 移出并把上述路径补进 `.gitignore`；**不重写历史**（用户已确认），历史瘦身留待单独决策
- 进展：`.gitignore` 已加入 `/tools/list_users`、`/tools/test_dns_config`、`/tools/test_web_api`、`/tools/test_sqlite`、`/sslcat-static-linux-amd64`、`/deploy/withssl-linux`

## 中危

### M1 i18n 五种语言各缺 338 个 key

- 状态：待开始
- 证据：按顶层 key 统计，`en-us` 与 `zh-cn` 各 1927 且完全对称；`de-de`、`es-es`、`fr-fr`、`ja-jp`、`ru-ru` 各 1589
- 修法：补齐 338×5 条；注意 `frontend/src/i18n/languages/ja-jp.ts:1674` 起已有 `TODO` 占位，说明此前就是临时搪塞

### M2 前端构建脚本不清空产物目录

- 状态：待开始
- 证据：`scripts/build-frontend.sh` 用 `cp -r dist/* ../internal/assets/frontend/`，目标目录未清空；Vite 输出带哈希文件名，旧产物会持续累积，需人工删除
- 修法：复制前清空 `../internal/assets/frontend/assets/`（保留 `index.html` 由复制覆盖）

### M3 缓存过期测试时间敏感

- 状态：待开始
- 证据：`internal/cache/upstream_cache_test.go:405` 设 `defaultTTL = 100ms`，`:425` 紧接着要求立即命中；本轮全量测试失败、单独重跑 3 次全部通过
- 修法：TTL 放宽到秒级，或注入可控时钟

### M4 同名大小写文件跨平台冲突

- 状态：待开始
- 证据：`PRODUCT_OVERVIEW.md`(1794B) 与 `product-overview.md`(15621B) 同时被跟踪，仅差大小写
- 修法：合并为单一文件，保留信息更全的 `product-overview.md`

## 低危

### L1 god file

- `internal/runner/git_server.go` 6195 行、`internal/ssl/manager.go` 3212、`internal/proxy/manager.go` 2941、`internal/config/config.go` 2931
- 建议按职责拆分，从 `git_server.go` 起步（配置读写 / 应用 CRUD / 部署 / 清理）

### L2 重复工具函数

- `min` 6 处、`max` 2 处、`contains` 2 处；Go 1.25 已内置 `min`/`max`

### L3 其他

- `internal/loadbalancer/types.go:53` 未导出字段带 json tag（`go vet` 唯一告警）
- `/metrics` 裸注册于根路径（`internal/web/server.go:999`），完整公开；`internal/web/server_ml.go:92` 也将其列为免鉴权路径，属有意设计，**需确认是否符合预期**
- 忽略错误 184 处 `_ =` 与 159 处 `, _ :=`；`panic(` 3 处；`TODO/FIXME` 40 处
- 根目录 45 个 `.md`，多为一次性诊断报告；`GPU算力租赁业务选址综合评估报告.md`(154KB) 与 `Git-AI-Client-项目规划.md` 与项目无关
- 死代码：`internal/web/api_ml.go:100` 的 `RegisterRoutes`、`internal/web/api_deployments.go:29-32` 的路由注册均无调用方

## 附录：路由鉴权状态复现脚本

```python
import re, glob
AUTH = ('authorizeAPI','checkAuth','requireAuth','requireAdmin','GetSessionFromRequest',
        'getCurrentUser','sessionManager','validateToken')
state = {}
for path in sorted(glob.glob('internal/web/*.go')):
    if path.endswith('_test.go'):
        continue
    src = open(path, encoding='utf-8', errors='ignore').read()
    for m in re.finditer(r'^func \(s \*Server\) (handle\w+|api\w+)\(w http\.ResponseWriter, r \*http\.Request\)', src, re.M):
        n, s0 = m.group(1), m.start()
        nxt = src.find('\nfunc ', s0 + 1)
        body = src[s0: nxt if nxt > 0 else len(src)]
        state[n] = any(a in body for a in AUTH)
rows = []
for path in glob.glob('internal/web/server*.go'):
    src = open(path, encoding='utf-8', errors='ignore').read()
    for m in re.finditer(r's\.mux\.HandleFunc\(([^,]+),\s*s\.(\w+)\)', src):
        rows.append((m.group(1).strip(), m.group(2)))
noauth = [(p, h) for p, h in rows if state.get(h) is False]
print('路由总数 %d | 无鉴权 %d' % (len(rows), len(noauth)))
```
