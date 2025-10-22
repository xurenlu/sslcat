# Git SSH 部署功能实现总结

## 概述

本次实现完成了完整的 Git SSH 收包和应用部署功能，类似于 Dokku/Heroku 的 git push 部署体验。

## 已实现功能

### 1. Git 钩子生成函数 ✅

实现了三个关键的 Git 钩子生成函数：

- **`generatePreReceiveHook()`**: 推送前验证钩子
  - 检查推送大小限制（默认100MB）
  - 记录推送信息到日志
  - 验证推送合法性

- **`generateUpdateHook()`**: 分支更新钩子
  - 记录分支更新信息
  - 支持分支保护逻辑扩展

- **`generatePostReceiveHook()`**: 推送后处理钩子
  - 自动更新工作目录
  - 获取提交信息
  - 触发自动部署流程
  - 创建部署触发文件

- **`generateReceivePackWrapper()`**: Git receive-pack 包装脚本
  - 记录 SSH 连接信息
  - 包装 git-receive-pack 调用

### 2. 自动创建应用逻辑 ✅

实现了 `ProcessGitPush()` 函数，支持：

- **自动创建应用**: 当推送的应用不存在时，自动调用 `CreateApp()` 创建新应用
- **裸仓库初始化**: 自动创建 bare repository 和工作目录
- **Git 钩子设置**: 自动配置所有必要的 Git 钩子
- **部署触发**: 推送完成后自动触发构建和部署流程

### 3. SSH 密钥绑定管理 ✅

实现了完整的 SSH 密钥与应用绑定关系管理：

- **`BindKeyToApp()`**: 绑定 SSH 密钥到指定应用
- **`UnbindKeyFromApp()`**: 解绑 SSH 密钥
- **`CheckPushPermission()`**: 检查推送权限
  - 如果应用未设置密钥限制，允许所有已添加的密钥推送
  - 如果设置了密钥限制，只允许绑定的密钥推送

**数据结构扩展**:
```go
type GitApp struct {
    // ... 其他字段
    AllowedKeys []string `json:"allowed_keys,omitempty"` // 允许推送的SSH密钥指纹列表
}
```

### 4. 推送记录和历史管理 ✅

实现了完整的推送记录系统：

**新增数据结构**:
```go
type PushRecord struct {
    ID            string    `json:"id"`
    AppName       string    `json:"app_name"`
    PusherKey     string    `json:"pusher_key"`      // SSH密钥指纹
    PusherName    string    `json:"pusher_name"`     // 推送者名称
    CommitHash    string    `json:"commit_hash"`     // 提交哈希
    CommitMessage string    `json:"commit_message"`  // 提交消息
    RefName       string    `json:"ref_name"`        // 分支/标签名
    Status        string    `json:"status"`          // pending/success/failed
    StartTime     time.Time `json:"start_time"`      // 推送开始时间
    EndTime       time.Time `json:"end_time"`        // 推送结束时间
    Duration      int64     `json:"duration"`        // 推送耗时（毫秒）
    ErrorMessage  string    `json:"error_message"`   // 错误信息
    LogFile       string    `json:"log_file"`        // 日志文件路径
    PushSize      int64     `json:"push_size"`       // 推送大小（字节）
    ClientIP      string    `json:"client_ip"`       // 客户端IP
}
```

**管理函数**:
- **`AddPushRecord()`**: 添加推送记录，自动限制历史数量（最多100条）
- **`GetPushHistory()`**: 获取推送历史，支持数量限制
- **`UpdatePushRecordStatus()`**: 更新推送记录状态

### 5. 构建失败反馈 ✅

钩子脚本已支持构建失败返回非零状态码：

- `pre-receive` 钩子中检测到问题时返回 `exit 1`
- 推送大小超限时拒绝推送并返回错误
- 构建失败时记录错误信息到推送记录

### 6. 推送限制 ✅

实现了多种推送限制：

- **推送大小限制**: 在 `pre-receive` 钩子中检查，默认限制为 100MB
- **并发限制**: 通过 Go 协程和 mutex 控制并发推送
- **超时限制**: 使用 `context.WithTimeout` 控制构建超时（默认300秒）
- **历史记录限制**: 自动清理旧记录，只保留最近100条

### 7. 部署触发监听 ✅

实现了 `WatchDeployTriggers()` 函数：

- 每2秒扫描一次 `/tmp` 目录下的部署触发文件
- 自动解析触发信息（应用名、提交哈希、分支名、提交消息）
- 触发部署后自动清理触发文件
- 在 `GitServer.Start()` 中自动启动监听协程

### 8. Web API 接口 ✅

新增了以下 API 接口：

**推送历史相关**:
- `GET /api/git-server/push-history?app={app_name}&limit={limit}` - 获取推送历史

**SSH 密钥绑定相关**:
- `POST /api/git-server/app/bind-key` - 绑定SSH密钥到应用
  ```json
  {
    "app_name": "myapp",
    "key_fingerprint": "SHA256:xxxxx"
  }
  ```
- `POST /api/git-server/app/unbind-key` - 解绑SSH密钥
  ```json
  {
    "app_name": "myapp",
    "key_fingerprint": "SHA256:xxxxx"
  }
  ```

## 使用流程

### 1. 设置 SSH 环境

```bash
# 1. 启动 SSLcat（会自动尝试创建 git 用户和设置 SSH 配置）
./sslcat
# 或者如果需要 root 权限自动创建用户：
sudo ./sslcat

# 如果自动创建失败，可以手动创建 git 用户：
sudo useradd -r -s /bin/bash -m -d /home/git git

# 2. 重启 sshd 服务（仅首次需要，使 SSH 配置生效）
sudo systemctl restart sshd

# 3. 添加 SSH 公钥
curl -X POST http://localhost:8080/admin/api/git-server/ssh-key/add \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-dev-key",
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB..."
  }'
```

### 2. 创建应用（可选，推送时会自动创建）

```bash
curl -X POST http://localhost:8080/admin/api/git-server/app/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "myapp"
  }'
```

### 3. Git 推送部署

```bash
# 在项目目录中
git remote add sslcat ssh://git@your-server/myapp
git push sslcat main

# 推送过程会：
# 1. 验证推送大小
# 2. 检查 SSH 密钥权限
# 3. 更新工作目录
# 4. 自动检测应用类型
# 5. 执行构建和部署
# 6. 记录推送历史
```

### 4. 查看推送历史

```bash
curl http://localhost:8080/admin/api/git-server/push-history?app=myapp&limit=10
```

### 5. 绑定 SSH 密钥到应用（可选，用于限制推送权限）

```bash
curl -X POST http://localhost:8080/admin/api/git-server/app/bind-key \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "myapp",
    "key_fingerprint": "AAAAB3NzaC1yc2EAAAADAQABAAAB"
  }'
```

## 目录结构

```
/data/repos/
├── myapp/
│   ├── git/
│   │   ├── repo.git/          # 裸仓库
│   │   │   ├── hooks/
│   │   │   │   ├── pre-receive
│   │   │   │   ├── update
│   │   │   │   ├── post-receive
│   │   │   │   └── receive-pack
│   │   │   └── config
│   │   └── repo/              # 工作目录
│   └── logs/
│       ├── deploy-2024-01-01.log
│       └── push-2024-01-01.log
└── apps.json                  # 应用配置持久化
```

## 安全特性

1. **SSH 密钥认证**: 所有推送都需要配置的 SSH 密钥
2. **密钥绑定**: 支持将特定密钥绑定到特定应用，实现精细化权限控制
3. **推送大小限制**: 防止过大的推送占用资源
4. **审计日志**: 完整记录所有推送操作和部署历史
5. **SSH 隔离**: Git 用户只能执行 git-shell 命令，无法登录 shell

## 支持的应用类型

- Node.js (检测 `package.json`)
- Python (检测 `requirements.txt`)
- Go (检测 `go.mod`)
- PHP (检测 `composer.json`)
- Docker (检测 `Dockerfile`)
- Static HTML/CSS/JS (检测 `index.html`)

## 配置文件

应用配置会自动保存到 `{ReposDir}/apps.json`:

```json
{
  "myapp": {
    "name": "myapp",
    "git_path": "/data/repos/myapp/git",
    "bare_repo": "/data/repos/myapp/git/repo.git",
    "repo_dir": "/data/repos/myapp/git/repo",
    "domain": "myapp.localhost",
    "port": 8001,
    "status": "running",
    "allowed_keys": ["SHA256:xxxxx"],
    "push_history": [
      {
        "id": "push_1704067200",
        "app_name": "myapp",
        "pusher_key": "SHA256:xxxxx",
        "commit_hash": "abc123",
        "status": "success",
        ...
      }
    ]
  }
}
```

## 注意事项

1. **Git 用户自动创建**: 
   - ✅ 启动时会自动尝试创建 git 用户（使用标准的 `/home/git` 目录）
   - ⚠️ 需要 root/sudo 权限才能自动创建
   - 💡 如果权限不足，会显示友好提示，可手动创建后再启动

2. **SSH 服务器配置**: 首次启用需要重启 SSHD 以应用配置更改
   ```bash
   sudo systemctl restart sshd
   ```

3. **文件权限**: 
   - Git 用户 home: `/home/git`（标准位置）
   - SSH 密钥目录: `./data/runners/keys/ssh`（SSLcat 管理）
   - Git 仓库目录: `./data/runners/git`（SSLcat 管理）

4. **防火墙**: 确保 SSH 端口（默认22）对外开放

## 未来扩展

计划中的功能（TODO）：

- [ ] 多分支部署支持
- [ ] 预览环境（每个分支独立环境）
- [ ] Webhook 通知（Slack、Discord、钉钉等）
- [ ] 部署回滚功能
- [ ] 蓝绿部署
- [ ] A/B 测试支持
- [ ] 自定义构建脚本（Buildpack）
- [ ] 资源配额限制（CPU、内存、磁盘）

## 参考

本实现参考了以下项目：

- Dokku: https://github.com/dokku/dokku
- Heroku: https://www.heroku.com/
- Gitea: https://gitea.io/

## 相关文件

- `/Users/rocky/Sites/sslcat/internal/runner/git_server.go` - Git 服务器核心实现
- `/Users/rocky/Sites/sslcat/internal/runner/realtime_logs.go` - 实时日志流
- `/Users/rocky/Sites/sslcat/internal/web/api_runners.go` - API 接口
- `/Users/rocky/Sites/sslcat/internal/web/server.go` - 路由注册
- `/Users/rocky/Sites/sslcat/docs/git-deploy-ssh-plan.md` - 原始计划文档

