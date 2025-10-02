# Git Deploy 功能改进

## 改进内容

### 1. 前端 - 添加复制命令按钮

**问题**：用户创建应用后，提示中的 Git 命令难以复制

**解决方案**：
- ✅ 在 Git 推送指令提示中添加复制按钮
- ✅ 点击按钮可一键复制所有命令到剪贴板
- ✅ 复制成功后显示提示消息

**文件**：`frontend/src/pages/GitServerManagement.tsx`

**改进后效果**：
```
┌─────────────────────────────────────────────┐
│ 推送代码到应用                               │
├─────────────────────────────────────────────┤
│ 在您的项目目录中执行：                       │
│ ┌───────────────────────────────────────┬─┐ │
│ │git remote add sslcat git@host:app.git│📋│ │
│ │git push sslcat main                   │  │ │
│ └───────────────────────────────────────┴─┘ │
└─────────────────────────────────────────────┘
```

### 2. 后端 - 自动创建目录

**问题**：
1. Git Deploy 服务未启用时，应用创建后无法保存（只存在内存中）
2. 刷新页面后应用消失
3. 必要的目录不会自动创建

**解决方案**：
- ✅ 在 `saveApps()` 方法中添加自动创建目录逻辑
- ✅ 使用 `os.MkdirAll()` 递归创建所有必要的父目录
- ✅ 添加日志记录，显示保存路径和应用数量

**文件**：`internal/runner/git_server.go`

**改进代码**：
```go
func (gs *GitServer) saveApps() error {
    // 确保目录存在
    if err := os.MkdirAll(gs.config.Runners.Git.ReposDir, 0755); err != nil {
        return fmt.Errorf("创建应用目录失败: %w", err)
    }

    appsFile := filepath.Join(gs.config.Runners.Git.ReposDir, "apps.json")
    // ... 保存逻辑 ...
    
    gs.logger.Infof("应用数据已保存到 %s (%d 个应用)", appsFile, len(gs.apps))
    return nil
}
```

### 3. 后端 API - 改进错误处理

**问题**：
- Git Deploy 服务未启用时，前端请求会返回不友好的错误
- 用户不知道如何解决问题

**解决方案**：
- ✅ 在 CreateApp API 中添加服务状态检查
- ✅ 返回友好的错误消息，明确告知如何启用服务
- ✅ 对目录创建错误提供更详细的提示

**文件**：`internal/web/api_runners.go`

**改进代码**：
```go
func (api *GitServerAPI) CreateApp(w http.ResponseWriter, r *http.Request) {
    // 检查 Git 服务器是否为 nil（未启用）
    if api.server == nil {
        api.writeError(w, 
            "Git Deploy 服务未启用，请在配置文件中启用 runners.git.enabled", 
            http.StatusServiceUnavailable)
        return
    }
    
    // ... 创建逻辑 ...
    
    if err != nil {
        // 提供更友好的错误消息
        errMsg := err.Error()
        if strings.Contains(errMsg, "目录") || strings.Contains(errMsg, "directory") {
            errMsg = "创建应用目录失败，请检查 runners.git.repos_dir 配置和目录权限: " + errMsg
        }
        api.writeError(w, "创建应用失败: "+errMsg, http.StatusInternalServerError)
        return
    }
}
```

## 配置修改

### 启用 Git Deploy 服务

在 `sslcat.conf` 和 `sslcat-dev.conf` 中添加/修改：

```json
{
  "runners": {
    "git": {
      "enabled": true,  // ✅ 改为 true
      "repos_dir": "./data/runners/git",
      "max_concurrent": 3,
      "clone_timeout": 300,
      "auto_cleanup": true,
      "cleanup_interval": 7200
    }
  }
}
```

## 使用流程

### 1. 启用 Git Deploy（仅需一次）

```bash
# 1. 配置文件中启用 runners.git.enabled = true
# 2. 重启后端服务
./dev.sh backend
```

### 2. 创建应用

1. 在管理面板访问 Git Server 页面
2. 点击"创建应用"
3. 填写应用名称
4. 点击复制按钮，复制 Git 命令
5. 在本地项目目录执行命令

### 3. 数据持久化

应用数据会自动保存到：
```
./data/runners/git/
├── apps.json              # 应用列表
├── server_config.json     # 服务器配置
└── {app-name}/           # 各应用目录
    ├── git/
    │   ├── repo.git/     # 裸仓库
    │   └── repo/         # 工作目录
    └── logs/             # 部署日志
```

## 测试验证

1. ✅ 创建应用后刷新页面，应用仍然存在
2. ✅ 可以点击复制按钮复制 Git 命令
3. ✅ 未启用 Git Deploy 时显示友好错误消息
4. ✅ 目录权限问题时提供详细错误信息

## 未来改进建议

1. 在前端添加 Git Deploy 服务状态指示器
2. 提供一键启用 Git Deploy 的按钮
3. 在创建应用前检查服务状态，提前提示用户
4. 添加应用数据导出/导入功能
5. 支持批量操作（删除、启用/禁用）

## 相关文件

- `frontend/src/pages/GitServerManagement.tsx` - 前端 Git 服务器管理页面
- `internal/web/api_runners.go` - 后端 API 处理器
- `internal/runner/git_server.go` - Git 服务器核心逻辑
- `sslcat.conf` / `sslcat-dev.conf` - 配置文件

## 更新日期

2025-10-03

