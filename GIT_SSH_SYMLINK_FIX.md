# Git SSH 符号链接自动创建功能

## 问题背景

在使用 SSLcat 的 Git Deploy 功能时，用户通过 SSH 推送代码会遇到以下错误：

```bash
git push git@host:appname.git
fatal: 'appname.git' does not appear to be a git repository
```

### 根本原因

1. **仓库存储位置**：SSLcat 将 Git 仓库存储在 `{repos_dir}/{appname}/git/repo.git`
2. **git-shell 查找路径**：当用户执行 `git push git@host:appname.git` 时，git-shell 会在 git 用户的 home 目录（`/home/git/`）下查找 `appname.git`
3. **缺少路径映射**：两者之间没有建立连接，导致 git-shell 找不到仓库

## 解决方案

通过在 git 用户的 home 目录下自动创建符号链接，指向实际的裸仓库位置：

```
/home/git/appname.git -> /path/to/repos/appname/git/repo.git
```

## 实现细节

### 1. 创建应用时自动建立符号链接

在 `CreateApp` 函数中添加了符号链接创建逻辑：

```go
// 创建符号链接，让 git-shell 能够找到仓库
gs.logger.Debugf("  创建 Git SSH 符号链接...")
if err := gs.createGitSymlink(app); err != nil {
    gs.logger.Warnf("创建 Git SSH 符号链接失败: %v", err)
} else {
    gs.logger.Infof("  ✓ Git SSH 符号链接已创建")
}
```

### 2. 新增 createGitSymlink 函数

```go
// createGitSymlink 创建符号链接，让 git-shell 能够通过 SSH 访问仓库
func (gs *GitServer) createGitSymlink(app *GitApp) error {
    symlinkPath := filepath.Join(gs.sshHomeDir, app.Name+".git")
    targetPath := app.BareRepo
    
    // 检查并删除旧链接
    if _, err := os.Lstat(symlinkPath); err == nil {
        os.Remove(symlinkPath)
    }
    
    // 创建新链接
    if err := os.Symlink(targetPath, symlinkPath); err != nil {
        return fmt.Errorf("创建符号链接失败: %w", err)
    }
    
    // 设置所有者为 git 用户
    if gs.uid > 0 && gs.gid > 0 {
        os.Lchown(symlinkPath, gs.uid, gs.gid)
    }
    
    return nil
}
```

### 3. 启动时为现有应用补充符号链接

在 `loadApps` 函数中添加了检查和补充逻辑：

```go
// 为已存在的应用补充缺失的符号链接
gs.logger.Infof("检查并创建缺失的 Git SSH 符号链接...")
for _, app := range gs.apps {
    symlinkPath := filepath.Join(gs.sshHomeDir, app.Name+".git")
    if _, err := os.Lstat(symlinkPath); os.IsNotExist(err) {
        if err := gs.createGitSymlink(app); err != nil {
            gs.logger.Warnf("为应用 %s 创建符号链接失败: %v", app.Name, err)
        } else {
            gs.logger.Infof("已为应用 %s 补充 Git SSH 符号链接", app.Name)
        }
    }
}
```

### 4. 删除应用时清理符号链接

在 `DeleteApp` 函数中添加了清理逻辑：

```go
// 删除 Git SSH 符号链接
symlinkPath := filepath.Join(gs.sshHomeDir, appName+".git")
if _, err := os.Lstat(symlinkPath); err == nil {
    if err := os.Remove(symlinkPath); err != nil {
        gs.logger.Warnf("删除 Git SSH 符号链接失败: %v", err)
    } else {
        gs.logger.Infof("Git SSH 符号链接已删除: %s", symlinkPath)
    }
}
```

## 功能特点

1. **自动化**：创建应用时自动建立符号链接，无需手动操作
2. **向后兼容**：启动时自动为已存在的应用补充缺失的符号链接
3. **完整生命周期**：创建、更新、删除应用时都会正确处理符号链接
4. **权限管理**：自动设置符号链接的所有者为 git 用户
5. **容错性**：创建失败只会警告，不会影响应用的其他功能

## 使用方式

用户无需任何操作，功能会自动生效：

```bash
# 创建应用（通过 Web 界面或 API）
# SSLcat 会自动创建符号链接

# 推送代码
git remote add deploy git@your-server.com:appname.git
git push deploy main

# 删除应用（通过 Web 界面或 API）
# SSLcat 会自动清理符号链接
```

## 升级说明

对于已经部署的 SSLcat 实例：

1. **更新代码**：拉取最新代码并重新编译
2. **重启服务**：重启 SSLcat 服务
3. **自动修复**：启动时会自动为现有应用创建缺失的符号链接

无需手动干预！

## 注意事项

1. **权限要求**：SSLcat 进程需要有权限在 `/home/git/` 目录下创建符号链接
2. **root 权限**：如果 SSLcat 没有以 root 运行，符号链接的所有者设置可能会失败（但不影响功能）
3. **日志监控**：可以通过日志查看符号链接的创建情况

## 修改文件

- `internal/runner/git_server.go`
  - 修改 `CreateApp()` 函数：添加符号链接创建调用
  - 修改 `DeleteApp()` 函数：添加符号链接删除逻辑
  - 修改 `loadApps()` 函数：添加符号链接补充逻辑
  - 新增 `createGitSymlink()` 函数：实现符号链接创建逻辑

## 测试验证

```bash
# 1. 创建测试应用
curl -X POST http://localhost:9942/sslcat-panel2/api/git-server/app/create \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"name":"test-app","auto_ssl":false}'

# 2. 检查符号链接
ls -la /home/git/test-app.git

# 3. 测试 Git 推送
git push git@localhost:test-app.git main

# 4. 删除应用
curl -X DELETE http://localhost:9942/sslcat-panel2/api/git-server/apps/test-app \
  -u admin:password

# 5. 验证符号链接已删除
ls -la /home/git/test-app.git
```

## 相关文档

- [Git Deploy 快速入门](docs/git-deploy-quickstart.md)
- [Git 用户自动创建功能](GIT_USER_AUTO_CREATE.md)
- [Git Deploy 改进说明](GIT_DEPLOY_IMPROVEMENTS.md)

