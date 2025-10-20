# SSH 服务自动重启功能

## 功能概述

为 Git Deploy 服务添加了 SSH 服务自动重启功能，解决首次启用时需要手动重启 sshd 的问题。

## 实现方案

### 1. 后端自动重启

#### 文件：`internal/runner/git_server.go`

**在 `setupSSHUser()` 方法中添加自动重启**：
```go
// 尝试自动重启 sshd 服务
if err := gs.restartSSHD(); err != nil {
    gs.logger.Warnf("自动重启 SSH 服务失败: %v，请手动执行: sudo systemctl restart sshd", err)
} else {
    gs.logger.Info("SSH 服务已自动重启")
}
```

**新增 `restartSSHD()` 方法**：
- 自动检测操作系统类型（Linux/macOS）
- Linux: 使用 `systemctl restart sshd`
- macOS: 使用 `launchctl unload/load`

**新增 `detectOSType()` 方法**：
- 检测 systemctl 命令（Linux）
- 检测 launchctl 命令（macOS）
- 默认返回 linux

### 2. API 接口

#### 文件：`internal/web/api_runners.go`

**新增 `RestartSSHD()` API 方法**：
```go
func (api *GitServerAPI) RestartSSHD(w http.ResponseWriter, r *http.Request) {
    if api.server == nil {
        api.writeError(w, "Git Deploy 服务未启用", http.StatusServiceUnavailable)
        return
    }

    if err := api.server.RestartSSHD(); err != nil {
        api.logger.Errorf("重启 SSH 服务失败: %v", err)
        api.writeError(w, "重启 SSH 服务失败: "+err.Error(), http.StatusInternalServerError)
        return
    }

    response := map[string]interface{}{
        "success": true,
        "message": "SSH 服务重启成功",
    }
    api.writeJSON(w, response)
}
```

#### 文件：`internal/web/server.go`

**添加路由**：
```go
// SSH 服务管理 API 路由
s.mux.HandleFunc(s.config.AdminPrefix+"/api/git-server/restart-sshd", gitAPI.RestartSSHD)
```

### 3. 前端界面

#### 文件：`frontend/src/pages/GitServerManagement.tsx`

**添加重启提示和按钮**：
```tsx
{/* SSH 服务重启提示 */}
{config.enabled && (
  <Alert status="info" mb={6}>
    <AlertIcon />
    <Box flex="1">
      <AlertTitle>需要重启 SSH 服务</AlertTitle>
      <AlertDescription>
        首次启用 Git Deploy 服务后，需要重启 SSH 服务以使配置生效。
        <br />
        <Text as="span" fontWeight="bold" color="blue.600">
          Linux: sudo systemctl restart sshd
        </Text>
        <br />
        <Text as="span" fontWeight="bold" color="blue.600">
          macOS: sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist && sudo launchctl load /System/Library/LaunchDaemons/ssh.plist
        </Text>
      </AlertDescription>
    </Box>
    <Button
      colorScheme="blue"
      size="sm"
      onClick={handleRestartSSHD}
      isLoading={loading}
    >
      自动重启 SSH
    </Button>
  </Alert>
)}
```

**新增 `handleRestartSSHD()` 函数**：
- 调用 `/api/git-server/restart-sshd` API
- 显示成功/失败提示
- 处理加载状态

## 工作流程

### 自动重启流程

1. **启动 Git Deploy 服务**
   ```bash
   ./sslcat
   ```

2. **自动执行**：
   - 创建 git 用户（如果不存在）
   - 设置 SSH 配置
   - **自动尝试重启 sshd 服务**

3. **日志输出**：
   ```
   INFO git 用户创建成功，home 目录: /home/git
   INFO SSH 用户配置完成
   INFO SSH 服务已自动重启
   INFO Git 服务器已启动
   ```

### 手动重启流程

如果自动重启失败，用户可以通过以下方式：

1. **前端界面**：
   - 在 Git Server 管理页面点击"自动重启 SSH"按钮
   - 系统会调用 API 尝试重启

2. **命令行**：
   ```bash
   # Linux
   sudo systemctl restart sshd
   
   # macOS
   sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
   sudo launchctl load /System/Library/LaunchDaemons/ssh.plist
   ```

## 支持的操作系统

### Linux 系统
- **检测方式**：检查 `systemctl` 命令是否存在
- **重启命令**：`systemctl restart sshd`
- **验证**：`systemctl --version`

### macOS 系统
- **检测方式**：检查 `launchctl` 命令是否存在
- **重启命令**：
  ```bash
  launchctl unload /System/Library/LaunchDaemons/ssh.plist
  launchctl load /System/Library/LaunchDaemons/ssh.plist
  ```

## 错误处理

### 权限不足
```
WARN 自动重启 SSH 服务失败: 权限不足（需要 root/sudo 权限），请手动执行: sudo systemctl restart sshd
```

### 命令不存在
```
WARN 自动重启 SSH 服务失败: 不支持的操作系统: unknown，请手动执行: sudo systemctl restart sshd
```

### 重启失败
```
WARN 自动重启 SSH 服务失败: 重启 SSH 服务失败: exit status 1，请手动执行: sudo systemctl restart sshd
```

## 安全考虑

1. **权限要求**：重启 sshd 需要 root 权限
2. **服务中断**：重启会短暂中断 SSH 连接
3. **错误恢复**：如果重启失败，会提供手动命令

## 测试验证

### 1. 编译测试
```bash
cd /Users/rocky/Sites/sslcat
go build -o sslcat-test .
```

### 2. 功能测试
```bash
# 启动服务
./sslcat

# 检查日志
tail -f data/sslcat.log | grep -i ssh

# 测试 API
curl -X POST http://localhost:8080/sslcat-panel2/api/git-server/restart-sshd
```

### 3. 前端测试
1. 访问 Git Server 管理页面
2. 启用 Git Deploy 服务
3. 查看是否显示重启提示
4. 点击"自动重启 SSH"按钮
5. 验证是否显示成功提示

## 相关文件

- `internal/runner/git_server.go` - 核心重启逻辑
- `internal/web/api_runners.go` - API 接口
- `internal/web/server.go` - 路由配置
- `frontend/src/pages/GitServerManagement.tsx` - 前端界面

## 更新日期

2025-10-02

## 版本

v1.3.5-rc10
