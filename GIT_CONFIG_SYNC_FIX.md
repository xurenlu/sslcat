# Git Server 配置同步修复

## 📋 问题描述

**Bug**: 前端界面修改 Git Server 开关状态时，只保存到了 `./data/repos/server_config.json`，没有同步到主配置文件 `/etc/sslcat/sslcat.conf` 中的 `runners.git.enabled`。

**影响**: 
- 前端显示 Git Deploy 已启用
- 但重启服务后，日志显示 `git_server.not_enabled`
- Git Server 实际未启动

## 🔧 修复内容

### 修改文件
`internal/runner/git_server.go` 的 `UpdateServerConfig()` 方法

### 修改前（第 578-592 行）
```go
// UpdateServerConfig 更新服务器配置
func (gs *GitServer) UpdateServerConfig(config *GitServerConfig) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	gs.serverConfig = config

	// 保存配置到文件
	if err := gs.saveServerConfig(); err != nil {
		return fmt.Errorf(gs.translator.T("git_server.save_config_failed")+": %w", err)
	}

	gs.logger.Info(gs.translator.T("git_server.config_updated"))
	return nil
}
```

### 修改后（第 578-604 行）
```go
// UpdateServerConfig 更新服务器配置
func (gs *GitServer) UpdateServerConfig(config *GitServerConfig) error {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	gs.serverConfig = config

	// 同步更新主配置文件中的 runners.git.enabled
	// 这样重启服务后配置才会生效
	gs.config.Runners.Git.Enabled = config.Enabled
	
	// 保存主配置文件
	if err := gs.config.Save(gs.config.ConfigFile); err != nil {
		gs.logger.Warnf("保存主配置文件失败: %v", err)
		// 继续执行，不中断流程
	} else {
		gs.logger.Info("主配置文件已更新")
	}

	// 保存 Git Server 内部配置到文件
	if err := gs.saveServerConfig(); err != nil {
		return fmt.Errorf(gs.translator.T("git_server.save_config_failed")+": %w", err)
	}

	gs.logger.Info(gs.translator.T("git_server.config_updated"))
	return nil
}
```

## 🎯 修复逻辑

1. **同步内存配置**: 将前端传来的 `enabled` 状态同步到 `gs.config.Runners.Git.Enabled`
2. **保存主配置**: 调用 `gs.config.Save()` 将配置持久化到主配置文件
3. **保存内部配置**: 继续保存 Git Server 的内部配置到 `server_config.json`
4. **容错处理**: 如果主配置文件保存失败（如权限问题），记录警告但不中断流程

## ✅ 验证方法

### 方法一：通过前端界面测试

1. 登录 SSLcat 管理面板
2. 进入 Git Server 管理页面
3. 点击"服务器配置"按钮
4. 切换"启用 Git Server"开关
5. 保存配置
6. 检查主配置文件：
   ```bash
   grep -A 10 '"runners"' /etc/sslcat/sslcat.conf
   ```
7. 应该看到 `"enabled"` 的值已改变

### 方法二：通过 API 测试

```bash
# 关闭 Git Server
curl -X PUT http://localhost:8080/sslcat-panel2/api/git-server/config \
  -H "Content-Type: application/json" \
  -d '{"enabled": false, "port": 22, ...}'

# 检查配置文件
grep -A 10 '"runners"' /etc/sslcat/sslcat.conf | grep enabled

# 重新开启
curl -X PUT http://localhost:8080/sslcat-panel2/api/git-server/config \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "port": 22, ...}'

# 再次检查
grep -A 10 '"runners"' /etc/sslcat/sslcat.conf | grep enabled
```

### 方法三：重启验证

```bash
# 在前端开启 Git Server
# 然后重启服务
sudo systemctl restart sslcat

# 查看日志，应该看到：
# "Git 服务器已启动" 或 "Git server started"
# 而不是 "git_server.not_enabled"
sudo journalctl -u sslcat -f | grep git
```

## 📝 涉及的配置

### 主配置文件 (`/etc/sslcat/sslcat.conf`)
```json
{
  "runners": {
    "git": {
      "enabled": true,  // ← 这个值现在会被同步更新
      "repos_dir": "/opt/sslcat/repos",
      "max_concurrent": 5,
      "clone_timeout": 300,
      "auto_cleanup": true,
      "cleanup_interval": 86400
    }
  }
}
```

### Git Server 内部配置 (`./data/repos/server_config.json`)
```json
{
  "enabled": true,  // ← 内部配置
  "port": 22,
  "webhook": "",
  "defaultBranch": "main",
  "domain_suffix": "localhost",
  "port_range": [8000, 9000],
  "welcomeMessage": "欢迎使用 SSLcat Git 部署平台！",
  "autoSSL": true,
  "sslEmail": "",
  "defaultStrategy": "auto",
  "buildTimeout": 300,
  "autoDomain": true
}
```

## 🚀 部署说明

1. **编译新版本**:
   ```bash
   cd /Users/rocky/Sites/sslcat
   go build -o sslcat main.go
   ```

2. **部署到服务器**:
   ```bash
   # 停止服务
   ssh iZbp1ihxiywy5jgh315hb5Z "sudo systemctl stop sslcat"
   
   # 上传新版本
   scp sslcat iZbp1ihxiywy5jgh315hb5Z:/opt/sslcat/
   
   # 启动服务
   ssh iZbp1ihxiywy5jgh315hb5Z "sudo systemctl start sslcat"
   ```

3. **验证修复**:
   - 通过前端界面测试配置开关
   - 检查主配置文件是否同步更新
   - 重启服务验证配置是否生效

## 📅 修复信息

- **日期**: 2025-10-04
- **版本**: 下一个 release (建议标记为 bugfix)
- **影响范围**: Git Deploy 功能
- **向后兼容**: ✅ 是（不影响现有功能）

## 🔍 相关代码位置

- `internal/runner/git_server.go:578-604` - UpdateServerConfig 方法
- `internal/config/config.go:994-1033` - Config.Save 方法
- `internal/web/api_runners.go:237-256` - API 接口
- `frontend/src/pages/GitServerManagement.tsx:706-730` - 前端调用

