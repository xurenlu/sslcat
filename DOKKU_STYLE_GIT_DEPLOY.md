# Dokku 风格 Git 部署功能

## 功能概述

SSLcat 现在支持 Dokku 风格的 Git 部署，可以通过 `git push` 自动创建不存在的应用！

## 核心特性

### ✅ 自动创建应用
- **无需预先创建**：直接 `git push git@host:newapp.git` 即可
- **智能检测**：如果应用不存在，自动通过 API 创建
- **透明部署**：创建后立即开始部署流程

### ✅ Dokku 风格实现
- **SSH Command Wrapper**：使用 `command=` 参数拦截 Git 命令
- **安全限制**：自动添加 `no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding`
- **密钥隔离**：每个密钥独立管理，互不影响

### ✅ 向后兼容
- **旧密钥继续工作**：已有的标准格式密钥不受影响
- **自动识别**：系统自动识别密钥格式
- **平滑升级**：无需修改现有配置

## 工作原理

### 1. 标准 SSH 流程 vs SSLcat 流程

**标准 SSH + git-shell**:
```
git push → SSH → git-shell → git-receive-pack → 仓库
```

**SSLcat Dokku 风格**:
```
git push → SSH → sslcat-git-hook → 检查/创建应用 → git-receive-pack → 仓库
```

### 2. authorized_keys 格式

**标准格式**:
```
# my-key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... user@host
```

**Dokku 风格（SSLcat 新格式）**:
```
# my-key
command="/usr/local/bin/sslcat-git-hook my-key",no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... user@host
```

### 3. Wrapper 脚本流程

```bash
sslcat-git-hook 接收 SSH 命令
    ↓
解析 SSH_ORIGINAL_COMMAND
提取应用名称（如 "appname.git" → "appname"）
    ↓
检查应用是否存在
    ├─ 存在 → 直接转发给 git-receive-pack
    └─ 不存在 → 调用 API 创建应用
        ↓
    等待创建完成（2秒）
        ↓
    验证创建成功
        ↓
    转发给 git-receive-pack
```

## 安装配置

### 方法 1：自动安装（推荐）

```bash
# 在 SSLcat 目录下执行
cd /opt/sslcat
sudo ./scripts/install-git-hook.sh
```

### 方法 2：手动安装

```bash
# 1. 复制 wrapper 脚本
sudo cp scripts/sslcat-git-hook /usr/local/bin/
sudo chmod +x /usr/local/bin/sslcat-git-hook

# 2. 配置环境变量（可选）
sudo -u git nano ~/.bashrc

# 添加：
export SSLCAT_API_URL='http://localhost:9942/sslcat-panel2'
export SSLCAT_REPOS_DIR='/opt/sslcat/data/runners/git'
```

### 配置说明

可通过环境变量自定义配置：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SSLCAT_API_URL` | `http://localhost:9942/sslcat-panel2` | SSLcat API 地址 |
| `SSLCAT_REPOS_DIR` | `/opt/sslcat/data/runners/git` | Git 仓库存储目录 |

## 使用示例

### 场景 1：推送到新应用（自动创建）

```bash
# 1. 本地初始化项目
mkdir my-new-app
cd my-new-app
git init
echo "Hello SSLcat!" > index.html
git add .
git commit -m "Initial commit"

# 2. 添加 SSLcat 远程仓库
git remote add sslcat git@your-server:my-new-app.git

# 3. 直接推送（应用会自动创建！）
git push sslcat main
```

**预期输出**:
```
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Writing objects: 100% (3/3), 245 bytes, done.
Total 3 (delta 0), reused 0 (delta 0)
remote: [sslcat-git-hook] SSH_ORIGINAL_COMMAND: git-receive-pack 'my-new-app.git'
remote: [sslcat-git-hook] Parsed command: git-receive-pack, app: my-new-app
remote: [sslcat-git-hook] 应用 'my-new-app' 不存在，正在自动创建...
remote: [sslcat-git-hook] ✓ 应用 'my-new-app' 创建成功
remote: [sslcat-git-hook] ✓ 验证通过，应用已就绪
remote: [sslcat-git-hook] 执行: git-receive-pack '/opt/sslcat/data/runners/git/my-new-app/git/repo.git'
remote: 
remote: ╔═══════════════════════════════════════════════════════════════╗
remote: ║                    SSLcat Git Deploy                          ║
remote: ╚═══════════════════════════════════════════════════════════════╝
remote: 
remote: Application: my-new-app
remote: ...部署日志...
To your-server:my-new-app.git
 * [new branch]      main -> main
```

### 场景 2：推送到已存在的应用

```bash
git push sslcat main
```

**预期输出**:
```
remote: [sslcat-git-hook] 应用 'my-new-app' 已存在
remote: [sslcat-git-hook] 执行: git-receive-pack ...
remote: -----> Deploying application
...
```

### 场景 3：Clone 不存在的应用

```bash
git clone git@your-server:another-app.git
```

**预期输出**:
```
Cloning into 'another-app'...
remote: [sslcat-git-hook] ERROR: 应用 'another-app' 不存在且不是 push 操作，无法自动创建
fatal: Could not read from remote repository.
```

**说明**: 只有 `git push` 会自动创建应用，`git clone` 不会。

## 旧密钥迁移

### 自动迁移（未来版本）

计划在未来版本中添加自动迁移工具。

### 手动迁移

如果您已有旧格式的 SSH 密钥，有两种方式：

**方式 1：保持不变**（推荐）
- 旧密钥继续正常工作
- 只是不支持自动创建应用功能
- 新添加的密钥会使用 Dokku 风格

**方式 2：重新添加**
```bash
# 1. 删除旧密钥
curl -X DELETE "http://localhost:9942/sslcat-panel2/api/git-server/ssh-key/remove?fingerprint=xxx"

# 2. 重新添加（会自动使用新格式）
curl -X POST http://localhost:9942/sslcat-panel2/api/git-server/ssh-key/add \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-key",
    "public_key": "ssh-rsa AAAAB3..."
  }'
```

## 故障排查

### 问题 1：wrapper 脚本未找到

**错误**:
```
bash: /usr/local/bin/sslcat-git-hook: No such file or directory
```

**解决**:
```bash
# 安装 wrapper 脚本
sudo ./scripts/install-git-hook.sh
```

### 问题 2：API 连接失败

**错误**:
```
remote: [sslcat-git-hook] ERROR: 创建应用失败
remote: [sslcat-git-hook] API 响应: curl: (7) Failed to connect...
```

**解决**:
```bash
# 检查 SSLcat 服务是否运行
systemctl status sslcat

# 检查 API 地址配置
sudo -u git bash -c 'echo $SSLCAT_API_URL'
```

### 问题 3：权限问题

**错误**:
```
remote: [sslcat-git-hook] ERROR: 仓库路径不存在
```

**解决**:
```bash
# 检查目录权限
ls -la /opt/sslcat/data/runners/git/

# 确保 git 用户可以访问
sudo chown -R git:git /opt/sslcat/data/runners/git/
```

### 问题 4：调试模式

启用详细日志：

```bash
# 编辑 wrapper 脚本
sudo nano /usr/local/bin/sslcat-git-hook

# 在文件开头添加：
set -x  # 启用调试输出

# 查看 SSH 日志
sudo tail -f /var/log/auth.log  # Debian/Ubuntu
sudo tail -f /var/log/secure    # CentOS/RHEL
```

## 与 Dokku 对比

| 特性 | SSLcat | Dokku |
|------|--------|-------|
| 自动创建应用 | ✅ | ✅ |
| SSH Command Wrapper | ✅ | ✅ |
| 安全限制 | ✅ | ✅ |
| 实时部署日志 | ✅ | ✅ |
| Web 管理界面 | ✅ | ❌ |
| 内置 SSL 管理 | ✅ | ✅ |
| 多语言支持 | ✅ | ✅ |
| 自托管 | ✅ | ✅ |
| Buildpack 支持 | 计划中 | ✅ |
| Docker 支持 | ✅ | ✅ |
| 插件系统 | 计划中 | ✅ |

## 实现细节

### Wrapper 脚本位置
- **系统路径**: `/usr/local/bin/sslcat-git-hook`
- **源码路径**: `scripts/sslcat-git-hook`

### API 端点
- **创建应用**: `POST /sslcat-panel2/api/git-server/apps`
- **请求格式**: `{"name":"appname","auto_ssl":true}`

### 文件修改
- `internal/runner/git_server.go:2082-2133` - AddSSHKey 添加 command= 参数
- `internal/runner/git_server.go:2170-2225` - ListSSHKeys 支持新格式
- `scripts/sslcat-git-hook` - Wrapper 脚本实现

## 安全考虑

### SSH 限制选项
```
no-agent-forwarding    # 禁止 SSH agent 转发
no-user-rc            # 禁止执行用户 RC 文件
no-X11-forwarding     # 禁止 X11 转发
no-port-forwarding    # 禁止端口转发
```

### Command 限制
- 只允许执行 `sslcat-git-hook` 脚本
- 用户无法获得 shell 访问权限
- 所有命令都经过 wrapper 验证

### API 调用
- Wrapper 只能调用创建应用的 API
- API 在内部网络访问（localhost）
- 无需额外认证（基于 SSH 密钥信任）

## 未来改进

- [ ] 支持环境变量配置（部署时自动设置）
- [ ] 支持自定义 AutoSSL 设置
- [ ] 支持部署策略选择（Docker/Native）
- [ ] 添加速率限制（防止恶意创建）
- [ ] 支持应用模板（预设配置）
- [ ] 自动迁移旧密钥工具
- [ ] WebSocket 实时日志集成

## 相关文档

- [Git Deploy 快速入门](docs/git-deploy-quickstart.md)
- [Git SSH 符号链接修复](GIT_SSH_SYMLINK_FIX.md)
- [Git 用户自动创建](GIT_USER_AUTO_CREATE.md)
- [Git Push 实时部署日志](GIT_PUSH_REALTIME_DEPLOY.md)

## 贡献

欢迎提交 PR 改进此功能！特别是：
- 更完善的错误处理
- 更多配置选项
- 性能优化
- 安全加固

## 许可证

与 SSLcat 主项目相同。

---

**注意**: 这是 v1.3.5-rc24 新增的实验性功能。如有问题请通过 GitHub Issues 反馈。

