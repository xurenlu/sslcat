# Git 用户自动创建功能

## 功能概述

在启用 Git Deploy 服务时，SSLcat 现在会**自动尝试创建 git 用户**，无需手动创建。

## 实现方案

### 1. 使用最佳实践的目录结构

```
/home/git/                              # Git 用户 home（标准 Linux 位置）✅
├── .ssh/                               # 系统 SSH 配置
├── .gitconfig                          # Git 全局配置
└── git-shell-commands/                # Git shell 命令

/path/to/sslcat/data/
├── runners/
│   ├── git/                           # Git 仓库目录（SSLcat 管理）
│   │   ├── apps.json                  # 应用配置
│   │   └── myapp/                     # 具体应用
│   │       ├── git/repo.git/         # 裸仓库
│   │       └── logs/                  # 部署日志
│   └── keys/
│       └── ssh/
│           └── authorized_keys        # SSH 密钥（SSLcat 管理）
└── certs/                             # SSL 证书
```

### 2. 代码改动

#### 修改 1: 在启动时自动创建用户

**文件**: `internal/runner/git_server.go`

**位置**: `Start()` 方法（第 496-499 行）

```go
// 尝试自动创建 git 用户（如果不存在）
if err := gs.createGitUser(); err != nil {
    gs.logger.Warnf("创建 git 用户失败: %v，如果需要请手动创建: sudo useradd -r -s /bin/bash -m -d /home/git git", err)
}
```

#### 修改 2: 改进 createGitUser() 函数

**文件**: `internal/runner/git_server.go`

**位置**: 第 1759-1784 行

```go
// createGitUser 创建 git 用户（使用标准的 /home/git 目录）
func (gs *GitServer) createGitUser() error {
    // 检查用户是否已存在
    cmd := exec.Command("id", "-u", gs.sshUser)
    if err := cmd.Run(); err == nil {
        gs.logger.Infof("git 用户已存在")
        return nil
    }

    // 使用标准的 /home/git 作为 home 目录（最佳实践）
    homeDir := "/home/git"
    
    // 创建用户 - 需要 root 权限
    cmd = exec.Command("useradd", "-r", "-s", "/bin/bash", "-m", "-d", homeDir, gs.sshUser)
    output, err := cmd.CombinedOutput()
    if err != nil {
        // 检查是否是权限问题
        if strings.Contains(string(output), "Permission denied") || strings.Contains(err.Error(), "permission") {
            return fmt.Errorf("权限不足（需要 root/sudo 权限）: %w", err)
        }
        return fmt.Errorf("创建用户失败: %s, %w", string(output), err)
    }

    gs.logger.Infof("git 用户创建成功，home 目录: %s", homeDir)
    return nil
}
```

## 使用方式

### 场景 1: 以 root 权限启动（推荐生产环境）

```bash
# 配置文件启用 Git Deploy
vim sslcat.conf
# 设置: "runners": { "git": { "enabled": true } }

# 以 sudo 启动，会自动创建 git 用户
sudo ./sslcat

# 重启 sshd（仅首次需要）
sudo systemctl restart sshd
```

**日志输出**:
```
INFO git 用户创建成功，home 目录: /home/git
INFO SSH 用户配置完成
INFO Git 服务器已启动
```

### 场景 2: 普通权限启动（开发环境）

```bash
# 配置文件启用 Git Deploy
vim sslcat-dev.conf

# 普通权限启动
./sslcat
```

**日志输出**:
```
WARN 创建 git 用户失败: 权限不足（需要 root/sudo 权限），如果需要请手动创建: sudo useradd -r -s /bin/bash -m -d /home/git git
WARN SSH用户 git 不存在，请手动创建
INFO Git 服务器已启动
```

**解决方案**：

方案 A - 手动创建后重启：
```bash
# 手动创建用户
sudo useradd -r -s /bin/bash -m -d /home/git git

# 重启服务
./sslcat

# 重启 sshd
sudo systemctl restart sshd
```

方案 B - 使用 sudo 启动：
```bash
sudo ./sslcat
```

### 场景 3: git 用户已存在

```bash
# 启动服务
./sslcat
```

**日志输出**:
```
INFO git 用户已存在
INFO SSH 用户配置完成
INFO Git 服务器已启动
```

## 特性说明

### ✅ 自动化

- 启动时自动检测 git 用户是否存在
- 如果不存在且有权限，自动创建
- 如果已存在，跳过创建

### ✅ 最佳实践

- 使用标准的 `/home/git` 作为用户 home 目录
- 设置 shell 为 `/bin/bash`
- 创建系统用户（`-r` 参数）
- 自动创建 home 目录（`-m` 参数）

### ✅ 友好提示

- 权限不足时给出清晰的错误信息
- 提供完整的手动创建命令
- 不会因为用户创建失败而阻止服务启动

### ✅ 安全性

- 只在需要时创建用户
- 使用最小权限原则（系统用户）
- 不会覆盖已存在的用户

## 完整启动流程

```bash
# 1. 配置 Git Deploy
vim sslcat.conf
# 设置: "runners": { "git": { "enabled": true } }

# 2. 启动服务（自动创建用户）
sudo ./sslcat
# 或者先手动创建用户
sudo useradd -r -s /bin/bash -m -d /home/git git
./sslcat

# 3. 重启 sshd（仅首次需要）
sudo systemctl restart sshd

# 4. 添加 SSH 公钥
curl -X POST http://localhost:8080/admin/api/git-server/ssh-key/add \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dev-key",
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB..."
  }'

# 5. 测试 SSH 连接
ssh -T git@your-server

# 6. Git 推送部署
cd your-project
git remote add sslcat git@your-server:myapp
git push sslcat main
```

## 目录权限

创建用户后的权限结构：

```bash
# Git 用户 home 目录
drwxr-xr-x  git git  /home/git/

# SSH 配置目录
drwx------  git git  /home/git/.ssh/

# SSLcat 管理的目录
drwxr-xr-x  sslcat sslcat  ./data/runners/git/
drwx------  sslcat sslcat  ./data/runners/keys/ssh/
-rw-------  sslcat sslcat  ./data/runners/keys/ssh/authorized_keys
```

## 常见问题

### Q1: 为什么自动创建失败？

**A**: 创建系统用户需要 root 权限。解决方案：
- 使用 `sudo ./sslcat` 启动
- 或者手动创建用户后再启动

### Q2: git 用户的 home 目录一定是 /home/git 吗？

**A**: 是的，现在统一使用 `/home/git` 作为标准位置，这是 Linux 的最佳实践。

### Q3: SSH 密钥文件在哪里？

**A**: 
- Git 用户的系统 SSH 配置: `/home/git/.ssh/`
- SSLcat 管理的 SSH 密钥: `./data/runners/keys/ssh/authorized_keys`
- SSLcat 会将密钥写入自己管理的 `authorized_keys` 文件

### Q4: 需要重启 sshd 吗？

**A**: **仅首次启用** Git Deploy 时需要重启一次 sshd，让 SSH 配置生效：
```bash
sudo systemctl restart sshd
```

后续添加/删除 SSH 密钥不需要重启 sshd。

### Q5: 如何验证 git 用户创建成功？

**A**: 
```bash
# 检查用户是否存在
id git

# 查看用户信息
getent passwd git

# 应该看到类似：
# git:x:999:999::/home/git:/bin/bash
```

## 相关文件

- `internal/runner/git_server.go` - Git 服务器核心实现
- `docs/git-deploy-ssh-implementation.md` - Git SSH 部署文档
- `GIT_DEPLOY_IMPROVEMENTS.md` - Git Deploy 改进文档

## 更新日期

2025-10-02

