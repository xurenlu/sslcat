# 安装脚本改进

## 概述

对 `scripts/install-from-release.sh` 和 `scripts/install-from-release-zh.sh` 进行了全面改进，添加了 Docker 安装、Git 用户检测、系统依赖安装等功能。

## 新增功能

### 1. 系统依赖自动安装

**支持的操作系统**：
- Debian/Ubuntu: `apt-get install curl wget tar gzip git`
- RHEL/CentOS/Fedora: `dnf/yum install curl wget tar gzip git`
- Arch Linux: `pacman -S curl wget tar gzip git`
- macOS: `brew install curl wget git`

**自动检测**：
- 检测操作系统类型
- 安装必要的系统工具
- 支持多种包管理器

### 2. Docker 自动安装

**功能**：
- 检测 Docker 是否已安装
- 自动安装 Docker（如果未安装）
- 启动并启用 Docker 服务

**支持的系统**：
- Linux: 使用 `get.docker.com` 脚本
- macOS: 通过 Homebrew 安装 Docker Desktop

**安装命令**：
```bash
# 自动安装 Docker
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.3.5-rc10 --install-docker
```

### 3. Git 用户自动创建

**功能**：
- 检测 git 用户是否存在
- 自动创建 git 用户（如果不存在）
- 设置正确的用户权限和目录

**创建命令**：
```bash
useradd -r -s /bin/bash -m -d /home/git git
```

**使用方式**：
```bash
# 自动创建 git 用户
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.3.5-rc10 --install-git-user
```

### 4. 多语言支持

**新增消息**：
- Docker 检测和安装相关消息
- Git 用户检测和创建相关消息
- 系统依赖安装相关消息

**支持语言**：
- 中文 (zh)
- 英文 (en)
- 法文 (fr)
- 西班牙文 (es)
- 日文 (ja)

### 5. 配置优化

**默认配置更新**：
- 启用 Git Deploy 服务
- 设置正确的目录路径
- 优化配置参数

**新增配置**：
```json
{
  "runners": {
    "git": {
      "enabled": true,
      "repos_dir": "/opt/sslcat/runners/git",
      "max_concurrent": 3,
      "clone_timeout": 300,
      "auto_cleanup": true,
      "cleanup_interval": 7200
    }
  }
}
```

## 使用方法

### 基本安装

```bash
# 标准安装
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.3.5-rc10

# 中文版安装
curl -fsSL https://sslcat.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v 1.3.5-rc10
```

### 完整安装（推荐）

```bash
# 安装 SSLcat + Docker + Git 用户
curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.3.5-rc10 --install-docker --install-git-user
```

### 参数说明

| 参数 | 说明 | 示例 |
|------|------|------|
| `-v, --version` | 指定版本 | `-v 1.3.5-rc10` |
| `-l, --lang` | 指定语言 | `-l zh` |
| `--install-docker` | 自动安装 Docker | `--install-docker` |
| `--install-git-user` | 自动创建 git 用户 | `--install-git-user` |

## 安装流程

### 1. 系统检测
- 检测操作系统类型
- 检测架构（amd64, arm64, arm）
- 检测必要的系统工具

### 2. 依赖安装
- 安装系统依赖（curl, wget, tar, gzip, git）
- 根据操作系统选择合适的包管理器

### 3. Docker 安装（可选）
- 检测 Docker 是否已安装
- 如果未安装且指定了 `--install-docker`，则自动安装
- 启动并启用 Docker 服务

### 4. Git 用户设置（可选）
- 检测 git 用户是否存在
- 如果不存在且指定了 `--install-git-user`，则自动创建
- 设置正确的用户权限和目录

### 5. SSLcat 安装
- 下载指定版本的 SSLcat
- 安装到 `/opt/sslcat/sslcat`
- 创建 systemd 服务
- 生成默认配置文件

### 6. 服务启动
- 启用 SSLcat 服务
- 启动服务
- 显示访问信息

## 错误处理

### Docker 安装失败
```
[sslcat] Docker 安装失败，请手动安装: https://docs.docker.com/get-docker/
```

### Git 用户创建失败
```
创建 git 用户失败
```

### 系统依赖安装失败
- 会显示具体的包管理器错误信息
- 提供手动安装建议

## 日志输出示例

### 成功安装
```
[sslcat] 安装系统依赖...
[sslcat] 检查 Docker 是否已安装...
[sslcat] Docker 已安装
[sslcat] 检查 git 用户是否存在...
[sslcat] git 用户已存在
[sslcat] 安装完成: /opt/sslcat/sslcat
[sslcat] 配置: /etc/sslcat/sslcat.conf
[sslcat] 管理面板: http://1.2.3.4:80/sslcat-panel/
```

### 自动安装 Docker
```
[sslcat] 检查 Docker 是否已安装...
[sslcat] Docker 未安装，尝试安装 Docker...
[sslcat] Docker 安装成功
```

### 自动创建 Git 用户
```
[sslcat] 检查 git 用户是否存在...
[sslcat] git 用户不存在，创建 git 用户...
[sslcat] git 用户创建成功
```

## 兼容性

### 支持的操作系统
- Ubuntu 18.04+
- Debian 9+
- CentOS 7+
- RHEL 7+
- Fedora 30+
- Arch Linux
- macOS 10.15+

### 支持的架构
- x86_64/amd64
- aarch64/arm64
- armv7l/arm

## 安全考虑

1. **权限要求**：需要 root/sudo 权限
2. **网络访问**：需要访问 GitHub 和 Docker 官方源
3. **用户创建**：自动创建系统用户需要谨慎
4. **服务启动**：自动启动服务需要确认

## 故障排除

### 1. 权限不足
```bash
# 确保使用 sudo
sudo bash -s -- -v 1.3.5-rc10 --install-docker --install-git-user
```

### 2. 网络问题
```bash
# 使用中文镜像
curl -fsSL https://sslcat.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v 1.3.5-rc10
```

### 3. Docker 安装失败
```bash
# 手动安装 Docker
curl -fsSL https://get.docker.com | sh
sudo systemctl enable docker
sudo systemctl start docker
```

### 4. Git 用户创建失败
```bash
# 手动创建 git 用户
sudo useradd -r -s /bin/bash -m -d /home/git git
```

## 相关文件

- `scripts/install-from-release.sh` - 英文版安装脚本
- `scripts/install-from-release-zh.sh` - 中文版安装脚本
- `docs/INSTALL_SCRIPT_IMPROVEMENTS.md` - 本文档

## 更新日期

2025-10-02

## 版本

v1.3.5-rc10
