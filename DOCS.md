# WithSSL 文档目录

欢迎查看 WithSSL 项目的完整文档！本文档目录帮助您快速找到所需的信息。

## 📚 主要文档

### 🚀 开始使用

| 文档 | 语言 | 描述 |
|------|------|------|
| [README.md](README.md) | 🇨🇳 中文 | 主要说明文档，包含功能介绍、安装和配置指南 |
| [README_EN.md](README_EN.md) | 🇺🇸 English | English version of main documentation |
| [README_JA.md](README_JA.md) | 🇯🇵 日本語 | Japanese version of main documentation |
| [README_ES.md](README_ES.md) | 🇪🇸 Español | Spanish version of main documentation |
| [README_FR.md](README_FR.md) | 🇫🇷 Français | French version of main documentation |
| [README_RU.md](README_RU.md) | 🇷🇺 Русский | Russian version of main documentation |

### 🏗️ 部署运维

| 文档 | 语言 | 描述 |
|------|------|------|
| [DEPLOYMENT.md](DEPLOYMENT.md) | 🇨🇳 中文 | 详细的部署指南，包含交叉编译、部署脚本使用等 |
| [DEPLOYMENT_EN.md](DEPLOYMENT_EN.md) | 🇺🇸 English | Complete deployment and operations guide |

### 📋 项目总结

| 文档 | 语言 | 描述 |
|------|------|------|
| [项目总结.md](项目总结.md) | 🇨🇳 中文 | 详细的功能介绍和技术实现说明 |

## 🛠️ 工具和脚本

### 安装和部署脚本

| 脚本 | 用途 | 适用场景 |
|------|------|----------|
| [install.sh](install.sh) | 完整自动安装 | 新服务器环境，从源码构建 |
| [deploy.sh](deploy.sh) | 快速部署 | 生产环境部署，更新现有服务 |
| [start.sh](start.sh) | 开发测试 | 本地开发和功能测试 |
| [demo.sh](demo.sh) | 演示运行 | 快速体验和功能演示 |

### 构建工具

| 工具 | 描述 |
|------|------|
| [Makefile](Makefile) | 构建管理，支持多平台编译 |
| [go.mod](go.mod) | Go 模块依赖管理 |

## 🐳 容器化部署

| 文件 | 描述 |
|------|------|
| [Dockerfile](Dockerfile) | Docker 镜像构建文件 |
| [docker-compose.yml](docker-compose.yml) | Docker Compose 部署配置 |

## ⚙️ 配置文件

| 文件 | 描述 |
|------|------|
| [withssl.conf.example](withssl.conf.example) | 配置文件示例 |
| [.gitignore](.gitignore) | Git 忽略文件配置 |

## 📖 文档阅读建议

### 🆕 新用户推荐阅读顺序

1. **了解项目** → [README.md](README.md) 或 [README_EN.md](README_EN.md)
2. **功能详解** → [项目总结.md](项目总结.md)
3. **部署实践** → [DEPLOYMENT.md](DEPLOYMENT.md) 或 [DEPLOYMENT_EN.md](DEPLOYMENT_EN.md)

### 👨‍💻 开发者推荐阅读

1. **项目架构** → [项目总结.md](项目总结.md)
2. **本地开发** → [README.md](README.md) 的开发指南部分
3. **构建部署** → [DEPLOYMENT.md](DEPLOYMENT.md)

### 🚀 运维人员推荐阅读

1. **快速上手** → [README.md](README.md)
2. **部署指南** → [DEPLOYMENT.md](DEPLOYMENT.md)
3. **脚本使用** → [install.sh](install.sh) 和 [deploy.sh](deploy.sh)

## 🔧 快速命令参考

### 开发和测试

```bash
# 快速开始开发
./start.sh

# 运行演示
./demo.sh

# 构建项目
make build

# 构建所有平台
make build-all
```

### 部署相关

```bash
# 自动安装（新环境）
sudo bash install.sh

# 快速部署（生产环境）
./deploy.sh your-server.com root

# 构建 Linux 服务器版本
make build-linux
```

### 服务管理

```bash
# 查看服务状态
sudo systemctl status withssl

# 查看日志
sudo journalctl -u withssl -f

# 平滑重启
sudo systemctl reload withssl
```

## 💡 获取帮助

如果您在使用过程中遇到问题：

1. 📖 **查看文档**: 按照上述推荐阅读相关文档
2. 🔍 **搜索问题**: 在各文档中搜索关键词
3. 🐛 **问题反馈**: 创建 GitHub Issue
4. 💬 **社区讨论**: 参与项目讨论

## 📝 文档贡献

欢迎为文档贡献内容：

- 🐛 **错误修正**: 发现文档错误请提交 PR
- 📚 **内容补充**: 增加缺失的使用案例或说明
- 🌍 **多语言支持**: 帮助翻译文档到其他语言
- 💡 **改进建议**: 提出文档结构或内容的改进建议

## 🌍 多语言支持

WithSSL 项目提供完整的多语言文档支持：

| 语言 | README 文档 | 特色 |
|------|-------------|------|
| 🇨🇳 中文 | [README.md](README.md) | 原版文档，最完整 |
| 🇺🇸 English | [README_EN.md](README_EN.md) | Complete English documentation |
| 🇯🇵 日本語 | [README_JA.md](README_JA.md) | 日本語版ドキュメント |
| 🇪🇸 Español | [README_ES.md](README_ES.md) | Documentación en español |
| 🇫🇷 Français | [README_FR.md](README_FR.md) | Documentation en français |
| 🇷🇺 Русский | [README_RU.md](README_RU.md) | Русская документация |

### 🔄 语言版本选择建议

**根据您的语言偏好选择：**
- **中文用户** → [README.md](README.md) (最详细)
- **English Users** → [README_EN.md](README_EN.md) (Complete)
- **日本のユーザー** → [README_JA.md](README_JA.md)
- **Usuarios Hispanohablantes** → [README_ES.md](README_ES.md)
- **Utilisateurs Francophones** → [README_FR.md](README_FR.md)
- **Русскоязычные пользователи** → [README_RU.md](README_RU.md)

---

**Happy coding with WithSSL!** 🚀
