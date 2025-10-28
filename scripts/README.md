# SSLCat 构建和发布脚本

本目录包含 SSLCat 的各种构建、发布和管理脚本。

## 📦 编译和发布脚本

### `build-and-release.sh` ⭐️ 推荐
**完整的编译和发布流程**

一键完成从编译到发布的全部流程：
- ✅ 编译所有平台（Linux、macOS、Windows）
- ✅ 启用 CGO（支持 WebP、SQLite 等）
- ✅ 静态链接（Linux、Windows）
- ✅ 生成 SHA256 校验和
- ✅ 交互式创建 Git 标签
- ✅ 发布到 GitHub Release

**使用方法**:
```bash
./scripts/build-and-release.sh
```

**前置要求**:
- Go 1.21+
- Git
- GitHub CLI (`brew install gh`)
- musl-cross (`brew install musl-cross`) - 用于 Linux
- Zig (`brew install zig`) - 用于 Windows

### `build-all-platforms.sh`
**快速编译所有平台**

仅编译，不发布，适合快速测试：
```bash
./scripts/build-all-platforms.sh
```

输出文件保存在 `dist/` 目录。

## 🏗️ 前端构建脚本

### `build-frontend.sh`
**构建前端项目**

编译 React + TypeScript 前端：
```bash
./scripts/build-frontend.sh
```

自动：
- 安装依赖（yarn）
- 编译前端（Vite）
- 复制到 Go 嵌入目录

## 🔧 工具脚本

### `check-deps.sh`
**检查依赖**

检查所有必需和可选的工具是否安装：
```bash
./scripts/check-deps.sh
```

### `clean.sh`
**清理构建文件**

清理所有编译产物：
```bash
./scripts/clean.sh
```

清理内容：
- `build/` - 编译临时文件
- `dist/` - 发布文件
- `frontend/dist/` - 前端编译文件
- `internal/assets/frontend/` - 嵌入的前端文件

## 📊 监控和分析脚本

### `analyze_timers.py`
**定时器分析**

分析系统中的定时器使用情况。

### `sslcat-memory-monitor.sh`
**内存监控**

监控 SSLCat 的内存使用情况。

## 🚀 快速开始

### 1. 首次使用

```bash
# 安装依赖
brew install go git gh musl-cross zig

# 登录 GitHub CLI
gh auth login

# 检查环境
./scripts/check-deps.sh
```

### 2. 开发流程

```bash
# 修改代码...

# 编译测试（仅当前平台）
make build

# 编译所有平台
./scripts/build-all-platforms.sh

# 测试二进制
./dist/sslcat_*_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m).tar.gz
```

### 3. 发布新版本

```bash
# 更新 CHANGELOG.md
vim CHANGELOG.md

# 提交更改
git add .
git commit -m "feat: 新功能"

# 编译并发布
./scripts/build-and-release.sh
# 按提示输入版本号和 Release 说明
```

## 📋 编译平台支持

| 平台 | 架构 | CGO | 链接方式 | 工具链 |
|------|------|-----|---------|--------|
| Linux | AMD64 | ✅ | 静态 | musl-cross |
| Linux | ARM64 | ✅ | 静态 | musl-cross |
| macOS | AMD64 | ✅ | 动态 | 系统 Clang |
| macOS | ARM64 | ✅ | 动态 | 系统 Clang |
| Windows | AMD64 | ✅ | 静态 | Zig |
| Windows | ARM64 | ✅ | 静态 | Zig |

## 🔍 脚本详解

### build-and-release.sh 流程

```
1. 检查工具链
   ├─ Go
   ├─ Git
   ├─ GitHub CLI
   ├─ musl-cross (可选)
   └─ Zig (可选)

2. 询问创建标签
   └─ 输入新版本号

3. 构建前端
   └─ build-frontend.sh

4. 编译所有平台
   ├─ Linux AMD64 (musl-cross)
   ├─ Linux ARM64 (musl-cross)
   ├─ macOS AMD64 (系统)
   ├─ macOS ARM64 (系统)
   ├─ Windows AMD64 (Zig)
   └─ Windows ARM64 (Zig)

5. 生成校验和
   └─ sha256sum.txt

6. 询问发布
   ├─ 输入 Release 说明
   ├─ 推送标签
   └─ 创建 GitHub Release
```

### 编译器选择逻辑

```bash
# Linux
if has musl-cross:
    use musl-cross (静态链接)
elif has zig:
    use zig (静态链接)
else:
    skip

# macOS
if on macOS:
    use system clang
else:
    skip

# Windows
if has zig:
    use zig (交叉编译)
else:
    skip
```

## 💡 最佳实践

### 1. 编译前检查

```bash
# 检查工具
./scripts/check-deps.sh

# 检查代码
go vet ./...
go test ./...
```

### 2. 版本号规范

- 正式版本: `v1.3.20`
- RC 版本: `v1.3.20-rc1`
- Beta 版本: `v1.3.20-beta1`

### 3. Release 说明

使用 Markdown 格式，包含：
- 新特性
- Bug 修复
- 改进
- 破坏性变更（如有）

### 4. 发布检查清单

- [ ] 更新 CHANGELOG.md
- [ ] 更新版本号
- [ ] 本地测试
- [ ] 编译所有平台
- [ ] 验证二进制
- [ ] 发布到 GitHub
- [ ] 测试下载

## 🆚 本地编译 vs GitHub Actions

### 本地编译优势

- ⚡ **速度快**: 无需排队，立即开始
- 🎯 **灵活**: 随时编译，快速迭代
- 🔧 **调试**: 方便调试编译问题
- 🚀 **紧急修复**: 快速发布热修复

### GitHub Actions 优势

- 🤖 **自动化**: 推送即触发
- 🌍 **全平台**: 支持所有平台
- 📝 **可追溯**: 完整的构建日志
- 👥 **团队协作**: 统一的构建环境

### 推荐策略

- **日常开发**: 使用本地编译快速测试
- **正式发布**: 使用 GitHub Actions 确保一致性
- **紧急修复**: 使用本地编译快速响应

## 📚 相关文档

- [本地编译和发布指南](../docs/zh/development/local-build-and-release.md)
- [构建脚本说明](../build-scripts/README.md)
- [GitHub Actions 配置](../.github/workflows/release.yml)

## 🛠️ 故障排除

### 问题：musl-cross 未安装

```bash
brew install musl-cross
```

### 问题：Zig 未安装

```bash
brew install zig
```

### 问题：GitHub CLI 未登录

```bash
gh auth login
```

### 问题：编译失败

```bash
# 清理后重试
./scripts/clean.sh
./scripts/build-all-platforms.sh
```

## 📞 获取帮助

- 查看脚本源码了解详细逻辑
- 阅读相关文档
- 提交 Issue 报告问题

