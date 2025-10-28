# 本地编译和发布指南

本文档介绍如何在本地编译所有平台的 SSLCat 版本（启用 CGO）并发布到 GitHub Release。

## 📋 前置要求

### 必需工具

1. **Go 1.21+**
   ```bash
   go version
   ```

2. **Git**
   ```bash
   git --version
   ```

3. **GitHub CLI** (用于发布)
   ```bash
   brew install gh
   gh auth login
   ```

### 推荐工具（用于交叉编译）

#### 1. musl-cross（Linux 静态链接）

```bash
# macOS
brew install musl-cross

# 验证
x86_64-linux-musl-gcc --version
aarch64-linux-musl-gcc --version
```

**作用**: 编译完全静态链接的 Linux 版本，无任何依赖，可在所有 Linux 发行版上运行。

#### 2. Zig（Windows 交叉编译）

```bash
# macOS
brew install zig

# 验证
zig version
```

**作用**: 在 macOS/Linux 上交叉编译 Windows 版本。

## 🚀 快速开始

### 方式一：完整编译和发布（推荐）

使用交互式脚本，编译所有平台并可选发布到 GitHub：

```bash
./scripts/build-and-release.sh
```

**功能**:
- ✅ 自动检测可用的编译工具链
- ✅ 编译所有支持的平台（Linux、macOS、Windows）
- ✅ 生成 SHA256 校验和
- ✅ 交互式创建 Git 标签
- ✅ 可选发布到 GitHub Release

**流程**:
1. 检查工具链
2. 询问是否创建新版本标签
3. 构建前端
4. 编译所有平台
5. 生成校验和
6. 询问是否发布到 GitHub

### 方式二：仅编译（不发布）

快速编译所有平台，不发布：

```bash
./scripts/build-all-platforms.sh
```

**输出**: 所有编译文件保存在 `dist/` 目录。

## 📦 支持的平台

### 完全支持（CGO Enabled）

| 平台 | 架构 | 工具链要求 | 链接方式 |
|------|------|-----------|---------|
| Linux | AMD64 | musl-cross | 静态链接 |
| Linux | ARM64 | musl-cross | 静态链接 |
| macOS | AMD64 | 系统 Clang | 动态链接 |
| macOS | ARM64 | 系统 Clang | 动态链接 |
| Windows | AMD64 | Zig | 静态链接 |
| Windows | ARM64 | Zig | 静态链接 |

### 编译条件

- **Linux**: 需要 `musl-cross`，否则跳过
- **macOS**: 必须在 macOS 系统上编译
- **Windows**: 需要 `zig`，否则跳过

## 🔧 详细使用

### 1. 准备环境

```bash
# 安装所有推荐工具
brew install musl-cross zig gh

# 登录 GitHub CLI
gh auth login
```

### 2. 编译所有平台

```bash
# 进入项目目录
cd /path/to/sslcat

# 运行编译脚本
./scripts/build-and-release.sh
```

### 3. 创建新版本

脚本会询问：
```
是否创建新的 Git 标签？ [y/N]: y
请输入新版本号 (例如 v1.3.20): v1.3.21
```

输入版本号后，脚本会：
1. 创建本地标签
2. 使用新版本号编译
3. 发布时自动推送标签

### 4. 发布到 GitHub

编译完成后，脚本会询问：
```
是否发布到 GitHub Release？ [y/N]: y
```

然后输入 Release 说明（支持多行，Ctrl+D 结束）：
```
请输入 Release 说明 (按 Ctrl+D 结束):
## 新特性
- 添加 CLI 管理功能
- 支持静态链接编译

## Bug 修复
- 修复代理规则切换问题
^D
```

### 5. 手动发布（可选）

如果选择不自动发布，可以后续手动发布：

```bash
# 发布到 GitHub
gh release create v1.3.21 \
  --title "SSLCat v1.3.21" \
  --notes "Release notes here" \
  dist/*
```

## 📊 编译输出

### 文件结构

```
dist/
├── sslcat_v1.3.21_linux_amd64.tar.gz      # Linux AMD64 (静态)
├── sslcat_v1.3.21_linux_arm64.tar.gz      # Linux ARM64 (静态)
├── sslcat_v1.3.21_darwin_amd64.tar.gz     # macOS Intel
├── sslcat_v1.3.21_darwin_arm64.tar.gz     # macOS M1/M2
├── sslcat_v1.3.21_windows_amd64.zip       # Windows AMD64
├── sslcat_v1.3.21_windows_arm64.zip       # Windows ARM64
└── sha256sum.txt                           # 校验和
```

### 文件大小参考

- Linux (静态链接): ~34MB
- macOS: ~30MB
- Windows: ~32MB

## 🔍 验证编译结果

### 检查文件

```bash
# 查看编译文件
ls -lh dist/

# 查看校验和
cat dist/sha256sum.txt
```

### 测试二进制（Linux）

```bash
# 解压
tar -xzf dist/sslcat_v1.3.21_linux_amd64.tar.gz

# 检查链接类型
file sslcat
# 输出: ELF 64-bit LSB executable, x86-64, statically linked

# 检查依赖（应该没有）
ldd sslcat
# 输出: not a dynamic executable

# 测试运行
./sslcat -version
```

## 🛠️ 故障排除

### 问题 1: musl-cross 未安装

**症状**: Linux 版本被跳过

**解决**:
```bash
brew install musl-cross
```

### 问题 2: Zig 未安装

**症状**: Windows 版本被跳过

**解决**:
```bash
brew install zig
```

### 问题 3: 在 Linux 上编译 macOS 版本

**症状**: macOS 版本被跳过

**说明**: macOS 版本必须在 macOS 系统上编译（CGO 依赖系统库）

**解决**: 使用 GitHub Actions 或在 macOS 机器上编译

### 问题 4: GitHub CLI 未登录

**症状**: 发布失败，提示未登录

**解决**:
```bash
gh auth login
# 按提示完成登录
```

### 问题 5: 编译失败 - CGO 错误

**症状**: 
```
# github.com/chai2010/webp
undefined: webpGetInfo
```

**原因**: 交叉编译时 CGO 找不到对应平台的 C 库

**解决**: 
- 确保使用了正确的交叉编译工具链
- 对于 Linux: 使用 musl-cross
- 对于 Windows: 使用 Zig

## 📝 最佳实践

### 1. 发布前检查清单

- [ ] 更新 CHANGELOG.md
- [ ] 更新版本号
- [ ] 本地测试所有功能
- [ ] 编译所有平台
- [ ] 验证二进制文件
- [ ] 检查校验和
- [ ] 发布到 GitHub
- [ ] 测试下载和安装

### 2. 版本号规范

遵循语义化版本：
- `v1.3.20` - 正式版本
- `v1.3.20-rc1` - 候选版本
- `v1.3.20-beta1` - 测试版本

### 3. Release 说明模板

```markdown
## 🎉 新特性
- 功能 1
- 功能 2

## 🐛 Bug 修复
- 修复问题 1
- 修复问题 2

## 🛠️ 改进
- 改进 1
- 改进 2

## 📦 下载
选择适合你系统的版本下载。所有 Linux 版本都是完全静态链接，无需任何依赖。

## 🔐 校验和
见 sha256sum.txt
```

## 🔄 与 GitHub Actions 对比

| 特性 | 本地编译 | GitHub Actions |
|------|---------|----------------|
| 速度 | ⚡ 快（本地资源） | 🐌 慢（需要排队） |
| 灵活性 | ✅ 高（随时编译） | ❌ 低（需要推送） |
| 成本 | 💰 本地资源 | 🆓 免费额度 |
| 自动化 | ❌ 手动触发 | ✅ 自动触发 |
| 平台支持 | ⚠️ 取决于本地环境 | ✅ 全平台支持 |

### 推荐使用场景

- **本地编译**: 快速迭代、测试版本、紧急修复
- **GitHub Actions**: 正式发布、自动化流程、多人协作

## 📚 相关文档

- [构建脚本说明](../../build-scripts/README.md)
- [GitHub Actions 配置](../../.github/workflows/release.yml)
- [部署指南](../deployment/README.md)

## 💡 提示

1. **首次使用**: 先运行 `./scripts/build-all-platforms.sh` 测试编译环境
2. **快速发布**: 使用 `./scripts/build-and-release.sh` 一键完成
3. **自定义编译**: 参考脚本内容，根据需要修改
4. **CI/CD**: 可以将脚本集成到自己的 CI/CD 流程中

