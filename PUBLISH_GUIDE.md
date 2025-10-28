# 发布已编译文件到 GitHub Release

如果你已经编译好了文件，可以使用 `publish-release.sh` 脚本直接发布到 GitHub Release。

## 🚀 快速开始

### 1. 确保文件已编译

```bash
# 方式一：使用完整编译脚本
bash ./scripts/build-all-platforms.sh

# 方式二：使用本地静态编译
./build-linux-static.sh
```

编译后的文件应该在 `dist/` 目录中。

### 2. 发布到 GitHub

```bash
# 使用默认 dist 目录
./scripts/publish-release.sh

# 或指定其他目录
./scripts/publish-release.sh /path/to/your/dist
```

## 📋 发布流程

脚本会引导你完成以下步骤：

### 1. 检查文件

```
✓ 找到 6 个发布文件

📦 待发布的文件:
-rw-r--r--  1 rocky  staff   34M Oct 28 16:35 sslcat_v1.3.21_linux_amd64.tar.gz
-rw-r--r--  1 rocky  staff   33M Oct 28 16:36 sslcat_v1.3.21_linux_arm64.tar.gz
...
```

### 2. 输入版本号

```
📋 版本信息
   当前版本: v1.3.20-rc10

请输入要发布的版本号 [v1.3.20-rc10]: v1.3.21
```

可以：
- 直接回车使用当前版本
- 输入新版本号

### 3. 处理标签

如果标签不存在，脚本会询问：

```
⚠️  标签 v1.3.21 不存在
是否创建新标签？ [y/N]: y
✓ 已创建标签: v1.3.21

是否推送标签到远程？ [y/N]: y
✓ 标签已推送
```

### 4. 预览 Release 说明

脚本会自动从 `CHANGELOG.md` 提取当前版本的说明，或使用默认模板：

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## SSLCat v1.3.21

### 🎉 新特性
- CLI 命令行管理系统
- 静态链接构建支持

### 📦 下载
选择适合你系统的版本下载...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

是否编辑 Release 说明？ [y/N]: 
```

可以选择：
- `n`: 使用自动生成的说明
- `y`: 使用编辑器（vim/nano）编辑

### 5. 确认发布

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
准备发布到 GitHub Release
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   版本: v1.3.21
   文件数: 6
   仓库: xurenlu/sslcat
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

确认发布？ [y/N]: y
```

### 6. 发布完成

```
🚀 开始发布...

📝 创建 GitHub Release...

✓ 发布成功！

🔗 Release 地址:
   https://github.com/xurenlu/sslcat/releases/tag/v1.3.21

📊 Release 信息:
   - sslcat_v1.3.21_linux_amd64.tar.gz (34MB)
   - sslcat_v1.3.21_linux_arm64.tar.gz (33MB)
   - sslcat_v1.3.21_darwin_amd64.tar.gz (30MB)
   - sslcat_v1.3.21_darwin_arm64.tar.gz (29MB)
   - sslcat_v1.3.21_windows_amd64.zip (32MB)
   - sslcat_v1.3.21_windows_arm64.zip (31MB)

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                    🎉 发布完成！                           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

## 🎯 使用场景

### 场景 1: 已经编译好，直接发布

```bash
# 1. 编译所有平台
bash ./scripts/build-all-platforms.sh

# 2. 直接发布
./scripts/publish-release.sh

# 按提示操作即可
```

### 场景 2: 更新现有 Release

如果 Release 已存在，脚本会询问：

```
⚠️  Release v1.3.21 已存在
是否删除现有 Release 并重新创建？ [y/N]: y
```

### 场景 3: 自定义 Release 说明

```bash
# 1. 运行脚本
./scripts/publish-release.sh

# 2. 当询问是否编辑时选择 y
是否编辑 Release 说明？ [y/N]: y

# 3. 在编辑器中修改内容
# 4. 保存退出
```

### 场景 4: 发布到不同目录

```bash
# 如果编译文件在其他目录
./scripts/publish-release.sh /path/to/compiled/files
```

## ✨ 特性

### 自动从 CHANGELOG 提取

脚本会自动从 `CHANGELOG.md` 提取当前版本的更新说明：

```markdown
## [1.3.21] - 2025-10-28

### 🎉 新特性
- 功能 1
- 功能 2

### 🐛 Bug 修复
- 修复 1
```

会被提取并格式化到 Release 说明中。

### 智能版本检测

- 自动检测当前 Git 标签
- 支持创建新标签
- 可选推送标签到远程

### 灵活的编辑

- 支持使用默认编辑器（vim/nano）编辑
- 预览后再发布
- 支持取消操作

### 完整的错误处理

- 检查目录是否存在
- 检查文件是否存在
- 验证 GitHub CLI 登录状态
- 处理 Release 冲突

## 🔧 前置要求

### 必需

1. **GitHub CLI**
   ```bash
   brew install gh
   gh auth login
   ```

2. **已编译的文件**
   - 至少有一个 `.tar.gz` 或 `.zip` 文件
   - 文件应该在 `dist/` 目录（或指定目录）

### 可选

- **CHANGELOG.md**: 用于自动提取 Release 说明
- **Git 标签**: 如果没有会提示创建

## 📝 Release 说明模板

### 自动生成的模板

如果没有 CHANGELOG.md，会使用默认模板：

```markdown
## SSLCat v1.3.21

### 📦 下载

选择适合你系统的版本下载：

- **Linux AMD64**: 完全静态链接，支持所有 Linux 发行版
- **Linux ARM64**: 完全静态链接，支持 ARM64 服务器
- **macOS Intel**: 支持 Intel Mac
- **macOS Apple Silicon**: 支持 M1/M2/M3 Mac
- **Windows AMD64**: 支持 Windows 10/11 x64
- **Windows ARM64**: 支持 Windows on ARM

### ✨ 特性

- ✅ 完整的 CGO 支持（WebP、SQLite 等）
- ✅ Linux 版本完全静态链接，零依赖
- ✅ 高性能反向代理
- ✅ 自动 SSL 证书管理
...
```

### 从 CHANGELOG 提取

如果有 CHANGELOG.md，会提取对应版本的内容并添加下载说明。

## 💡 最佳实践

### 1. 发布前检查清单

- [ ] 代码已提交
- [ ] CHANGELOG.md 已更新
- [ ] 所有平台已编译
- [ ] 文件校验和已生成
- [ ] 本地测试通过

### 2. 版本号规范

遵循语义化版本：
- `v1.3.21` - 正式版本
- `v1.3.21-rc1` - 候选版本
- `v1.3.21-beta1` - 测试版本

### 3. Release 说明建议

包含以下内容：
- 🎉 新特性
- 🐛 Bug 修复
- 🛠️ 改进
- ⚠️ 破坏性变更（如有）
- 📦 下载说明
- 🔐 校验和说明

## 🆚 对比其他方式

### vs build-and-release.sh

| 特性 | publish-release.sh | build-and-release.sh |
|------|-------------------|---------------------|
| 编译 | ❌ 不编译 | ✅ 完整编译 |
| 发布 | ✅ 专注发布 | ✅ 可选发布 |
| 速度 | ⚡ 极快 | 🐌 需要编译时间 |
| 灵活性 | ✅ 高（可重复发布） | ❌ 低（一次性） |

**使用建议**:
- **已编译**: 使用 `publish-release.sh`
- **从头开始**: 使用 `build-and-release.sh`

### vs GitHub Actions

| 特性 | 本地发布 | GitHub Actions |
|------|---------|----------------|
| 速度 | ⚡ 即时 | 🐌 需要排队 |
| 控制 | ✅ 完全控制 | ❌ 自动化 |
| 编辑 | ✅ 可编辑 | ❌ 固定模板 |
| 记录 | ❌ 无日志 | ✅ 完整日志 |

## 🛠️ 故障排除

### 问题 1: GitHub CLI 未登录

```
❌ 未登录 GitHub CLI
💡 请运行: gh auth login
```

**解决**: 运行 `gh auth login` 并按提示登录。

### 问题 2: 找不到文件

```
❌ 在 dist 中没有找到任何 .tar.gz 或 .zip 文件
```

**解决**: 先编译文件或指定正确的目录。

### 问题 3: Release 已存在

```
⚠️  Release v1.3.21 已存在
是否删除现有 Release 并重新创建？ [y/N]:
```

**解决**: 选择 `y` 删除并重新创建，或选择 `n` 取消。

### 问题 4: 权限不足

```
HTTP 403: Resource not accessible by integration
```

**解决**: 确保你有仓库的写权限，或者重新登录 GitHub CLI。

## 📚 相关文档

- [本地编译指南](docs/zh/development/local-build-and-release.md)
- [构建脚本说明](scripts/README.md)
- [完整编译和发布](BUILD_RELEASE_EXAMPLE.md)

## 💬 示例会话

```bash
$ ./scripts/publish-release.sh

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║              SSLCat GitHub Release 发布工具                ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝

✓ 找到 6 个发布文件

✓ GitHub CLI 已就绪

📦 待发布的文件:
[文件列表...]

📋 版本信息
   当前版本: v1.3.20-rc10

请输入要发布的版本号 [v1.3.20-rc10]: v1.3.21
✓ 将发布版本: v1.3.21

⚠️  标签 v1.3.21 不存在
是否创建新标签？ [y/N]: y
✓ 已创建标签: v1.3.21

是否推送标签到远程？ [y/N]: y
✓ 标签已推送

📝 生成 Release 说明...

[Release 说明预览...]

是否编辑 Release 说明？ [y/N]: n

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
准备发布到 GitHub Release
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   版本: v1.3.21
   文件数: 6
   仓库: xurenlu/sslcat
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

确认发布？ [y/N]: y

🚀 开始发布...

📝 创建 GitHub Release...

✓ 发布成功！

🔗 Release 地址:
   https://github.com/xurenlu/sslcat/releases/tag/v1.3.21

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                    🎉 发布完成！                           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

