# 本地编译和发布示例

## 🚀 快速发布新版本

### 场景：发布 v1.3.21 版本

```bash
# 1. 确保代码已提交
git status

# 2. 更新 CHANGELOG.md
vim CHANGELOG.md

# 3. 运行编译和发布脚本
./scripts/build-and-release.sh
```

### 交互过程示例

```
⚡ SSLCat 本地编译和发布脚本 (CGO Enabled)

🔍 检查必要的工具...
✓ Go: go version go1.23.4 darwin/arm64
✓ Git
✓ GitHub CLI
✓ musl-cross
✓ Zig: 0.13.0

📦 版本信息
   版本: v1.3.20-rc10-dirty
   时间: 2025-10-28_16:30:00

是否创建新的 Git 标签？ [y/N]: y
请输入新版本号 (例如 v1.3.20): v1.3.21
✓ 已创建标签: v1.3.21

🏗️  构建前端...
✓ 前端构建完成

🔨 开始编译所有平台版本...

📦 编译 linux-amd64...
   使用 musl-cross 静态链接
   ✓ 完成: dist/sslcat_v1.3.21_linux_amd64.tar.gz (34M)

📦 编译 linux-arm64...
   使用 musl-cross 静态链接
   ✓ 完成: dist/sslcat_v1.3.21_linux_arm64.tar.gz (33M)

📦 编译 darwin-amd64...
   使用系统 Clang
   ✓ 完成: dist/sslcat_v1.3.21_darwin_amd64.tar.gz (30M)

📦 编译 darwin-arm64...
   使用系统 Clang
   ✓ 完成: dist/sslcat_v1.3.21_darwin_arm64.tar.gz (29M)

📦 编译 windows-amd64...
   使用 Zig 交叉编译
   ✓ 完成: dist/sslcat_v1.3.21_windows_amd64.zip (32M)

📦 编译 windows-arm64...
   使用 Zig 交叉编译
   ✓ 完成: dist/sslcat_v1.3.21_windows_arm64.zip (31M)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ 编译完成: 6 个平台

🔐 生成 SHA256 校验和...
✓ 校验和已生成

📊 编译结果:
total 189M
-rw-r--r--  1 rocky  staff   34M Oct 28 16:35 sslcat_v1.3.21_linux_amd64.tar.gz
-rw-r--r--  1 rocky  staff   33M Oct 28 16:36 sslcat_v1.3.21_linux_arm64.tar.gz
-rw-r--r--  1 rocky  staff   30M Oct 28 16:37 sslcat_v1.3.21_darwin_amd64.tar.gz
-rw-r--r--  1 rocky  staff   29M Oct 28 16:38 sslcat_v1.3.21_darwin_arm64.tar.gz
-rw-r--r--  1 rocky  staff   32M Oct 28 16:39 sslcat_v1.3.21_windows_amd64.zip
-rw-r--r--  1 rocky  staff   31M Oct 28 16:40 sslcat_v1.3.21_windows_arm64.zip
-rw-r--r--  1 rocky  staff  512B Oct 28 16:40 sha256sum.txt

是否发布到 GitHub Release？ [y/N]: y

🚀 发布到 GitHub Release...
请输入 Release 说明 (按 Ctrl+D 结束):
## 🎉 新特性

### CLI 命令行管理
- 新增 `config show/get/set` 配置管理命令
- 新增 `proxy list/add/update/delete` 代理规则管理
- 新增 `ssl list/show/request/renew/delete` SSL 证书管理

### 静态链接构建
- 支持完全静态链接编译
- 零依赖部署
- 兼容所有 Linux 发行版

## 🐛 Bug 修复
- 修复前端代理规则切换问题
- 优化 API 部分更新逻辑

## 📦 下载
选择适合你系统的版本下载。
^D

📤 推送标签到 GitHub...
📝 创建 GitHub Release...
✓ 发布成功！
🔗 查看 Release: https://github.com/xurenlu/sslcat/releases/tag/v1.3.21

╔════════════════════════════════════════════════════════════╗
║                                                            ║
║                    🎉 全部完成！                           ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
```

## 📋 仅编译（不发布）

如果只想编译测试，不发布：

```bash
./scripts/build-all-platforms.sh
```

输出：
```
⚡ SSLCat 快速编译（所有平台，CGO Enabled）

✓ musl-cross 可用，Linux 版本将静态链接
✓ aarch64-linux-musl-gcc 可用

🏗️  构建前端...
✅ 前端构建完成！

📦 版本: v1.3.21

🐧 编译 Linux AMD64 (静态链接)...
✓ Linux AMD64 完成

🐧 编译 Linux ARM64 (静态链接)...
✓ Linux ARM64 完成

🍎 编译 macOS AMD64...
✓ macOS AMD64 完成

🍎 编译 macOS ARM64 (M1/M2)...
✓ macOS ARM64 完成

🪟 编译 Windows AMD64...
✓ Windows AMD64 完成

🪟 编译 Windows ARM64...
✓ Windows ARM64 完成

🔐 生成 SHA256 校验和...

✅ 编译完成！

📊 编译结果:
[文件列表...]

💡 提示:
   - 文件保存在 dist/ 目录
   - 使用 ./scripts/build-and-release.sh 可以直接发布到 GitHub
```

## 🛠️ 工具链安装

### macOS

```bash
# 安装所有必需工具
brew install go git gh musl-cross zig

# 登录 GitHub CLI
gh auth login
```

### Linux

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y golang git

# 安装 GitHub CLI
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt-get update
sudo apt-get install -y gh

# 登录
gh auth login
```

## 🔍 验证编译结果

### 检查 Linux 静态链接

```bash
# 解压
tar -xzf dist/sslcat_v1.3.21_linux_amd64.tar.gz

# 检查文件类型
file sslcat
# 输出: ELF 64-bit LSB executable, x86-64, statically linked

# 检查依赖
ldd sslcat
# 输出: not a dynamic executable

# 测试运行
./sslcat -version
```

### 检查校验和

```bash
# 查看校验和
cat dist/sha256sum.txt

# 验证文件
cd dist
sha256sum -c sha256sum.txt
```

## 📝 发布检查清单

发布前确保：

- [ ] 代码已提交并推送
- [ ] CHANGELOG.md 已更新
- [ ] 版本号符合规范
- [ ] 本地测试通过
- [ ] 所有平台编译成功
- [ ] 校验和已生成
- [ ] Release 说明准备好
- [ ] GitHub CLI 已登录

## 🆚 对比 GitHub Actions

### 使用本地编译的场景

✅ **适合**:
- 快速迭代测试
- 紧急修复发布
- 网络不稳定
- 需要立即发布

❌ **不适合**:
- 团队协作发布
- 需要完整的 CI/CD
- 需要构建日志追溯

### 使用 GitHub Actions 的场景

✅ **适合**:
- 正式版本发布
- 团队协作
- 自动化流程
- 需要构建记录

❌ **不适合**:
- 紧急修复
- 快速测试
- 网络受限环境

## 💡 最佳实践

1. **开发阶段**: 使用 `make build` 快速编译当前平台
2. **测试阶段**: 使用 `./scripts/build-all-platforms.sh` 编译所有平台
3. **发布阶段**: 使用 `./scripts/build-and-release.sh` 完整发布流程
4. **紧急修复**: 使用本地编译快速发布，后续补充 GitHub Actions

## 🔗 相关资源

- [本地编译和发布指南](docs/zh/development/local-build-and-release.md)
- [脚本说明](scripts/README.md)
- [构建脚本说明](build-scripts/README.md)
- [GitHub Actions 配置](.github/workflows/release.yml)

