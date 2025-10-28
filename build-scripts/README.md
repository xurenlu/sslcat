# SSLCat 构建脚本说明

本目录包含各种构建 SSLCat 的脚本和 Dockerfile。

## 📦 推荐使用（生产环境）

### `build-musl-local.sh` ⭐️
**最佳选择 - 本地静态编译**

- ✅ 使用本地 musl-cross 工具链
- ✅ 完全静态链接，无任何依赖
- ✅ CGO 已启用（支持 WebP、SQLite 等）
- ✅ 适用于所有 Linux 发行版
- ✅ 编译速度快，无需 Docker

**使用方法：**
```bash
# 确保已安装 musl-cross
brew install musl-cross

# 编译
./build-musl-local.sh

# 输出文件
./sslcat-static-linux-amd64
```

**根目录快捷方式：**
```bash
# 根目录下有一个符号链接方便使用
../build-linux-static.sh
```

## 🔧 其他构建方式

### `build-static.sh`
**Docker + Debian 静态编译**

- 使用 Debian 基础镜像
- 需要 Docker 环境
- 适合 CI/CD 环境
- 需要网络下载镜像

### `build-zig-alpine.sh`
**Zig + Alpine 编译（实验性）**

- 使用 Zig 作为 C 编译器
- Alpine Linux 基础镜像
- 镜像体积小
- 网络问题可能导致失败

### `build-zig-cgo.sh`
**Zig 交叉编译（实验性）**

- 使用 Zig 进行交叉编译
- 支持多平台
- 配置复杂

### `test-static-binary.sh`
**二进制文件测试脚本**

在 Linux 系统上测试编译好的二进制文件：
- 检查文件类型
- 验证静态链接
- 测试运行

## 📋 Dockerfile 说明

### `Dockerfile.static`
配合 `build-static.sh` 使用，Debian 基础镜像。

### `Dockerfile.zig-alpine`
配合 `build-zig-alpine.sh` 使用，Alpine + Zig。

### `Dockerfile.zig-cgo`
配合 `build-zig-cgo.sh` 使用，Zig 交叉编译。

### `Dockerfile.zig`
基础 Zig 编译环境。

## 🎯 使用建议

1. **开发环境**：使用 `build-musl-local.sh`（最快、最可靠）
2. **CI/CD**：使用 GitHub Actions（见 `.github/workflows/release.yml`）
3. **测试**：使用 `test-static-binary.sh` 验证二进制文件

## 📝 注意事项

- 所有静态链接的二进制文件都包含 CGO 支持
- musl-cross 只是编译工具，运行时不需要
- 静态链接的文件较大（约 34MB），但无依赖
- 可在任何 Linux 发行版上运行（Ubuntu、CentOS、Alpine 等）

## 🚀 快速开始

```bash
# 1. 安装依赖（仅首次）
brew install musl-cross

# 2. 编译
cd /path/to/sslcat
./build-linux-static.sh

# 3. 测试（在 Linux 上）
./test-static-binary.sh

# 4. 部署
scp sslcat-static-linux-amd64 user@server:/usr/local/bin/sslcat
```

## 📚 相关文档

- GitHub Actions 配置：`.github/workflows/release.yml`
- Makefile：`../Makefile`
- 部署文档：`../deploy/README.md`

