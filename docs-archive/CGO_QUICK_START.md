# SSLcat CGO 构建 - 快速开始

## ✅ 已完成

成功在 Apple Silicon Mac 上使用 Docker + Zig 编译出 AMD64 Linux CGO 二进制文件！

**文件位置**: `build/sslcat-linux-amd64-cgo` (27MB)

## 🚀 快速命令

### 方式一：使用 Make（推荐）
```bash
make docker-cgo-zig
```

### 方式二：直接运行脚本
```bash
./build-cgo-zig.sh
```

## 📤 部署到服务器

```bash
# 上传文件
scp build/sslcat-linux-amd64-cgo user@server:/opt/sslcat/sslcat

# SSH 到服务器
ssh user@server

# 设置权限并运行
chmod +x /opt/sslcat/sslcat
/opt/sslcat/sslcat --version
```

## 🔄 重新编译

每次代码更新后：
```bash
git pull
make docker-cgo-zig
# 或
./build-cgo-zig.sh
```

## 💡 关键技术

- **基础镜像**: golang:1.25-alpine (ARM64)
- **交叉编译**: Zig 编译器
- **目标架构**: x86-64 (AMD64)
- **CGO**: 已启用
- **链接方式**: static-pie（静态链接）

## 📊 构建选项对比

| 命令 | 架构 | 适用场景 |
|------|------|---------|
| `make docker-cgo-zig` | AMD64 | ⭐ **推荐** - 在 ARM Mac 上编译 |
| `make docker-cgo-arm64` | ARM64 | ARM64 Linux 服务器 |
| `make build-linux` | AMD64 | 纯 Go 版本（CGO_ENABLED=0） |

## 🎯 CGO vs 纯 Go

### 使用 CGO 版本的理由：
- ✅ mattn/go-sqlite3 性能更好（2-3x）
- ✅ 可以使用 C 库
- ✅ 本构建脚本已解决交叉编译难题

### 使用纯 Go 版本的理由：
- ✅ 编译更简单快速
- ✅ 使用 modernc.org/sqlite（纯 Go，兼容性好）

## 📝 详细文档

查看 `CGO_BUILD_SUCCESS.md` 了解完整技术细节和故障排除。

