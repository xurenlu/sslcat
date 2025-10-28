# 使用 Zig 在 Mac ARM64 上交叉编译 Linux AMD64 CGO 二进制文件

本文档说明如何在 Mac ARM64 (Apple Silicon) 上使用 Docker + Zig 编译出 Linux AMD64 平台的 CGO 启用的二进制文件。

## 🎯 目标

- **源平台**: Mac ARM64 (Apple Silicon M1/M2/M3)
- **目标平台**: Linux AMD64 (x86_64)
- **CGO**: 启用（支持 SQLite 等 C 库）
- **兼容性**: GLIBC 2.32+ 或完全静态链接

## 📋 前置要求

1. **Docker Desktop for Mac**
   ```bash
   # 检查 Docker 是否安装
   docker --version
   
   # 检查 Docker 是否运行
   docker info
   ```

2. **代理设置**（如果需要访问国外镜像）
   ```bash
   export https_proxy=http://127.0.0.1:7890
   export http_proxy=http://127.0.0.1:7890
   export all_proxy=socks5://127.0.0.1:7890
   ```

## 🚀 快速开始

### 方案 1: Alpine + 静态链接（推荐）

**优势**：
- ✅ 编译速度最快
- ✅ 完全静态链接，无任何依赖
- ✅ 兼容所有 Linux 发行版
- ✅ 文件体积小

**使用方法**：
```bash
# 执行构建脚本
./build-zig-alpine.sh

# 输出文件
./build/sslcat-linux-amd64-static
```

### 方案 2: Debian + GLIBC 2.32

**优势**：
- ✅ 兼容 GLIBC 2.32+
- ✅ 适合需要动态链接的场景
- ✅ 更接近标准 Linux 环境

**使用方法**：
```bash
# 执行构建脚本
./build-zig-cgo.sh

# 输出文件
./build/sslcat-linux-amd64-cgo
```

### 方案 3: 原始 Zig 方案

**使用方法**：
```bash
# 执行构建脚本
./build-zig.sh

# 输出文件
./sslcat-zig
```

## 📊 方案对比

| 方案 | 编译速度 | 文件大小 | 兼容性 | 依赖 |
|------|---------|---------|--------|------|
| Alpine + 静态链接 | ⭐⭐⭐⭐⭐ | ~10MB | 所有 Linux | 无 |
| Debian + GLIBC | ⭐⭐⭐⭐ | ~12MB | GLIBC 2.32+ | GLIBC |
| 原始 Zig | ⭐⭐⭐ | ~10MB | GLIBC 2.32+ | GLIBC |

## 🔧 详细使用说明

### 1. 编译前准备

```bash
# 克隆项目
cd /Users/rocky/Sites/sslcat

# 确保 Docker 运行
docker info

# 设置代理（如果需要）
export https_proxy=http://127.0.0.1:7890
export http_proxy=http://127.0.0.1:7890
```

### 2. 执行编译

```bash
# 使用 Alpine 方案（推荐）
./build-zig-alpine.sh

# 或使用 Debian 方案
./build-zig-cgo.sh
```

### 3. 验证结果

```bash
# 查看文件信息
file ./build/sslcat-linux-amd64-static

# 查看文件大小
ls -lh ./build/sslcat-linux-amd64-static

# 计算 SHA256
shasum -a 256 ./build/sslcat-linux-amd64-static
```

### 4. 测试二进制文件

```bash
# 在 Docker 中测试
docker run --rm --platform linux/amd64 \
    -v $(pwd)/build:/test \
    alpine:latest \
    /test/sslcat-linux-amd64-static --version
```

### 5. 部署到服务器

```bash
# 上传到服务器
scp ./build/sslcat-linux-amd64-static user@server:/opt/sslcat/

# 在服务器上设置权限
ssh user@server "chmod +x /opt/sslcat/sslcat-linux-amd64-static"

# 运行
ssh user@server "/opt/sslcat/sslcat-linux-amd64-static --version"
```

## 🐛 故障排查

### 问题 1: Docker 构建失败

```bash
# 清理 Docker 缓存
docker system prune -a

# 重新构建
./build-zig-alpine.sh
```

### 问题 2: 网络超时

```bash
# 设置代理
export https_proxy=http://127.0.0.1:7890
export http_proxy=http://127.0.0.1:7890

# 或修改 Docker 代理设置
# Docker Desktop -> Settings -> Resources -> Proxies
```

### 问题 3: 平台不匹配

```bash
# 确保使用 --platform linux/amd64
docker build --platform linux/amd64 -f Dockerfile.zig-alpine .
```

### 问题 4: 二进制文件无法运行

```bash
# 检查文件类型
file ./build/sslcat-linux-amd64-static

# 检查依赖
ldd ./build/sslcat-linux-amd64-static

# 在 Docker 中测试
docker run --rm --platform linux/amd64 \
    -v $(pwd)/build:/test \
    alpine:latest \
    /test/sslcat-linux-amd64-static --version
```

## 📝 技术细节

### Zig 交叉编译原理

Zig 提供了强大的交叉编译能力：

```bash
# 使用 Zig 作为 C 编译器
CC="zig cc -target x86_64-linux-musl"

# 指定目标平台和 GLIBC 版本
CC="zig cc -target x86_64-linux-gnu.2.32"
```

### CGO 配置

```bash
# 启用 CGO
export CGO_ENABLED=1

# 设置目标平台
export GOOS=linux
export GOARCH=amd64

# 静态链接
export CGO_LDFLAGS="-static"
```

### 构建标签

```bash
# 完全静态链接
go build -tags 'osusergo netgo static_build' \
    -ldflags="-s -w -linkmode external -extldflags '-static'" \
    -o sslcat main.go
```

## 🎯 最佳实践

1. **使用 Alpine 方案**：最快、最小、最兼容
2. **启用 Docker 缓存**：加速重复构建
3. **设置代理**：避免网络问题
4. **验证二进制文件**：确保编译正确
5. **在 Docker 中测试**：模拟目标环境

## 📚 相关文档

- [Zig 官方文档](https://ziglang.org/documentation/master/)
- [Go 交叉编译](https://golang.org/doc/install/source#environment)
- [Docker 多平台构建](https://docs.docker.com/build/building/multi-platform/)

## 🆘 获取帮助

如果遇到问题，请：

1. 查看构建日志
2. 检查 Docker 状态
3. 验证网络连接
4. 查看 GitHub Issues

## 📄 许可证

本项目采用 MIT 许可证。

