# SSLcat CGO 构建成功说明

## ✅ 构建成功！

已成功在 Apple Silicon Mac 上使用 Docker 编译出启用 CGO 的 AMD64 Linux 二进制文件。

## 📦 构建产物

**文件位置**: `/Users/rocky/Sites/sslcat/build/sslcat-linux-amd64-cgo`

**文件信息**:
- 架构: x86-64 (AMD64)
- 大小: 27MB
- 类型: ELF 64-bit LSB executable
- 链接: static-pie (静态链接)
- CGO: 已启用
- 版本: v1.3.11-cgo-amd64

## 🔧 使用的技术方案

### 问题
在 Apple Silicon (ARM64) Mac 上编译 AMD64 Linux 二进制文件时遇到交叉编译问题：
- 网络问题导致无法拉取 AMD64 Docker 镜像
- 传统交叉编译工具链配置复杂

### 解决方案
使用 **Zig** 作为 C 编译器进行交叉编译：
- Zig 是一个现代系统编程语言，其编译器可以作为 C/C++ 编译器使用
- Zig 原生支持零配置交叉编译
- 在 ARM64 容器内使用 Zig 编译器直接生成 AMD64 二进制文件

### 技术细节
```dockerfile
FROM golang:1.25-alpine
# 安装 Zig
RUN curl -L https://ziglang.org/download/0.11.0/zig-linux-aarch64-0.11.0.tar.xz | tar -xJ

# 设置 Zig 作为 C 编译器
ENV CC="zig cc -target x86_64-linux-musl"
ENV CXX="zig c++ -target x86_64-linux-musl"
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

# 编译
RUN go build -o sslcat-linux-amd64-cgo main.go
```

## 🚀 快速构建命令

```bash
# 一键构建（推荐）
./build-cgo-zig.sh

# 或使用 Make
make docker-cgo-zig  # 如果添加到 Makefile
```

## 📤 部署到服务器

### 方法一：SCP 上传
```bash
scp build/sslcat-linux-amd64-cgo user@server:/opt/sslcat/sslcat
ssh user@server "chmod +x /opt/sslcat/sslcat"
```

### 方法二：使用现有部署脚本
```bash
# 修改 deploy-to-s2.sh 等脚本，使用 build/sslcat-linux-amd64-cgo
./deploy-to-s2.sh
```

### 在服务器上运行
```bash
# 检查版本
./sslcat --version

# 启动服务
./sslcat --config /etc/sslcat/sslcat.conf
```

## 📝 构建脚本说明

### 主要文件
1. **Dockerfile.cgo.zig** - 使用 Zig 交叉编译的 Dockerfile
2. **build-cgo-zig.sh** - 一键构建脚本
3. **build-cgo-local.sh** - 原始构建脚本（需要同架构）
4. **build-cgo-arm64.sh** - ARM64 版本构建脚本

### 构建选项对比

| 脚本 | 架构 | 用途 | 推荐度 |
|------|------|------|--------|
| build-cgo-zig.sh | AMD64 | 在 ARM64 Mac 上交叉编译 AMD64 | ⭐⭐⭐⭐⭐ |
| build-cgo-local.sh | 本机架构 | 简单直接，但需要同架构 | ⭐⭐⭐ |
| build-cgo-arm64.sh | ARM64 | ARM64 服务器使用 | ⭐⭐⭐ |

## 🔍 验证 CGO 是否启用

```bash
# 在 Linux 服务器上
strings sslcat-linux-amd64-cgo | grep -i cgo
# 应该看到 CGO 相关的符号

# 检查 SQLite 支持（CGO 版本的标志）
ldd sslcat-linux-amd64-cgo
# 应该显示 "statically linked" 或显示 sqlite 相关的库
```

## 🎯 与 CGO_ENABLED=0 版本的区别

### CGO 禁用版本（CGO_ENABLED=0）
- ✅ 编译快速
- ✅ 纯 Go，可移植性好
- ❌ 不能使用 mattn/go-sqlite3（只能用 pure Go 的 modernc.org/sqlite）
- ❌ 某些性能敏感的 C 库无法使用

### CGO 启用版本（CGO_ENABLED=1，本次编译）
- ✅ 可以使用 mattn/go-sqlite3（性能更好）
- ✅ 可以使用各种 C 库
- ✅ 静态链接，部署仍然方便
- ⚠️ 编译略慢
- ⚠️ 交叉编译需要配置工具链（本方案已解决）

## 📊 性能对比

根据项目中的依赖配置：
```go
require (
    github.com/mattn/go-sqlite3 v1.14.32      // CGO 版本（C 实现）
    modernc.org/sqlite v1.29.6                // Pure Go 版本
)
```

**SQLite 性能对比**（典型场景）：
- mattn/go-sqlite3 (CGO): ~2-3x 更快
- modernc.org/sqlite (Pure Go): 兼容性好，但性能较低

## 🔄 后续维护

### 定期重新编译
当代码更新后，重新运行构建脚本：
```bash
git pull
./build-cgo-zig.sh
```

### 清理 Docker 缓存
如果需要完全重新构建：
```bash
docker rmi sslcat-cgo-zig:latest
docker builder prune -f
./build-cgo-zig.sh
```

## 💡 故障排除

### 问题：Docker 镜像源访问失败
**解决**：脚本已使用 `DOCKER_BUILDKIT=0` 和本地镜像

### 问题：Zig 下载失败
**解决**：检查网络，或手动下载 Zig 并修改 Dockerfile

### 问题：编译时内存不足
**解决**：增加 Docker 内存限制（Docker Desktop 设置）

### 问题：编译的二进制文件在服务器上无法运行
**检查**：
```bash
# 确认服务器架构
uname -m  # 应显示 x86_64

# 检查文件格式
file sslcat-linux-amd64-cgo  # 应显示 x86-64
```

## 🎉 总结

通过使用 Zig 作为 C 编译器，我们成功实现了：
1. ✅ 在 ARM64 Mac 上编译 AMD64 Linux 二进制文件
2. ✅ 启用了 CGO 支持
3. ✅ 静态链接，方便部署
4. ✅ 无需复杂的交叉编译工具链配置

这个方案简单、可靠、易于维护！

