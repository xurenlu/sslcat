# SSLcat Docker CGO 构建指南

## 概述

本项目提供了优化的 Docker CGO 构建方案，专门针对中国地区网络环境进行了加速优化。

## 特性

- ✅ 使用 Go 1.25 版本
- ✅ 配置中国镜像源加速（阿里云镜像）
- ✅ Go 模块代理加速（goproxy.cn）
- ✅ 多阶段构建解决交叉编译问题
- ✅ 自动提取二进制文件
- ✅ 支持 CGO 编译的 SQLite 驱动

## 快速开始

### 1. 构建 CGO Docker 镜像

```bash
# 基本构建
make docker-cgo

# 构建并提取二进制文件
make docker-cgo-extract

# 使用脚本构建（更多选项）
./scripts/build-cgo-docker.sh -c -e
```

### 2. 手动构建

```bash
# 构建镜像
docker build -f Dockerfile.cgo -t sslcat-cgo:latest .

# 运行容器
docker run -p 80:80 -p 443:443 sslcat-cgo:latest
```

### 3. 提取二进制文件

```bash
# 创建临时容器并复制文件
container_id=$(docker create sslcat-cgo:latest)
docker cp $container_id:/usr/local/bin/sslcat ./sslcat-linux-amd64-cgo
docker rm $container_id
chmod +x ./sslcat-linux-amd64-cgo
```

## 构建脚本选项

`./scripts/build-cgo-docker.sh` 支持以下选项：

- `-t, --tag TAG`: 设置镜像标签（默认: sslcat-cgo:latest）
- `-o, --output DIR`: 输出目录（默认: build）
- `-e, --extract`: 构建后提取二进制文件
- `-c, --cleanup`: 构建前清理缓存
- `-h, --help`: 显示帮助信息

## 镜像信息

- **基础镜像**: golang:1.25-alpine
- **目标平台**: linux/amd64
- **最终镜像大小**: ~90MB
- **二进制文件大小**: ~38MB

## 加速配置

### APT 镜像源
```dockerfile
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
```

### Go 模块代理
```dockerfile
ENV GOPROXY=https://goproxy.cn,direct
ENV GOSUMDB=sum.golang.google.cn
```

## 故障排除

### 1. 交叉编译问题
如果遇到 `gcc: error: unrecognized command-line option '-m64'` 错误，请确保使用 `--platform=linux/amd64` 标志。

### 2. Go 版本不匹配
确保 Dockerfile 中的 Go 版本与 go.mod 中的版本要求一致。

### 3. 网络问题
如果下载速度慢，检查是否使用了中国镜像源配置。

## 验证构建结果

```bash
# 检查二进制文件类型
file build/sslcat-linux-amd64-cgo

# 检查文件大小
ls -lh build/sslcat-linux-amd64-cgo

# 测试运行（如果有 Linux 环境）
./build/sslcat-linux-amd64-cgo --version
```

## 部署

生成的 `sslcat-linux-amd64-cgo` 二进制文件可以直接部署到 Linux AMD64 服务器上：

```bash
# 上传到服务器
scp build/sslcat-linux-amd64-cgo user@server:/opt/sslcat/sslcat

# 设置权限
chmod +x /opt/sslcat/sslcat

# 运行
/opt/sslcat/sslcat --config /etc/sslcat/sslcat.conf
```

## 注意事项

1. CGO 版本需要目标系统有相应的 C 库支持
2. 二进制文件是动态链接的，需要目标系统有 musl libc
3. 如果需要静态链接，可以修改构建参数添加 `CGO_ENABLED=1 CGO_LDFLAGS="-static"`
