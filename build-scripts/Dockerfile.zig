# 使用 Zig 进行交叉编译，生成兼容老版本 GLIBC 的二进制文件
FROM golang:1.23.4-alpine AS builder

# 安装 Zig 和必要的工具
RUN apk add --no-cache \
    zig \
    gcc \
    musl-dev \
    pkgconfig \
    git \
    make \
    file

# 设置工作目录
WORKDIR /app

# 复制源代码
COPY . .

# 设置 Go 环境变量
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64

# 使用 Zig 作为 C 编译器，并设置 GLIBC 版本兼容性
ENV CC="zig cc -target x86_64-linux-gnu.2.32 -static"
ENV CXX="zig c++ -target x86_64-linux-gnu.2.32 -static"

# 安装 Go 依赖
RUN go mod download

# 编译 sslcat
RUN go build -ldflags="-s -w" -o sslcat main.go

# 验证二进制文件
RUN file sslcat
RUN ldd sslcat || echo "Static binary or ldd not available"

# 最终阶段
FROM alpine:latest

# 安装运行时依赖
RUN apk add --no-cache ca-certificates

# 复制二进制文件
COPY --from=builder /app/sslcat /usr/local/bin/sslcat

# 设置权限
RUN chmod +x /usr/local/bin/sslcat

# 验证
RUN sslcat --version || echo "Version check failed"

CMD ["sslcat", "--help"]
