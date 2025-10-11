# 使用 Zig 作为 C 编译器在 ARM64 容器内交叉编译到 AMD64
FROM golang:1.25-alpine AS builder

# 安装基础工具和 Zig
RUN apk add --no-cache \
    git \
    curl \
    xz \
    sqlite-dev

# 下载并安装 Zig（用作 C 交叉编译器）
RUN cd /tmp && \
    curl -L https://ziglang.org/download/0.11.0/zig-linux-aarch64-0.11.0.tar.xz -o zig.tar.xz && \
    tar -xf zig.tar.xz && \
    mv zig-linux-*/ /usr/local/zig && \
    rm zig.tar.xz

# 设置 Go 代理
ENV GOPROXY=https://goproxy.cn,direct
ENV GO111MODULE=on
ENV PATH="/usr/local/zig:${PATH}"

WORKDIR /build

# 复制项目文件
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 使用 Zig 作为 C 编译器交叉编译到 AMD64
ENV CGO_ENABLED=1
ENV GOOS=linux
ENV GOARCH=amd64
ENV CC="zig cc -target x86_64-linux-musl"
ENV CXX="zig c++ -target x86_64-linux-musl"

RUN go build \
    -ldflags "-s -w -X main.version=v1.3.11-cgo-amd64 -X main.build=$(date -u +%Y-%m-%d_%H:%M:%S)" \
    -o sslcat-linux-amd64-cgo \
    main.go

# 验证构建结果
RUN ls -lh sslcat-linux-amd64-cgo

CMD ["sh", "-c", "echo /build/sslcat-linux-amd64-cgo"]

