#!/bin/bash

# SSLcat Linux AMD64 CGO 编译脚本（使用 Docker）
# 使用方法: ./scripts/build-linux-cgo-docker.sh

set -e

echo "🐳 使用 Docker 构建 SSLcat Linux AMD64 CGO 二进制文件..."

# 设置编译参数
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")

# 输出文件名
OUTPUT_FILE="sslcat-linux-amd64-cgo"

echo "📦 编译信息:"
echo "   版本: ${VERSION}"
echo "   构建时间: ${BUILD_TIME}"
echo "   Git提交: ${GIT_COMMIT}"
echo "   目标平台: Linux AMD64 (CGO 启用)"
echo "   输出文件: ${OUTPUT_FILE}"
echo ""

# 检查 Docker 是否可用
if ! command -v docker &> /dev/null; then
    echo "❌ 错误: Docker 未安装或不可用"
    echo "请先安装 Docker: https://www.docker.com/get-started"
    exit 1
fi

echo "🔨 正在构建 Docker 镜像并编译..."
echo ""

# 创建临时 Dockerfile
TEMP_DOCKERFILE=$(mktemp)
cat > "$TEMP_DOCKERFILE" << 'EOF'
FROM golang:1.23-alpine

# 安装 CGO 依赖
RUN apk add --no-cache gcc musl-dev sqlite-dev git

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建前端（如果需要）
RUN if [ -d "frontend" ]; then \
        apk add --no-cache nodejs npm && \
        cd frontend && \
        npm install && \
        npm run build && \
        mkdir -p /app/internal/assets/frontend && \
        cp -r dist/* /app/internal/assets/frontend/ || true; \
    fi

# 编译 (CGO 启用)
ARG VERSION
ARG BUILD_TIME
ARG GIT_COMMIT

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}" \
    -o /app/sslcat-cgo main.go

# 检查文件
RUN ls -lh /app/sslcat-cgo && file /app/sslcat-cgo
EOF

# 构建镜像并编译
echo "🏗️  构建 Docker 镜像..."
docker build \
    --build-arg VERSION="${VERSION}" \
    --build-arg BUILD_TIME="${BUILD_TIME}" \
    --build-arg GIT_COMMIT="${GIT_COMMIT}" \
    -f "$TEMP_DOCKERFILE" \
    -t sslcat-builder:latest \
    .

# 创建容器并复制文件
echo ""
echo "📦 从容器中提取二进制文件..."
CONTAINER_ID=$(docker create sslcat-builder:latest)
docker cp "$CONTAINER_ID:/app/sslcat-cgo" "./${OUTPUT_FILE}"
docker rm "$CONTAINER_ID" > /dev/null

# 清理临时文件
rm -f "$TEMP_DOCKERFILE"

# 检查编译结果
if [ -f "${OUTPUT_FILE}" ]; then
    echo ""
    echo "✅ 编译成功!"
    echo ""
    echo "📊 文件信息:"
    ls -lh "${OUTPUT_FILE}"
    echo ""
    echo "🔍 文件类型:"
    file "${OUTPUT_FILE}"
    echo ""
    echo "📈 文件大小:"
    du -h "${OUTPUT_FILE}"
    echo ""
    echo "🎯 使用方法:"
    echo "   1. 上传到 Linux 服务器:"
    echo "      scp ${OUTPUT_FILE} user@server:/path/to/sslcat"
    echo ""
    echo "   2. 在服务器上设置权限并运行:"
    echo "      chmod +x /path/to/sslcat"
    echo "      ./sslcat --config sslcat.conf"
    echo ""
    echo "💡 提示:"
    echo "   - CGO 版本支持 SQLite 数据库的完整功能"
    echo "   - 文件已静态链接，可在任何 Linux amd64 系统运行"
    echo "   - 如需清理 Docker 镜像: docker rmi sslcat-builder:latest"
else
    echo ""
    echo "❌ 编译失败!"
    exit 1
fi

echo ""
echo "🎉 编译完成!"

