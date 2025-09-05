# SSLcat Dockerfile

# 构建阶段
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的包
RUN apk add --no-cache git ca-certificates tzdata

# 复制go mod文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o withssl main.go

# 运行阶段
FROM alpine:latest

# 安装必要的包
RUN apk --no-cache add ca-certificates tzdata certbot

# 创建用户和目录
RUN addgroup -g 1000 withssl && \
    adduser -D -s /bin/false -u 1000 -G withssl withssl && \
    mkdir -p /etc/sslcat /var/lib/sslcat/{certs,keys,logs} && \
    chown -R withssl:withssl /var/lib/sslcat

# 设置时区
ENV TZ=Asia/Shanghai

# 从构建阶段复制二进制文件
COPY --from=builder /app/withssl /opt/sslcat/withssl

# 复制配置文件模板
COPY --from=builder /app/withssl.conf.example /etc/sslcat/withssl.conf

# 设置权限
RUN mkdir -p /opt/sslcat && \
    chmod +x /opt/sslcat/withssl && \
    chown withssl:withssl /etc/sslcat/withssl.conf && \
    chmod 600 /etc/sslcat/withssl.conf

# 切换到非root用户
USER withssl

# 暴露端口
EXPOSE 80 443

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/health || exit 1

# 启动命令
CMD ["/opt/sslcat/withssl", "--config", "/etc/sslcat/withssl.conf"]
