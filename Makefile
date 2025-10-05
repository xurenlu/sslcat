# SSLcat Makefile

# 变量定义
BINARY_NAME=sslcat
BUILD_DIR=build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION=$(shell go version | awk '{print $$3}')
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.build=$(BUILD_TIME)"

# 默认目标
.PHONY: all
all: clean build

# 清理构建文件
.PHONY: clean
clean:
	@echo "清理构建文件..."
	@rm -rf $(BUILD_DIR)
	@go clean

# 下载依赖
.PHONY: deps
deps:
	@echo "下载Go依赖..."
	@go mod download
	@go mod tidy

# 格式化代码
.PHONY: fmt
fmt:
	@echo "格式化代码..."
	@go fmt ./...

# 运行测试
.PHONY: test
test:
	@echo "运行测试..."
	@go test -v ./...

# 运行基准测试
.PHONY: bench
bench:
	@echo "运行基准测试..."
	@go test -bench=. -benchmem ./...

# 代码检查
.PHONY: lint
lint:
	@echo "运行代码检查..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint 未安装，跳过代码检查"; \
	fi

# 构建前端
.PHONY: build-frontend
build-frontend:
	@echo "构建前端..."
	@./scripts/build-frontend.sh

# 构建二进制文件
.PHONY: build
build: deps build-frontend
	@echo "构建 $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) main.go
	@echo "构建完成: $(BUILD_DIR)/$(BINARY_NAME)"

# 构建多个平台的二进制文件
.PHONY: build-all
build-all: deps build-frontend
	@echo "构建多平台二进制文件..."
	@mkdir -p $(BUILD_DIR)
	@echo "  🐧 构建 Linux AMD64..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	# @echo "  🐧 构建 Linux ARM64..."
	# @GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 main.go
	# @echo "  🍎 构建 macOS AMD64..."
	# @GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go
	# @echo "  🍎 构建 macOS ARM64 (M1/M2)..."
	# @GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 main.go
	# @echo "  🪟 构建 Windows AMD64..."
	# @GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go
	@echo "✅ 多平台构建完成（仅 Linux AMD64）"

# 构建 Linux 服务器版本（最常用）
.PHONY: build-linux
build-linux: deps build-frontend
	@echo "构建 Linux 服务器版本..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	@echo "✅ Linux 版本构建完成: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

# 运行开发服务器
.PHONY: run
run: build
	@echo "启动开发服务器..."
	@./$(BUILD_DIR)/$(BINARY_NAME) --config sslcat.conf --log-level debug

# 运行开发服务器（直接运行，不构建）
.PHONY: dev
dev:
	@echo "启动开发服务器..."
	@go run main.go --config sslcat.conf --log-level debug

# 修复 Node.js 环境
.PHONY: fix-node
fix-node:
	@echo "修复 Node.js 环境..."
	@./scripts/fix-node-env.sh

# 运行前端开发服务器
.PHONY: dev-frontend
dev-frontend:
	@echo "启动前端开发服务器..."
	@./scripts/dev-frontend.sh

# 运行前端开发服务器（绕过 Node.js 问题）
.PHONY: dev-frontend-simple
dev-frontend-simple:
	@echo "启动前端开发服务器（简单模式）..."
	@./scripts/start-frontend-dev.sh

# 安装到系统
.PHONY: install
install: build
	@echo "安装到系统..."
	@sudo mkdir -p /opt/sslcat
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /opt/sslcat/
	@sudo chmod +x /opt/sslcat/$(BINARY_NAME)
	@echo "安装完成"

# 创建发布包
.PHONY: release
release: build-all
	@echo "创建发布包..."
	@mkdir -p $(BUILD_DIR)/release
	@cd $(BUILD_DIR) && \
	for binary in $(BINARY_NAME)-*; do \
		platform=$$(echo $$binary | sed 's/$(BINARY_NAME)-//'); \
		tar -czf release/$(BINARY_NAME)-$(VERSION)-$$platform.tar.gz $$binary; \
	done
	@echo "发布包创建完成: $(BUILD_DIR)/release/"

# 生成文档
.PHONY: docs
docs:
	@echo "生成文档..."
	@if command -v godoc >/dev/null 2>&1; then \
		godoc -http=:6060; \
	else \
		echo "godoc 未安装，跳过文档生成"; \
	fi

# 生成API文档
.PHONY: api-docs
api-docs:
	@echo "生成API文档..."
	@if command -v swag >/dev/null 2>&1; then \
		swag init -g main.go; \
	else \
		echo "swag 未安装，跳过API文档生成"; \
	fi

# 创建Docker镜像
.PHONY: docker
docker:
	@echo "创建Docker镜像..."
	@docker build -t sslcat:$(VERSION) .
	@docker tag sslcat:$(VERSION) sslcat:latest
	@echo "Docker镜像创建完成"

# 创建CGO Docker镜像（中国优化版）
.PHONY: docker-cgo
docker-cgo:
	@echo "创建CGO Docker镜像（中国优化版）..."
	@./scripts/build-cgo-docker.sh -t sslcat-cgo:$(VERSION) -c
	@docker tag sslcat-cgo:$(VERSION) sslcat-cgo:latest
	@echo "CGO Docker镜像创建完成"

# 构建并提取CGO二进制文件（清理缓存，首次构建或完全重建时使用）
.PHONY: docker-cgo-extract
docker-cgo-extract:
	@echo "构建CGO Docker镜像并提取二进制文件..."
	@./scripts/build-cgo-docker.sh -t sslcat-cgo:$(VERSION) -e -o $(BUILD_DIR) -c
	@echo "CGO二进制文件已提取到 $(BUILD_DIR)/sslcat-linux-amd64-cgo"

# 快速构建CGO二进制文件（利用缓存，日常开发使用）
.PHONY: docker-cgo-fast
docker-cgo-fast:
	@echo "快速构建CGO Docker镜像并提取二进制文件（利用缓存）..."
	@./scripts/build-cgo-docker.sh -t sslcat-cgo:$(VERSION) -e -o $(BUILD_DIR)
	@echo "CGO二进制文件已提取到 $(BUILD_DIR)/sslcat-linux-amd64-cgo"

# 运行Docker容器
.PHONY: docker-run
docker-run:
	@echo "运行Docker容器..."
	@docker run -d \
		--name sslcat \
		-p 80:80 \
		-p 443:443 \
		-v /etc/sslcat:/etc/sslcat \
		-v /var/lib/sslcat:/var/lib/sslcat \
		sslcat:latest

# 停止Docker容器
.PHONY: docker-stop
docker-stop:
	@echo "停止Docker容器..."
	@docker stop sslcat || true
	@docker rm sslcat || true

# 检查代码质量
.PHONY: check
check: fmt lint test
	@echo "代码质量检查完成"

# 完整构建流程
.PHONY: ci
ci: clean deps check build test
	@echo "CI构建流程完成"

# 显示帮助信息
.PHONY: help
help:
	@echo "SSLcat Makefile 帮助"
	@echo ""
	@echo "可用目标:"
	@echo "  all          - 清理并构建项目"
	@echo "  clean        - 清理构建文件"
	@echo "  deps         - 下载Go依赖"
	@echo "  fmt          - 格式化代码"
	@echo "  test         - 运行测试"
	@echo "  bench        - 运行基准测试"
	@echo "  lint         - 代码检查"
	@echo "  build        - 构建本地平台二进制文件"
	@echo "  build-linux  - 构建 Linux 服务器版本 (推荐用于部署)"
	@echo "  build-all    - 构建所有平台二进制文件"
	@echo "  run          - 构建并运行开发服务器"
	@echo "  dev          - 直接运行开发服务器"
	@echo "  install      - 安装到系统"
	@echo "  release      - 创建发布包"
	@echo "  docs         - 生成文档"
	@echo "  api-docs     - 生成API文档"
	@echo "  docker       - 创建Docker镜像"
	@echo "  docker-cgo   - 创建CGO Docker镜像（中国优化版）"
	@echo "  docker-cgo-extract - 构建CGO镜像并提取二进制文件"
	@echo "  docker-run   - 运行Docker容器"
	@echo "  docker-stop  - 停止Docker容器"
	@echo "  check        - 代码质量检查"
	@echo "  ci           - CI构建流程"
	@echo "  help         - 显示此帮助信息"
	@echo ""
	@echo "版本信息:"
	@echo "  版本: $(VERSION)"
	@echo "  构建时间: $(BUILD_TIME)"
	@echo "  Go版本: $(GO_VERSION)"
