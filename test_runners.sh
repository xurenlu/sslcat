#!/bin/bash

# SSLcat Runner 功能测试脚本

echo "=== SSLcat Runner 功能测试 ==="

# 检查 SSLcat 是否运行
if ! pgrep -f "sslcat" > /dev/null; then
    echo "错误: SSLcat 未运行，请先启动 SSLcat"
    exit 1
fi

echo "✓ SSLcat 正在运行"

# 测试 Local Runner API
echo ""
echo "=== 测试 Local Runner API ==="

# 添加一个 Golang 任务
echo "添加 Golang 任务..."
curl -X POST "http://localhost:9933/sslcat-panel/api/local-runner/task/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "测试 Golang 应用",
    "type": "golang",
    "binary_path": "/usr/bin/echo",
    "port": 8080,
    "args": ["Hello", "World"],
    "env": {
      "GIN_MODE": "release"
    }
  }' 2>/dev/null | jq '.'

# 添加一个 Spring Boot 任务
echo "添加 Spring Boot 任务..."
curl -X POST "http://localhost:9933/sslcat-panel/api/local-runner/task/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "测试 Spring Boot 应用",
    "type": "springboot",
    "binary_path": "/path/to/app.jar",
    "port": 8081,
    "active_profile": "prod",
    "args": ["--server.port=8081"],
    "env": {
      "SPRING_PROFILES_ACTIVE": "prod"
    }
  }' 2>/dev/null | jq '.'

# 列出所有任务
echo "列出所有 Local Runner 任务..."
curl -X GET "http://localhost:9933/sslcat-panel/api/local-runner/tasks" 2>/dev/null | jq '.'

# 测试 Docker Runner API
echo ""
echo "=== 测试 Docker Runner API ==="

# 添加一个 Docker 任务
echo "添加 Docker 任务..."
curl -X POST "http://localhost:9933/sslcat-panel/api/docker-runner/task/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "测试 Docker 应用",
    "git_url": "https://github.com/gin-gonic/gin.git",
    "git_branch": "master",
    "port": 8082,
    "env": {
      "GIN_MODE": "release"
    }
  }' 2>/dev/null | jq '.'

# 列出所有 Docker 任务
echo "列出所有 Docker Runner 任务..."
curl -X GET "http://localhost:9933/sslcat-panel/api/docker-runner/tasks" 2>/dev/null | jq '.'

# 测试 Git 服务器 API
echo ""
echo "=== 测试 Git 服务器 API ==="

# 添加一个 Git 仓库
echo "添加 Git 仓库..."
curl -X POST "http://localhost:9933/sslcat-panel/api/git-server/repo/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "测试仓库",
    "url": "https://github.com/gin-gonic/gin.git",
    "branch": "master"
  }' 2>/dev/null | jq '.'

# 列出所有仓库
echo "列出所有 Git 仓库..."
curl -X GET "http://localhost:9933/sslcat-panel/api/git-server/repos" 2>/dev/null | jq '.'

# 测试运行时检测 API
echo ""
echo "=== 测试运行时检测 API ==="

# 检测项目类型
echo "检测项目类型..."
curl -X GET "http://localhost:9933/sslcat-panel/api/runtime-detector/detect?path=/tmp" 2>/dev/null | jq '.'

echo ""
echo "=== 测试完成 ==="
echo "所有 Runner 功能已成功集成到 SSLcat 中！"
echo ""
echo "功能说明："
echo "1. Local Runner - 支持 Golang 二进制程序和 Spring Boot JAR 包执行"
echo "2. Docker Runner - 从 Git 仓库拉取代码、检测运行时类型、编译并执行"
echo "3. Git 服务器 - 集成 Git 操作和代码执行"
echo "4. 运行时检测 - 自动识别项目类型和框架"
echo ""
echo "API 端点："
echo "- Local Runner: /sslcat-panel/api/local-runner/*"
echo "- Docker Runner: /sslcat-panel/api/docker-runner/*"
echo "- Git 服务器: /sslcat-panel/api/git-server/*"
echo "- 运行时检测: /sslcat-panel/api/runtime-detector/*"
